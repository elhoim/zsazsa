"""Stakeholders, the organisations they belong to and the users zsazsa recognises.

A stakeholder is a MISP event that PIRs, GIRs and distribution lists point at by
UUID, so an edit must never turn it into a new event. The organisation registry
is a small SQLite table filled from MISP by hand and by every SSO request, and
the stakeholder page and export read both. Where MISP is called it is an autospec
of PyMISP, and the databases are temporary.

    python -m unittest tests.test_stakeholders
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import MISPEvent, PyMISP

import config
from webapp import collection_cache, create_app, misp_store, org_store, sso_users
from webapp.routes import export

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
ORG_UUID = "0b3f6a8e-2c4d-4e5f-9a1b-c2d3e4f5a6b7"


def _event(**data):
    event = MISPEvent()
    event.uuid = UUID
    event.date = "2026-10-01"
    event.add_object(misp_store._stakeholder_obj({"name": "Ada", **data}))
    return event


def _stakeholder(**fields):
    stored = {"uuid": UUID, "id": UUID, "name": "Ada", "role": "SOC", "organization": "",
              "contacts": [], "email": "", "tlp_clearance": "amber", "products": [],
              "product_modes": {}, "notification_channels": [], "notes": "",
              "influence": 5, "interest": 5, "engagement_strategy": "", "stakeholder_type": "Internal",
              "created_at": None, "misp_url": "", "history_url": ""}
    stored.update(fields)
    return SimpleNamespace(**stored)


class TempDatabase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        org_store.init_db()
        sso_users.init_db()


class Contacts(unittest.TestCase):
    def test_a_preferred_phone_number_is_not_the_email_address(self):
        """The distribution card links the address with mailto, and showed the
        phone number when that was the preferred contact."""
        ns = misp_store._stakeholder_ns(_event(contacts=[
            {"type": "Phone", "value": "+32 2 555 01 01", "preferred": True},
            {"type": "Email", "value": "ada@example.org", "preferred": False},
        ]))
        self.assertEqual(ns.email, "ada@example.org")

    def test_the_preferred_address_wins_over_the_first(self):
        ns = misp_store._stakeholder_ns(_event(contacts=[
            {"type": "Email", "value": "first@example.org", "preferred": False},
            {"type": "Email", "value": "ada@example.org", "preferred": True},
        ]))
        self.assertEqual(ns.email, "ada@example.org")

    def test_no_address_at_all(self):
        ns = misp_store._stakeholder_ns(_event(contacts=[{"type": "Teams", "value": "ada", "preferred": True}]))
        self.assertEqual(ns.email, "")


class Update(unittest.TestCase):
    def setUp(self):
        self.misp = mock.create_autospec(PyMISP, instance=True)
        patcher = mock.patch.object(misp_store, "_misp", return_value=self.misp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_stakeholder_that_has_gone_is_not_created_again(self):
        """It was, under a new UUID, which left every PIR it owned pointing at nothing."""
        self.misp.get_event.return_value = {"errors": (404, {"message": "Invalid event"})}
        with self.assertRaises(ValueError):
            misp_store.update_stakeholder(UUID, {"name": "Ada"})
        self.misp.add_event.assert_not_called()

    def test_an_event_that_is_not_a_stakeholder_is_left_alone(self):
        other = MISPEvent()
        other.uuid = UUID
        self.misp.get_event.return_value = other
        with self.assertRaises(ValueError):
            misp_store.update_stakeholder(UUID, {"name": "Ada"})
        self.misp.update_object.assert_not_called()
        self.misp.update_event.assert_not_called()


class Delete(unittest.TestCase):
    """A PIR, GIR or RFI keeps its owner by UUID, so a stakeholder who still owns
    one stays."""

    def setUp(self):
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.misp.get_event.return_value = _event()
        self.misp.delete_event.return_value = {"message": "Event deleted."}
        patcher = mock.patch.object(misp_store, "_misp", return_value=self.misp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def owning(self, pirs=(), girs=(), rfis=()):
        return mock.patch.multiple(misp_store, list_pirs=mock.Mock(return_value=list(pirs)),
                                   list_girs=mock.Mock(return_value=list(girs)),
                                   list_rfis=mock.Mock(return_value=list(rfis)))

    def test_the_records_are_listed_by_owner(self):
        with self.owning(pirs=[SimpleNamespace(owner_uuid=UUID, pir_id="PIR-001"),
                               SimpleNamespace(owner_uuid="", pir_id="PIR-002")],
                         girs=[SimpleNamespace(owner_uuid=UUID, gir_id="GIR-001")],
                         rfis=[SimpleNamespace(owner_uuid="b" * 36, rfi_id="RFI-001")]):
            owned = misp_store.records_owned_by_stakeholders()
        self.assertEqual(owned, {UUID: ["PIR-001", "GIR-001"], "b" * 36: ["RFI-001"]})

    def test_an_owner_is_not_deleted(self):
        for kind, record in (("pirs", SimpleNamespace(owner_uuid=UUID, pir_id="PIR-001")),
                             ("girs", SimpleNamespace(owner_uuid=UUID, gir_id="GIR-001")),
                             ("rfis", SimpleNamespace(owner_uuid=UUID, rfi_id="RFI-001"))):
            with self.subTest(kind), self.owning(**{kind: [record]}), \
                 self.assertRaisesRegex(ValueError, r"owns (PIR|GIR|RFI)-001"):
                misp_store.delete_stakeholder(UUID)
        self.misp.delete_event.assert_not_called()

    def test_a_stakeholder_who_owns_nothing_is_deleted(self):
        with self.owning(pirs=[SimpleNamespace(owner_uuid="b" * 36, pir_id="PIR-001")]):
            misp_store.delete_stakeholder(UUID)
        self.misp.delete_event.assert_called_once_with(UUID)


class RecentProducts(unittest.TestCase):
    def test_a_subscription_shows_without_any_requirement(self):
        """Nothing was listed for a stakeholder who owns no PIR or GIR, whatever
        they subscribe to."""
        fia = SimpleNamespace(uuid="f" * 36, fia_id="FIA-00001", title="Wiper on the grid",
                              created_at=None, misp_url="")
        misp = mock.create_autospec(PyMISP, instance=True)
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "list_fias", return_value=[fia]):
            products = misp_store.products_for_stakeholder(
                _stakeholder(products=["Flash intel alert"]), [], [])
        self.assertEqual([p.info for p in products], ["[zsazsa:fia] Wiper on the grid"])
        misp.search.assert_not_called()


class Organisations(TempDatabase):
    def setUp(self):
        super().setUp()
        info = {"uuid": ORG_UUID, "name": "CIRCL", "sector": "CERT", "country": "Luxembourg"}
        patcher = mock.patch.object(org_store, "_misp_lookup", return_value=info)
        self.lookup = patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_uuid_pasted_in_capitals_is_the_organisation_already_registered(self):
        """It got past the duplicate check and failed on the primary key."""
        org_store.add_organisation(ORG_UUID)
        with self.assertRaisesRegex(ValueError, "already registered"):
            org_store.add_organisation(ORG_UUID.upper())

    def test_a_numeric_id_is_refused_before_misp_is_asked(self):
        """MISP finds an organisation by its numeric id too."""
        with self.assertRaisesRegex(ValueError, "not a UUID"):
            org_store.add_organisation("1")
        self.lookup.assert_not_called()

    def test_sync_all_counts_the_ones_misp_no_longer_has(self):
        org_store.add_organisation(ORG_UUID)
        self.lookup.return_value = {"uuid": ORG_UUID, "name": "CIRCL.lu", "sector": "", "country": ""}
        self.assertEqual(org_store.sync_all_organisations(), (1, 0))
        self.assertEqual(org_store.get_organisation(ORG_UUID).name, "CIRCL.lu")
        self.lookup.return_value = None
        self.assertEqual(org_store.sync_all_organisations(), (0, 1))

    def test_an_organisation_linked_to_a_stakeholder_stays(self):
        org_store.add_organisation(ORG_UUID)
        with mock.patch.object(misp_store, "list_stakeholders",
                               return_value=[_stakeholder(organization=ORG_UUID)]), \
             self.assertRaisesRegex(ValueError, "Ada"):
            org_store.delete_organisation(ORG_UUID)
        self.assertIsNotNone(org_store.get_organisation(ORG_UUID))


class Sightings(TempDatabase):
    USER = {"email": "analyst@example.org", "id": "7", "Role": {"name": "User"},
            "Organisation": {"name": "CIRCL", "uuid": ORG_UUID}}

    def setUp(self):
        super().setUp()
        self.addCleanup(sso_users._recognised_in.discard, config.DB_FILE)
        self.addCleanup(sso_users._organisations_tried.discard, ORG_UUID)

    def test_the_users_organisation_is_registered(self):
        with mock.patch.object(org_store, "_misp_lookup",
                               return_value={"uuid": ORG_UUID, "name": "CIRCL", "sector": "", "country": ""}):
            sso_users.record_sighting(self.USER)
        self.assertEqual(org_store.get_organisation(ORG_UUID).name, "CIRCL")
        self.assertEqual(sso_users.organisation_uuids_in_use(), {ORG_UUID})

    def test_an_organisation_misp_cannot_find_is_not_asked_for_on_every_request(self):
        """A sighting is recorded before every request, and each one asked MISP
        again and wrote another warning."""
        with mock.patch.object(org_store, "_misp_lookup", return_value=None) as lookup, \
             self.assertLogs(sso_users.logger, "WARNING") as logs:
            for _ in range(3):
                sso_users.record_sighting(self.USER)
        lookup.assert_called_once()
        self.assertEqual(len(logs.records), 1)
        self.assertEqual(sso_users.list_sso_users()[0].organisation, "CIRCL")


class Export(unittest.TestCase):
    def test_the_organisation_is_named_and_requirements_are_read_once(self):
        """The export showed the organisation's UUID, and searched MISP for all
        PIRs and all GIRs again for every stakeholder."""
        stakeholders = [_stakeholder(organization=ORG_UUID, contacts=[
                            {"type": "Email", "value": "ada@example.org", "preferred": True}]),
                        _stakeholder(uuid="b" * 36, name="Bob")]
        pir = SimpleNamespace(owner_uuid=UUID, pir_id="PIR-001", question="Who targets the grid?")
        with mock.patch.object(misp_store, "list_stakeholders", return_value=stakeholders), \
             mock.patch.object(misp_store, "list_pirs", return_value=[pir]) as list_pirs, \
             mock.patch.object(misp_store, "list_girs", return_value=[]), \
             mock.patch.object(org_store, "org_map", return_value={ORG_UUID: "CIRCL"}):
            text = export._stakeholders_markdown()
        list_pirs.assert_called_once()
        self.assertIn("**Organisation:** CIRCL", text)
        self.assertIn("**Contacts:** Email: ada@example.org (preferred)", text)
        self.assertNotIn("**Email:**", text)
        ada, bob = text.split("## Bob")
        self.assertIn("- PIR-001: Who targets the grid?", ada)
        self.assertNotIn("PIR-001", bob)


class Pages(TempDatabase):
    def setUp(self):
        super().setUp()
        for patcher in (
            mock.patch.object(config, "LOG_FILE", str(Path(config.DB_FILE).with_name("test.log")), create=True),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(config, "NOTIFICATION_CHANNELS", []),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch("webapp.audit.record"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "token"

    def post(self, path, **form):
        return self.client.post(path, data={"csrf_token": "token", **form})

    def test_a_blank_name_creates_nothing(self):
        with mock.patch.object(misp_store, "create_stakeholder") as create:
            self.post("/stakeholders/new", name="   ")
        create.assert_not_called()

    def test_an_edit_saves_over_the_same_stakeholder(self):
        with mock.patch.object(misp_store, "get_stakeholder", return_value=_stakeholder()), \
             mock.patch.object(misp_store, "update_stakeholder") as update:
            reply = self.post(f"/stakeholders/{UUID}/edit", name=" Ada Lovelace ")
        self.assertEqual(update.call_args.args[0], UUID)
        self.assertEqual(update.call_args.args[1]["name"], "Ada Lovelace")
        self.assertTrue(reply.location.endswith(f"/stakeholders/{UUID}"))

    def test_a_product_without_a_stored_mode_keeps_the_default(self):
        """The hidden mode field said "None" for it."""
        with mock.patch.object(misp_store, "get_stakeholder", return_value=_stakeholder()):
            page = BeautifulSoup(self.client.get(f"/stakeholders/{UUID}/edit").data, "html.parser")
        modes = {i["value"] for i in page.select('input[name^="mode__"]')}
        self.assertEqual(modes, {misp_store.DEFAULT_SUBSCRIPTION_MODE})

    def test_an_organisation_a_stakeholder_belongs_to_cannot_be_removed(self):
        with mock.patch.object(org_store, "_misp_lookup",
                               return_value={"uuid": ORG_UUID, "name": "CIRCL", "sector": "", "country": ""}):
            org_store.add_organisation(ORG_UUID)
        with mock.patch.object(misp_store, "list_stakeholders",
                               return_value=[_stakeholder(organization=ORG_UUID)]):
            page = BeautifulSoup(self.client.get("/community/organisations").data, "html.parser")
        reason = page.select_one(f"#org-{ORG_UUID} span[title^='Cannot remove']")
        self.assertIn("stakeholder", reason["title"])
        self.assertTrue(reason.button.has_attr("disabled"))

    def test_the_list_disables_delete_for_an_owner_and_says_why(self):
        bob = _stakeholder(uuid="b" * 36, id="b" * 36, name="Bob")
        with mock.patch.object(misp_store, "list_stakeholders", return_value=[_stakeholder(), bob]), \
             mock.patch.object(misp_store, "records_owned_by_stakeholders",
                               return_value={UUID: ["PIR-001", "RFI-002"]}):
            page = BeautifulSoup(self.client.get("/stakeholders/").data, "html.parser")
        reason = page.select_one("span[title^='Cannot be deleted']")
        self.assertIn("PIR-001, RFI-002", reason["title"])
        self.assertTrue(reason.button.has_attr("disabled"))
        forms = [f["action"] for f in page.select("form[data-submit-confirm]")]
        self.assertEqual(forms, [f"/stakeholders/{'b' * 36}/delete"])

    def test_the_page_of_an_owner_disables_delete(self):
        empty = {name: mock.Mock(return_value=[]) for name in (
            "pirs_for_stakeholder", "pirs_distributed_to_stakeholder", "girs_for_stakeholder",
            "girs_distributed_to_stakeholder", "products_for_stakeholder")}
        with mock.patch.object(misp_store, "get_stakeholder", return_value=_stakeholder()), \
             mock.patch.multiple(misp_store, **empty), \
             mock.patch.object(misp_store, "records_owned_by_stakeholders",
                               return_value={UUID: ["RFI-007"]}):
            page = BeautifulSoup(self.client.get(f"/stakeholders/{UUID}").data, "html.parser")
        self.assertIn("RFI-007", page.select_one("span[title^='Cannot be deleted']")["title"])
        self.assertIsNone(page.select_one("form[data-submit-confirm]"))


if __name__ == "__main__":
    unittest.main()
