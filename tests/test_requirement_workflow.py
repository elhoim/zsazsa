"""The PIR, GIR and RFI workflow: what an edit, a triage and a status move may change.

Products, RFIs and stakeholders point at a requirement by UUID, so an update of
one that has gone fails rather than making a new one. The status of a PIR and an
RFI changes through triage and the status board only, never through the edit
form, and a triage is taken once. A product or an RFI is linked to an agreed PIR. Matching reads only Active requirements, so a
change of status refreshes it. A product records the PIR it answers on its
object, which is where the statistics and the stakeholder page have to look.

MISP is an autospec of PyMISP or the store functions are patched; nothing leaves
the machine.

    python -m unittest tests.test_requirement_workflow
"""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from flask import Flask
from pymisp import MISPEvent, PyMISP

import config
from notifier import dispatcher
from webapp import misp_store
from webapp.routes import detection_eng, requirements, rfi, stats, threat_actor_profile, vea

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
OTHER = "0b3f6a8e-2c4d-4e5f-9a1b-c2d3e4f5a6b7"


def _pir(uuid=UUID, **fields):
    """A PIR as get_pir returns one, read from a stored event."""
    event = MISPEvent()
    event.uuid = uuid
    event.date = "2026-10-01"
    event.add_object(misp_store._pir_obj({"pir_id": "PIR-001", "question": "Who targets the grid?",
                                          "status": "Pending", "intake_status": "submitted", **fields}))
    return misp_store._pir_ns(event)


def _app(*blueprints):
    app = Flask(__name__)
    app.secret_key = "test"
    for bp in blueprints:
        app.register_blueprint(bp)
    return app.test_client()


class GoneRecords(unittest.TestCase):
    def test_a_requirement_or_rfi_that_has_gone_is_not_created_again(self):
        """It was, under a new UUID, which left every product and RFI linked to
        it pointing at nothing, and on a passing MISP error made a duplicate."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = {"errors": (404, {"message": "Invalid event"})}
        # Recreating takes a number from the id counter in this install's database.
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True), \
             mock.patch.object(misp_store, "_misp", return_value=misp):
            for update in (misp_store.update_pir, misp_store.update_gir, misp_store.update_rfi):
                with self.subTest(update.__name__), self.assertRaises(ValueError):
                    update(UUID, {"question": "q", "topic": "t"})
        misp.add_event.assert_not_called()


class StatusStaysOutOfTheEditForm(unittest.TestCase):
    """The forms only show the status. A posted one could make a Pending PIR
    Active, or an untriaged RFI Delivered, without triage."""

    def capture(self, path, store_call, form, getter="get_rfi", stored=None):
        captured = {}

        def remember(*args):
            captured.update(args[-1])
            return UUID

        with mock.patch.object(misp_store, "list_stakeholders", return_value=[]), \
             mock.patch.object(misp_store, "list_pirs", return_value=[]), \
             mock.patch.object(misp_store, "list_girs", return_value=[]), \
             mock.patch.object(misp_store, store_call, side_effect=remember), \
             mock.patch.object(misp_store, getter, return_value=stored), \
             mock.patch("webapp.audit.record"), \
             mock.patch.object(requirements._matching, "invalidate_cache"):
            _app(requirements.bp, rfi.bp).post(path, data=form)
        return captured

    def test_a_pir_edit_keeps_the_stored_status_and_intake(self):
        pir = _pir(intake_status="acknowledged", acknowledged_by="lead@example.org")
        data = self.capture(f"/pirs/{UUID}/edit", "update_pir",
                            {"question": "Who targets the grid now?", "status": "Active"},
                            getter="get_pir", stored=pir)
        self.assertEqual(data["status"], "Pending")
        self.assertEqual(data["intake_status"], "acknowledged")
        self.assertEqual(data["acknowledged_by"], "lead@example.org")
        self.assertEqual(data["question"], "Who targets the grid now?")

    def test_a_gir_edit_ignores_a_status_it_does_not_know(self):
        gir = SimpleNamespace(uuid=UUID, gir_id="GIR-001", status="Active", focus_points=[])
        data = self.capture(f"/girs/{UUID}/edit", "update_gir", {"topic": "t", "status": "Hacked"},
                            getter="get_gir", stored=gir)
        self.assertEqual(data["status"], "Active")

    def test_a_new_rfi_starts_new(self):
        data = self.capture("/rfis/new", "create_rfi", {"question": "q", "status": "Closed"})
        self.assertEqual(data["status"], "New")

    def test_an_rfi_edit_keeps_the_stored_status(self):
        stored = SimpleNamespace(uuid=UUID, rfi_id="RFI-001", status="New", linked_pir_uuid="")
        data = self.capture(f"/rfis/{UUID}/edit", "update_rfi", {"question": "q", "status": "Delivered"},
                            stored=stored)
        self.assertEqual(data["status"], "New")


class RfiPirChoice(unittest.TestCase):
    """An RFI is linked to an agreed PIR, as a product is, or to the one it
    already has, which may since have left Active."""

    THIRD = "9c1d2e3f-4a5b-4c6d-8e7f-a0b1c2d3e4f5"

    def offered(self, path, stored=None):
        pirs = [_pir(UUID, status="Active"), _pir(OTHER, status="Pending"), _pir(self.THIRD, status="Retired")]
        with mock.patch.object(misp_store, "list_pirs", return_value=pirs), \
             mock.patch.object(misp_store, "list_stakeholders", return_value=[]), \
             mock.patch.object(misp_store, "list_girs", return_value=[]), \
             mock.patch.object(misp_store, "get_rfi", return_value=stored), \
             mock.patch.object(rfi, "render_template", return_value="") as render:
            _app(rfi.bp).get(path)
        return [p.uuid for p in render.call_args.kwargs["pirs"]]

    def test_a_new_rfi_is_offered_the_active_pirs(self):
        self.assertEqual(self.offered("/rfis/new"), [UUID])

    def test_an_edit_keeps_the_pir_the_rfi_is_linked_to(self):
        stored = SimpleNamespace(uuid=UUID, rfi_id="RFI-001", status="Acknowledged", linked_pir_uuid=self.THIRD)
        self.assertEqual(self.offered(f"/rfis/{UUID}/edit", stored), [UUID, self.THIRD])


class ProductPirChoice(unittest.TestCase):
    """The product forms offer the agreed PIRs, as the flash intel and threat
    landscape forms did already, and keep the one a product is linked to,
    whether the form is rendered from the stored product or from a post."""

    def test_each_form_offers_the_active_pirs_and_the_linked_one(self):
        third = RfiPirChoice.THIRD
        pirs = [_pir(UUID, status="Active"), _pir(OTHER, status="Pending"), _pir(third, status="Retired")]
        stored = SimpleNamespace(linked_pir_uuid=third)
        galaxies = {name: mock.Mock(return_value=[]) for name in (
            "galaxy_mitre_attack_patterns", "galaxy_threat_actors", "galaxy_geography",
            "galaxy_sectors", "list_indicator_feeds")}
        with mock.patch.object(misp_store, "list_pirs", return_value=pirs), \
             mock.patch.multiple(misp_store, **galaxies):
            for name, context, expected in (
                ("vea, posted", vea._wizard_context({"linked_pir_uuid": third}), [UUID, third]),
                ("der, stored", detection_eng._wizard_context(stored), [UUID, third]),
                ("tap, stored", threat_actor_profile._form_context(stored), [UUID, third]),
                ("der, new", detection_eng._wizard_context(), [UUID]),
            ):
                with self.subTest(name):
                    self.assertEqual([p.uuid for p in context["pirs"]], expected)


class Triage(unittest.TestCase):
    def setUp(self):
        self.pirs = {UUID: _pir(owner_uuid="owner", distribution=["reader"])}
        self.stakeholders = [SimpleNamespace(uuid=uuid, name=uuid) for uuid in ("owner", "reader", "outsider")]
        patches = (
            mock.patch.object(misp_store, "get_pir", side_effect=self.pirs.get),
            mock.patch.object(misp_store, "list_stakeholders", return_value=self.stakeholders),
            mock.patch.object(misp_store, "update_pir_intake"),
            mock.patch.object(dispatcher, "send_pir_intake"),
            mock.patch.object(requirements._matching, "invalidate_cache"),
            mock.patch("webapp.audit.record"),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = _app(requirements.bp)

    def triage(self, decision, **form):
        self.client.post(f"/pirs/{UUID}/triage", data={"decision": decision, **form})
        return misp_store.update_pir_intake

    def test_an_approval_is_matched_straight_away(self):
        self.triage("approved")
        misp_store.update_pir_intake.assert_called_once()
        requirements._matching.invalidate_cache.assert_called_once()

    def test_the_decision_reaches_only_the_owner_and_the_distribution(self):
        """It went to every Mattermost channel there is, with the question and
        the reason for a rejection."""
        self.triage("rejected", reason="Out of scope")
        recipients = dispatcher.send_pir_intake.call_args.args[3]
        self.assertEqual([s.uuid for s in recipients], ["owner", "reader"])

    def test_a_pir_triaged_already_is_not_triaged_again(self):
        """Rejecting an Active PIR left it Active, and so still matched."""
        self.pirs[UUID] = _pir(status="Active", intake_status="approved")
        self.triage("rejected", reason="Changed our mind").assert_not_called()

    def test_a_pir_is_not_merged_into_itself_or_into_one_that_cannot_take_it(self):
        self.pirs[OTHER] = _pir(OTHER, intake_status="rejected")
        for target in (UUID, OTHER, "nonsense", ""):
            with self.subTest(target=target):
                self.triage("merged", linked_pir_uuid=target).assert_not_called()

    def test_a_merge_links_the_pir_it_went_into(self):
        self.pirs[OTHER] = _pir(OTHER, status="Active", intake_status="approved")
        intake = self.triage("merged", linked_pir_uuid=OTHER)
        self.assertEqual(intake.call_args.kwargs["linked_pir_uuid"], OTHER)


class StatusBoard(unittest.TestCase):
    def test_a_move_refreshes_matching(self):
        """Matching reads only Active requirements, so moving one off Active
        kept it matched until the cache ran out."""
        for kind, record in (("pir", _pir(status="Active", intake_status="approved")),
                             ("gir", SimpleNamespace(uuid=UUID, gir_id="GIR-001", status="Active"))):
            with self.subTest(kind), \
                 mock.patch.object(misp_store, f"get_{kind}", return_value=record), \
                 mock.patch.object(misp_store, f"{kind}_to_data", return_value={}), \
                 mock.patch.object(misp_store, f"update_{kind}"), \
                 mock.patch("webapp.audit.record"), \
                 mock.patch.object(requirements._matching, "invalidate_cache") as invalidate:
                _app(requirements.bp).post(f"/{kind}s/{UUID}/status", data={"status": "Retired"})
            invalidate.assert_called_once()


class IntakeChannels(unittest.TestCase):
    def test_only_the_channels_of_the_stakeholders_are_posted_to(self):
        channels = [{"id": "soc", "name": "SOC", "type": "mattermost", "enabled": True,
                     "url": "https://chat.example.org/hooks/soc"},
                    {"id": "partner", "name": "Partner", "type": "mattermost", "enabled": True,
                     "url": "https://partner.example.org/hooks/p"}]
        owner = SimpleNamespace(name="SOC", notification_channels=["soc"])
        with mock.patch.object(config, "NOTIFICATION_CHANNELS", channels), \
             mock.patch.object(config, "FLOWINTEL_INSTANCES", [], create=True), \
             mock.patch("notifier.mattermost.requests.post") as post:
            dispatcher.send_pir_intake(_pir(), "approved", None, [owner])
        self.assertEqual([c.args[0] for c in post.call_args_list], ["https://chat.example.org/hooks/soc"])


def _product(**relations):
    """A product event whose object records the given relations."""
    event = MISPEvent()
    event.uuid = OTHER
    event.info = "[zsazsa:fia] Wiper on the grid"
    event.date = "2026-10-01"
    event.add_tag('zsazsa:ctiproduct="flash-intel"')
    obj = misp_store._build_obj("zsazsa-flash-intel")
    for relation, value in relations.items():
        obj.add_attribute(relation, value=value, type="text")
    event.add_object(obj)
    return event


class ProductLinks(unittest.TestCase):
    """No product names its PIR in its title or a tag, so looking only there
    found none: the statistics said no product answers a PIR."""

    def test_the_linked_pirs_are_read_from_the_object(self):
        self.assertEqual(misp_store.linked_pir_uuids(_product(**{"linked-pir-uuid": UUID})), {UUID})
        report = _product(**{"linked-pir-uuids": json.dumps([UUID, OTHER])})
        self.assertEqual(misp_store.linked_pir_uuids(report), {UUID, OTHER})

    def test_the_statistics_count_a_product_that_answers_a_pir(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = [_product(**{"linked-pir-uuid": UUID})]
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "list_rfis", return_value=[]), \
             mock.patch.object(misp_store, "list_stakeholders", return_value=[]):
            metrics = stats._program_metrics([_pir(status="Active")], [])
        self.assertEqual(metrics["products"]["with_pir_link"], 1)

    def test_the_stakeholder_page_lists_a_product_that_answers_their_pir(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = [_product(**{"linked-pir-uuid": UUID})]
        with mock.patch.object(misp_store, "_misp", return_value=misp):
            products = misp_store.products_for_stakeholder(SimpleNamespace(products=[]), [_pir()], [])
        self.assertEqual([p.uuid for p in products], [OTHER])


class GalaxyScopeSync(unittest.TestCase):
    def test_a_value_that_stays_keeps_its_notes(self):
        """Every value was deleted and added back without the notes typed against it."""
        event = MISPEvent()
        event.uuid = UUID
        event.add_attribute("text", "Sector|Energy|grid operators", comment=misp_store._FP_COMMENT)
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = event
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "add_focus_point") as add, \
             mock.patch.object(misp_store, "_rewrite_parent_scope"):
            misp_store.sync_focus_points_category(UUID, "Sector", ["energy", "Transport"])
        self.assertEqual([c.args[1:] for c in add.call_args_list],
                         [("Sector", "energy", "grid operators"), ("Sector", "Transport", "")])


if __name__ == "__main__":
    unittest.main()
