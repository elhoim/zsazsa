"""What the data collection page may write to, and with which key.

Every action on the page takes an event id and a source from the request and
writes with the key of that source's MISP. For a manual source that is zsazsa's
own MISP, where the id could name a stakeholder, a product or another
organisation's event, so an action only goes ahead for an event the collection
lists under that source. Reading through a manual source shows only manual
entries, a partner server's events are dismissed rather than rejected, and a
product never takes one of zsazsa's own records as its source.

MISP is an autospec of PyMISP; the collection cache and the sources are patched.

    python -m unittest tests.test_collection_actions
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask
from pymisp import MISPEvent, PyMISP

from webapp import misp_store
from webapp.routes import data_collection

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
MANUAL = {"id": "manual-slack", "kind": "manual", "label": "Slack", "url": "https://misp.example.org"}
PARTNER = {"id": "partner", "kind": "misp", "label": "Partner", "url": "https://partner.example.org",
           "api_key": "k", "verify_tls": True}


def _event(*tags):
    event = MISPEvent()
    event.uuid = UUID
    event.id = 7
    event.info = "An event"
    for tag in tags:
        event.add_tag(tag)
    return event


class _Page(unittest.TestCase):
    """The collection blueprint over a webapp MISP and a cache holding `cached`."""

    cached = ()

    def setUp(self):
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.misp.get_event.return_value = _event(misp_store.TAG_MANUAL_ENTRY)
        patches = (
            mock.patch.object(data_collection, "_sources", return_value=[MANUAL, PARTNER]),
            mock.patch.object(misp_store, "_misp", return_value=self.misp),
            mock.patch.object(data_collection.collection_cache, "get_events_by_uuids",
                              side_effect=lambda uuids: [r for r in self.cached if r["uuid"] in uuids]),
            mock.patch.object(data_collection.collection_cache, "insert_event"),
            mock.patch.object(data_collection.collection_cache, "flag_event"),
            mock.patch.object(data_collection.collection_cache, "is_flagged", return_value=False),
            mock.patch.object(data_collection.audit, "record"),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(data_collection.bp)
        self.client = app.test_client()

    def post(self, path, **body):
        return self.client.post(f"/collection/{UUID}/{path}", json={"source": MANUAL["id"], **body})


class AnEventTheCollectionDoesNotList(_Page):
    """Through a manual source, an id that names some other event on zsazsa's MISP."""

    def test_no_action_writes_to_it(self):
        for path, body in (("cti-tag", {"predicate": "relevance", "value": "high"}),
                           ("scope-tag", {"tag": 'misp-galaxy:country="belgium"'}),
                           ("flag", {}), ("reject", {}), ("dismiss", {})):
            with self.subTest(path):
                self.assertEqual(self.post(path, **body).status_code, 404)
        self.misp.tag.assert_not_called()
        self.misp.untag.assert_not_called()

    def test_a_bulk_reject_counts_it_as_an_error(self):
        reply = self.client.post("/collection/bulk-reject",
                                 json={"events": [{"uuid": UUID, "sourceId": MANUAL["id"]}]})
        self.assertEqual(reply.get_json()["errors"], 1)
        self.misp.get_event.assert_not_called()

    def test_the_page_only_shows_a_manual_entry(self):
        self.misp.get_event.return_value = _event('zsazsa:type="stakeholder"')
        reply = self.client.get(f"/collection/{UUID}/preview?source={MANUAL['id']}")
        self.assertEqual(reply.status_code, 404)
        self.assertIsNone(misp_store.get_manual_collection_event(UUID))
        with self.assertRaises(ValueError):
            misp_store.add_manual_collection_attachment(UUID, "x.txt", b"x")
        self.misp.add_attribute.assert_not_called()


class AnEventTheCollectionLists(_Page):
    cached = ({"uuid": UUID, "source_id": MANUAL["id"]}, {"uuid": UUID, "source_id": PARTNER["id"]})

    def test_it_can_be_tagged(self):
        self.misp.tag.return_value = {}
        reply = self.post("cti-tag", predicate="relevance", value="high")
        self.assertEqual(reply.status_code, 200)
        self.misp.tag.assert_called_once_with(UUID, 'cti-evaluation:relevance="high"', local=False)

    def test_a_partner_event_is_dismissed_not_rejected(self):
        """Its workflow state belongs to the other server, as a bulk reject has it."""
        reply = self.client.post(f"/collection/{UUID}/reject", json={"source": PARTNER["id"]})
        self.assertEqual(reply.status_code, 400)
        self.assertIn("dismissed", reply.get_json()["error"])


class Pull(unittest.TestCase):
    def test_one_of_zsazsas_records_is_not_pulled_in(self):
        """The scraper is often the MISP zsazsa keeps its records in."""
        app = Flask(__name__)
        app.register_blueprint(data_collection.bp)
        scraper = {"id": "scraper", "kind": "scraper"}
        with mock.patch.object(data_collection, "_resolve_pull_source", return_value=scraper), \
             mock.patch.object(misp_store, "_scraper_misp"), \
             mock.patch.object(data_collection, "_fetch_event_timed",
                               return_value=(_event('zsazsa:ctiproduct="flash-intel"'), [])), \
             mock.patch.object(data_collection.collection_cache, "insert_event") as insert, \
             mock.patch.object(data_collection.audit, "record"):
            reply = app.test_client().post("/collection/pull", json={"uuid": UUID, "source_id": "scraper"})
        self.assertEqual(reply.status_code, 404)
        insert.assert_not_called()


class PartnerConnection(unittest.TestCase):
    def test_it_has_a_timeout(self):
        """Without one, a partner server that stops answering holds the page."""
        with mock.patch.object(data_collection, "PyMISP") as connect:
            data_collection._connect_source(PARTNER)
        self.assertEqual(connect.call_args.kwargs["timeout"], misp_store.HTTP_TIMEOUT)


class AiSummary(unittest.TestCase):
    def test_a_report_misp_refuses_is_not_called_saved(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event_reports.return_value = [SimpleNamespace(content="An article about a RAT.")]
        misp.add_event_report.return_value = {"errors": (403, {"message": "Not allowed"})}
        # A summary that is wrongly taken as saved goes on to the audit log and
        # the cache, which belong to this install.
        with mock.patch("analyser.llm.summarise_report", return_value="**Summary** A RAT."), \
             mock.patch.object(data_collection.collection_cache, "mark_ai_summary") as mark, \
             mock.patch.object(data_collection.collection_cache, "insert_event"), \
             mock.patch.object(data_collection.audit, "record"):
            ok, message, _status = data_collection._generate_ai_summary(misp, _event(), "scraper")
        self.assertFalse(ok)
        self.assertIn("Could not save", message)
        mark.assert_not_called()


class ProductSource(unittest.TestCase):
    def test_a_zsazsa_record_is_not_tagged_as_a_product_source(self):
        """A product form could name a stakeholder or another product as its source."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = _event('zsazsa:type="stakeholder"')
        with mock.patch.object(misp_store, "_misp", return_value=misp):
            misp_store._tag_scraper_event_as_product_source(UUID, "flash-intel", source_id="webapp")
        misp.tag.assert_not_called()
        misp.untag.assert_not_called()


if __name__ == "__main__":
    unittest.main()
