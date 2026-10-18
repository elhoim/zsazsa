"""The statistics, scope statistics, pipeline and audit log pages: what each
number counts.

A product went out when MISP published it, or, for the profiles and feeds zsazsa
publishes without publishing the event, when it last changed. Products are named
after their type whatever tag value the settings give it, every page of them is
read, a rejected one is left out, and a stakeholder is covered by an active PIR
they own. Indicator health counts every enabled server once, from a cache. Scope values are
counted once per record, whatever their case. The pipeline never purges history
on an answer MISP refused, and the audit log says when it shows only part of
itself.

MISP is an autospec of PyMISP or the store is patched; the databases are
temporary.

    python -m unittest tests.test_statistics
"""

import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask
from pymisp import MISPEvent, PyMISP

import config
from core import db as core_db
from webapp import collection_cache, create_app, misp_store
from webapp.routes import pipeline, stats

PIR = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
DAY = 86400


def _product(published=None, changed=1, tag='zsazsa:ctiproduct="flash-intel"', linked_pir="",
             state="approved", object_name="zsazsa-flash-intel"):
    """A product event, published and last changed that many days ago, whose
    object records ``state`` (None for an object without one)."""
    now = time.time()
    event = MISPEvent()
    event.from_dict(info="[zsazsa:fia] An alert", date="2026-10-01",
                    timestamp=str(int(now - changed * DAY)),
                    publish_timestamp=str(int(now - published * DAY)) if published is not None else "0",
                    published=published is not None)
    event.add_tag(tag)
    if object_name:
        obj = misp_store._build_obj(object_name)
        relation = "status" if object_name == "zsazsa-threat-actor-profile" else "review-state"
        if state:
            obj.add_attribute(relation, value=state, type="text")
        if linked_pir:
            obj.add_attribute("linked-pir-uuid", value=linked_pir, type="text")
        event.add_object(obj)
    return event


def _pir(uuid=PIR, pir_id="PIR-001", status="Active", owner_uuid=""):
    return SimpleNamespace(uuid=uuid, pir_id=pir_id, status=status, owner_uuid=owner_uuid,
                           intel_level=[], collection_sources=[], focus_points=[])


def _metrics(products, pirs=(), stakeholders=(), misp=None):
    if misp is None:
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = products
    with mock.patch.object(misp_store, "_misp", return_value=misp), \
         mock.patch.object(misp_store, "list_rfis", return_value=[]):
        return stats._program_metrics(list(pirs), [], list(stakeholders))


class ProgramHealth(unittest.TestCase):
    def test_recent_products_are_counted(self):
        """PyMISP hands the timestamps over as datetimes, which int() refused,
        so every product read as dateless and both counts stayed at 0."""
        products = [_product(published=2), _product(published=20), _product(published=100),
                    _product(changed=10, tag='zsazsa:ctiproduct="threat-actor-profile"',
                             object_name="zsazsa-threat-actor-profile", state="Published")]
        metrics = _metrics(products)["products"]
        self.assertEqual((metrics["last_7d"], metrics["last_30d"]), (1, 3))

    def test_pir_coverage_counts_a_product_from_the_last_90_days(self):
        other = "0b3f6a8e-2c4d-4e5f-9a1b-c2d3e4f5a6b7"
        pirs = [_pir(), _pir(other, "PIR-002")]
        coverage = _metrics([_product(published=10, linked_pir=PIR), _product(published=100, linked_pir=other)],
                            pirs)["pir_coverage"]
        self.assertEqual((coverage["covered"], coverage["uncovered"]), (1, 1))

    def test_products_are_named_after_their_type_whatever_the_tag(self):
        """The maturity signals looked the counts up under the built-in tag values."""
        with mock.patch.object(config, "TAG_FLASH_INTEL", 'zsazsa:ctiproduct="fia"', create=True):
            program = _metrics([_product(published=1, tag='zsazsa:ctiproduct="fia"')])
            threat = stats._maturity_signals(program, [], [], 0, [])[2]
        self.assertEqual(program["products"]["by_type"], {"Flash intel alert": 1})
        self.assertIn("1 flash intel alerts", threat["observed"])

    def test_every_page_of_products_is_read(self):
        """Only the first 500 were, so the totals stopped there."""
        pages = {1: [_product(published=1) for _ in range(500)], 2: [_product(published=1)]}
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.side_effect = lambda page=1, **kw: pages.get(page, [])
        metrics = _metrics([], misp=misp)
        self.assertEqual(metrics["products"]["total"], 501)

    def test_a_draft_has_not_gone_out(self):
        """It was dated by its last edit, so one edited yesterday counted as a
        product of the last 7 days and covered the PIR it was linked to."""
        program = _metrics([_product(changed=1, state="draft", linked_pir=PIR)], [_pir()])
        self.assertEqual(program["products"]["last_7d"], 0)
        self.assertEqual(program["pir_coverage"]["covered"], 0)

    def test_a_rejected_product_is_left_out_and_drafts_are_named(self):
        """A rejected product never went out, and the analyser leaves many."""
        products = [_product(published=1), _product(state="rejected"), _product(state="draft"),
                    _product(state="draft", tag='zsazsa:ctiproduct="threat-actor-profile"',
                             object_name="zsazsa-threat-actor-profile"),
                    _product(tag='zsazsa:ctiproduct="indicator-feed"', object_name="zsazsa-indicator-feed",
                             state=None),
                    _product(object_name="")]
        metrics = _metrics(products)["products"]
        self.assertEqual(metrics["total"], 5)
        self.assertEqual(metrics["drafts"], 3)
        self.assertEqual(metrics["by_type"], {"Flash intel alert": 3, "Threat actor profile": 1,
                                              "Indicator feed": 1})
        self.assertEqual(metrics["drafts_by_type"], {"Flash intel alert": 2, "Threat actor profile": 1})

    def test_a_stakeholder_is_covered_by_an_active_pir_they_own(self):
        pirs = [_pir(owner_uuid="ada"), _pir(pir_id="PIR-002", status="Pending", owner_uuid="bob")]
        stakeholders = [SimpleNamespace(uuid="ada"), SimpleNamespace(uuid="bob")]
        coverage = _metrics([], pirs, stakeholders)["stakeholder_coverage"]
        self.assertEqual((coverage["with_pir"], coverage["without_pir"]), (1, 1))

    def test_a_program_held_back_by_coverage_says_why(self):
        """Three active PIRs and every product linked, but none in the last 90
        days: CTI1, with no gap to explain it."""
        pirs = [_pir(f"{i}" * 36, f"PIR-00{i}") for i in range(1, 4)]
        program = _metrics([_product(published=100, linked_pir="1" * 36)], pirs)
        signal = stats._maturity_signals(program, pirs, [], 1, [])[0]
        self.assertEqual(signal["level"], "CTI1")
        self.assertIn("No active PIR had a product in the last 90 days", signal["gaps"])


class ScopeStats(unittest.TestCase):
    def categories(self, pirs=(), fias=()):
        empty = {name: mock.Mock(return_value=[]) for name in
                 ("list_girs", "list_threat_actor_profiles", "list_briefings")}
        with mock.patch.multiple(misp_store, list_pirs=mock.Mock(return_value=list(pirs)),
                                 list_fias=mock.Mock(return_value=list(fias)), **empty):
            return {c["attr"]: c for c in misp_store.scope_stats()}

    def test_threat_actors_are_counted(self):
        pir = SimpleNamespace(uuid="p", pir_id="PIR-001", question="q", threat_actors=["Lazarus Group"])
        actors = self.categories([pir])["threat_actors"]
        self.assertEqual([i["value"] for i in actors["items"]], ["Lazarus Group"])

    def test_a_value_is_one_value_whatever_its_case_and_counts_once_per_record(self):
        pir = SimpleNamespace(uuid="p", pir_id="PIR-001", question="q", geographic_scope=["Belgium", "belgium"])
        alert = SimpleNamespace(uuid="f", fia_id="FIA-00001", title="t", geographic_scope=["BELGIUM"])
        geography = self.categories([pir], [alert])["geographic_scope"]
        self.assertEqual([(i["value"], i["count"]) for i in geography["items"]], [("Belgium", 2)])
        self.assertEqual([e["kind"] for e in geography["items"][0]["entries"]], ["pir", "fia"])


class IndicatorHealth(unittest.TestCase):
    """The pane counts indicators on every server zsazsa reads, from a cache the
    worker fills, as MISP's statistics take a while on a large instance."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp.name) / "cache.db")),
                        mock.patch.object(config, "MISP_WEBAPP_URL", "https://misp.example.org"),
                        mock.patch.object(config, "MISP_WEBAPP_KEY", "wk"),
                        mock.patch.object(config, "MISP_URL", "https://scraper.example.org/"),
                        mock.patch.object(config, "MISP_KEY", "sk"),
                        mock.patch.object(config, "MISP_SERVERS", [
                            {"id": "partner", "label": "Partner", "url": "https://partner.example.org", "api_key": "k"},
                            {"id": "off", "url": "https://off.example.org", "api_key": "k", "enabled": False},
                            {"id": "nokey", "url": "https://nokey.example.org"},
                            {"id": "again", "url": "https://scraper.example.org", "api_key": "k"},
                        ])):
            patcher.start()
            self.addCleanup(patcher.stop)
        collection_cache.init_db()

    def test_every_enabled_server_is_counted_once(self):
        """The scraper is often the store itself, and counting it twice doubles it."""
        ids = [misp_store._server_id(s) for s in misp_store.indicator_stat_servers()]
        self.assertEqual(ids, [misp_store.WEBAPP_STORE_ID, "scraper", "partner"])

    def refresh(self, answers):
        def connect(url, *args, **kwargs):
            misp = mock.create_autospec(PyMISP, instance=True)
            answer = answers[url.rstrip("/")]
            if isinstance(answer, Exception):
                misp.attributes_statistics.side_effect = answer
            else:
                misp.attributes_statistics.return_value = answer
            return misp
        with mock.patch.object(collection_cache, "PyMISP", side_effect=connect):
            collection_cache.refresh_indicator_stats()
        return {s["id"]: s for s in pipeline._indicator_stats()["servers"]}

    def test_the_counts_are_kept_per_server(self):
        servers = self.refresh({"https://misp.example.org": {"ip-dst": "4", "comment": "6"},
                                "https://scraper.example.org": {"domain": "2"},
                                "https://partner.example.org": {"ip-dst": "1", "sha256": "0"}})
        self.assertEqual(servers["zsazsa-store"]["by_type"], {"ip-dst": 4})
        self.assertEqual(servers["zsazsa-store"]["all_total"], 10)
        self.assertEqual(servers["partner"]["by_type"], {"ip-dst": 1})

    def test_a_server_that_fails_keeps_the_counts_it_last_gave(self):
        ok = {"https://misp.example.org": {"ip-dst": "4"}, "https://scraper.example.org": {"domain": "2"},
              "https://partner.example.org": {"ip-dst": "1"}}
        self.refresh(ok)
        servers = self.refresh({**ok, "https://partner.example.org": ConnectionError("timed out")})
        self.assertEqual(servers["partner"]["by_type"], {"ip-dst": 1})
        self.assertIn("timed out", servers["partner"]["error"])
        self.assertEqual(servers["scraper"]["error"], "")

    def test_a_server_no_longer_configured_drops_out(self):
        self.refresh({"https://misp.example.org": {}, "https://scraper.example.org": {},
                      "https://partner.example.org": {}})
        with mock.patch.object(config, "MISP_SERVERS", []):
            servers = self.refresh({"https://misp.example.org": {}, "https://scraper.example.org": {}})
        self.assertEqual(sorted(servers), ["scraper", "zsazsa-store"])

    def test_the_refresh_button_runs_a_job(self):
        app = Flask(__name__)
        app.register_blueprint(pipeline.bp)
        self.addCleanup(pipeline.job_store._memory.clear)
        with mock.patch.object(pipeline.job_store, "_command", return_value=None), \
             mock.patch.object(collection_cache, "refresh_indicator_stats") as refresh:
            reply = app.test_client().post("/pipeline/indicator-stats/refresh")
            job_id = reply.get_json()["job_id"]
            for thread in threading.enumerate():
                if thread.name == pipeline.job_store.thread_name(job_id):
                    thread.join(5)
            self.assertEqual(pipeline.job_store.get_job(job_id)["status"], "completed")
        refresh.assert_called_once()


class _TempDatabase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        core_db.init_db()


class Purge(_TempDatabase):
    def rows(self):
        with core_db.row_connection() as db:
            return db.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]

    def test_nothing_is_purged_on_an_answer_misp_refused(self):
        """A refused search read as "these events are gone", and their history
        was deleted."""
        with core_db.row_connection() as db:
            db.executemany("INSERT INTO event_log (event_uuid, outcome) VALUES (?, 'not_relevant')",
                           [(PIR,), ("0b3f6a8e-2c4d-4e5f-9a1b-c2d3e4f5a6b7",)])
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = {"errors": (500, {"message": "Internal error"})}
        with mock.patch.object(misp_store, "_scraper_misp", return_value=misp), \
             self.assertRaises(RuntimeError):
            pipeline._purge_orphaned_rows()
        self.assertEqual(self.rows(), 2)


class SourceCounts(unittest.TestCase):
    def test_a_tag_no_event_has_is_left_out(self):
        """The panel scales its bars by the busiest source, and a busiest source
        of 0 failed the page."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.tags_statistics.return_value = {"tags": {"scraper:data-collection-source:A": "3",
                                                      "scraper:data-collection-source:B": "0"}}
        with mock.patch.object(misp_store, "scraper_enabled", return_value=True), \
             mock.patch.object(misp_store, "_scraper_misp", return_value=misp):
            self.assertEqual(misp_store.data_collection_source_counts(), [{"source_feed": "A", "n": 3}])

    def test_a_partner_source_is_counted_with_the_filter_the_cache_reads_it_with(self):
        """Only its any-of tags were applied, so "on server" counted events the
        source never takes in."""
        src = {"id": "partner", "label": "Partner", "kind": "misp", "url": "https://partner.example.org",
               "api_key": "k", "verify_tls": True, "tags": ["tlp:clear"], "tags_and": [], "tags_not": ["tlp:red"]}
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = []
        with mock.patch("webapp.routes.data_collection._sources", return_value=[src]), \
             mock.patch.object(collection_cache, "get_source_status", return_value={}), \
             mock.patch.object(misp_store, "_test_connection", return_value={"ok": True}), \
             mock.patch("pymisp.PyMISP", return_value=misp):
            pipeline._source_health()
        for call in misp.search.call_args_list:
            self.assertTrue(call.kwargs["published"])
            self.assertEqual(call.kwargs["tags"], misp.build_complex_query.return_value)
        misp.build_complex_query.assert_called_with(or_parameters=["tlp:clear"], and_parameters=None,
                                                    not_parameters=["tlp:red"])


class AuditLog(_TempDatabase):
    def setUp(self):
        super().setUp()
        for patcher in (
            mock.patch.object(config, "LOG_FILE", str(Path(config.DB_FILE).with_name("test.log")), create=True),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def page(self, query=""):
        return BeautifulSoup(self.client.get(f"/logs{query}").data, "html.parser").get_text(" ", strip=True)

    def write(self, n):
        with core_db.row_connection() as db:
            db.executemany("INSERT INTO audit_log (timestamp, user, action, entity_type) VALUES (?, ?, ?, ?)",
                           [("2026-10-18T10:00:00", "analyst@example.org", "update", "pir")] * n)

    def test_a_filter_that_matches_nothing_says_so(self):
        self.write(1)
        self.assertIn("No entries match these filters.", self.page("?action=delete"))

    def test_a_cut_off_list_says_so(self):
        self.write(201)
        self.assertIn("The newest 200 entries are shown.", self.page())

    def test_a_short_list_does_not(self):
        self.write(3)
        self.assertNotIn("The newest 200", self.page())


if __name__ == "__main__":
    unittest.main()
