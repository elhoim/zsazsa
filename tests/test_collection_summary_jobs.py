"""AI summaries in data collection run as jobs, and cover manual entries.

The manual entry form has no MISP event yet, so it summarises the text on the
page; that call goes through a job like every other LLM run, or the analyst is
left watching a request that can outlive its proxy. An event typed in by hand
lives on the webapp MISP rather than the scraper one, which is what kept it out
of the summary path. And while a summary runs, the table holds back the actions
of its events: a flag or a reject set meanwhile is undone when it finishes.

    python -m unittest tests.test_collection_summary_jobs
"""

import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import requests
from bs4 import BeautifulSoup
from flask import Flask

import config as _config
from webapp import analyser_pipeline, collection_cache, create_app, job_store, misp_store
from webapp.routes import api, data_collection


class SummariseContentEndpoint(unittest.TestCase):
    """The manual entry form posts what is on the page and follows a job."""

    def setUp(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.register_blueprint(api.bp, url_prefix="/api")
        self.client = app.test_client()

    def post(self, **body):
        """Post with the worker thread stubbed out.

        Returns (reply, thread_args), where thread_args is what the job thread
        would have run with, or None when no job was started.
        """
        started = []
        with mock.patch.object(api.job_store, "create_job", return_value={"id": "job-1"}), \
             mock.patch.object(api.misp_session, "current_user_email", return_value="koen@example.org"), \
             mock.patch.object(api.threading, "Thread") as thread:
            thread.side_effect = lambda **kw: started.append(kw["args"]) or mock.MagicMock()
            reply = self.client.post("/api/summarise-content", json=body)
        return reply, (started[0] if started else None)

    def test_it_answers_with_a_job_to_follow(self):
        reply, args = self.post(content="An article.", title="An article")
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.get_json(), {"ok": True, "job_id": "job-1"})
        _job_id, content, title, user = args
        self.assertEqual((content, title, user), ("An article.", "An article", "koen@example.org"))

    def test_nothing_to_summarise_starts_no_job(self):
        reply, args = self.post(content="   ")
        self.assertEqual(reply.status_code, 400)
        self.assertIsNone(args)


class SummariseContentJob(unittest.TestCase):
    """The form applies whatever a completed job carries, so an answer the model
    declined to give has to fail the job rather than complete it empty."""

    def _run(self, summarised):
        with mock.patch.object(api.job_store, "update_job") as update, \
             mock.patch.object(api.audit, "record"), \
             mock.patch("analyser.llm.summarise_report", return_value=summarised):
            api._run_summarise_content_job("job-1", "An article.", "An article", "koen@example.org")
        return dict(update.call_args.kwargs)

    def test_a_summary_completes_the_job_with_the_text(self):
        final = self._run("Two hauliers were hit.")
        self.assertEqual(final["status"], "completed")
        self.assertEqual(final["result"], {"summary": "Two hauliers were hit."})

    def test_an_empty_answer_fails_the_job(self):
        final = self._run("  ")
        self.assertEqual(final["status"], "failed")
        self.assertIn("empty", final["error"])

    def test_a_broken_model_call_fails_the_job_with_its_reason(self):
        with mock.patch.object(api.job_store, "update_job") as update, \
             mock.patch("analyser.llm.summarise_report", side_effect=RuntimeError("no API key")):
            api._run_summarise_content_job("job-1", "An article.", "", "")
        final = dict(update.call_args.kwargs)
        self.assertEqual(final["status"], "failed")
        self.assertIn("no API key", final["error"])


_SCRAPER_SOURCE = {"id": "scraper", "kind": "scraper", "label": "MISP scraper"}
_MANUAL_SOURCE = {"id": "manual-slack", "kind": "manual", "label": "Slack"}
_EXTERNAL_SOURCE = {"id": "partner-misp", "kind": "misp", "label": "Partner"}
_ALL_SOURCES = [_SCRAPER_SOURCE, _MANUAL_SOURCE, _EXTERNAL_SOURCE]


class SummarisableSources(unittest.TestCase):
    """The summary is written back as a report, so it needs a MISP we may write
    to: the scraper, or the webapp instance holding the manual entries."""

    def _kinds(self, sources=_ALL_SOURCES):
        with mock.patch.object(data_collection, "_sources", return_value=sources):
            return data_collection._summarisable_sources()

    def test_scraper_and_manual_events_can_be_summarised(self):
        self.assertEqual(self._kinds(), {"scraper": "scraper", "manual-slack": "manual"})

    def test_a_third_party_misp_server_is_left_out(self):
        self.assertNotIn("partner-misp", self._kinds())

    def test_manual_events_are_read_from_the_webapp_misp(self):
        """They are created there, so the scraper connection would not find them."""
        with mock.patch.object(data_collection.misp_store, "_misp", return_value="webapp"), \
             mock.patch.object(data_collection.misp_store, "_scraper_misp", return_value="scraper"):
            self.assertEqual(data_collection._summarise_misp("manual"), "webapp")
            self.assertEqual(data_collection._summarise_misp("scraper"), "scraper")


class SummariseRoute(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.register_blueprint(data_collection.bp)
        self.client = app.test_client()

    def post(self, source, path=None, body=None):
        started = []
        with mock.patch.object(data_collection, "_sources", return_value=_ALL_SOURCES), \
             mock.patch.object(data_collection.job_store, "create_job", return_value={"id": "job-1"}), \
             mock.patch.object(data_collection.job_store, "update_job") as self.update_job, \
             mock.patch.object(data_collection.misp_session, "current_user_email", return_value="koen@example.org"), \
             mock.patch.object(data_collection.threading, "Thread") as thread:
            thread.side_effect = lambda **kw: started.append(kw["args"]) or mock.MagicMock()
            reply = self.client.post(path or "/collection/" + "u" * 36 + "/summarise",
                                     json=body or {"source": source})
        return reply, (started[0] if started else None)

    def test_a_manual_event_starts_a_summary_job(self):
        reply, args = self.post("manual-slack")
        self.assertEqual(reply.status_code, 200)
        self.assertTrue(reply.get_json()["ok"])
        _job_id, batch, _user = args
        self.assertEqual(batch, [{"uuid": "u" * 36, "sourceId": "manual-slack"}])

    def test_the_job_records_the_event_it_works_on(self):
        self.post("manual-slack")
        self.update_job.assert_called_once_with("job-1", events=["u" * 36])

    def test_a_batch_records_every_event_it_works_on(self):
        events = [{"uuid": "a" * 36, "sourceId": "scraper"}, {"uuid": "b" * 36, "sourceId": "manual-slack"}]
        self.post(None, path="/collection/bulk-summarise", body={"events": events})
        self.update_job.assert_called_once_with("job-1", events=["a" * 36, "b" * 36])

    def test_an_event_from_a_third_party_misp_is_refused(self):
        reply, args = self.post("partner-misp")
        self.assertEqual(reply.status_code, 400)
        self.assertIsNone(args)


class EventsBeingSummarised(unittest.TestCase):
    def test_only_an_unfinished_live_summary_holds_its_events(self):
        now = time.time()
        jobs = [
            {"id": "running", "action": "summarise", "status": "running", "updated_at": now, "events": ["a"]},
            {"id": "queued", "action": "bulk-summarise", "status": "queued", "updated_at": now,
             "events": ["b", "c"]},
            {"id": "done", "action": "summarise", "status": "completed", "updated_at": now, "events": ["d"]},
            # A worker that died with its process never moves its job off "running".
            {"id": "dead", "action": "summarise", "status": "running",
             "updated_at": now - job_store.STALE_AFTER_SECONDS - 60, "events": ["e"]},
            {"id": "other", "action": "collection-refresh", "status": "running", "updated_at": now,
             "events": ["f"]},
        ]
        with mock.patch.object(data_collection.job_store, "list_jobs", return_value=jobs):
            self.assertEqual(data_collection._events_being_summarised(),
                             {"a": "running", "b": "queued", "c": "queued"})


class BusyRowsInTheTable(unittest.TestCase):
    """What the server sends for a row whose event a summary is working on."""

    def setUp(self):
        def no_network(*args, **kwargs):
            raise requests.ConnectionError("tests run offline")

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rows = [{"uuid": uuid, "source_id": "scraper", "info": "Collected event", "tags": [],
                 "orgc": "CIRCL", "date": "2026-10-01"} for uuid in ("a" * 36, "b" * 36)]
        for patcher in (
            mock.patch("requests.adapters.HTTPAdapter.send", no_network),
            mock.patch.object(_config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(_config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(_config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(job_store, "_command", return_value=None),
            mock.patch.object(collection_cache, "get_events", return_value=rows),
            mock.patch.object(collection_cache, "get_source_status", return_value={}),
            mock.patch.object(collection_cache, "interval_s", return_value=300),
            mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
            mock.patch.object(misp_store, "list_briefings", return_value=[]),
            mock.patch.object(data_collection, "_events_being_summarised", return_value={"a" * 36: "job-7"}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        page = BeautifulSoup(create_app().test_client().get("/collection/").data, "html.parser")
        self.cells = {row["data-uuid"]: row.select_one(".event-actions")
                      for row in page.select("tr.event-row")}

    def test_a_busy_row_names_its_job_and_has_its_actions_disabled(self):
        cell = self.cells["a" * 36]
        self.assertEqual(cell["data-busy-job"], "job-7")
        self.assertIsNotNone(cell.select_one(".busy-indicator"))
        buttons = cell.select("button")
        self.assertTrue(buttons)
        self.assertTrue(all(b.has_attr("disabled") for b in buttons))

    def test_the_other_rows_are_left_alone(self):
        cell = self.cells["b" * 36]
        self.assertFalse(cell.has_attr("data-busy-job"))
        self.assertFalse(any(b.has_attr("disabled") for b in cell.select("button")))


class BatchAcrossSources(unittest.TestCase):
    """A selection can mix scraper events with manual entries, so the batch has
    to reach for the right connection per event rather than one for all."""

    def _run(self, batch, sources=_ALL_SOURCES, cached=None):
        """Run the batch job with both MISP connections and the LLM stubbed out.

        ``cached`` is what the collection cache holds, by default the batch
        itself. The returned namespace holds the stubs, so a check can see which
        connection each event was loaded from and how often the source list and
        the connections themselves were opened.
        """
        if cached is None:
            cached = [{"uuid": ev["uuid"], "source_id": ev["sourceId"]} for ev in batch]
        scraper_misp, webapp_misp = mock.MagicMock(), mock.MagicMock()
        with mock.patch.object(data_collection, "_sources", return_value=sources) as list_sources, \
             mock.patch.object(data_collection.collection_cache, "get_events_by_uuids",
                               side_effect=lambda uuids: [row for row in cached if row["uuid"] in uuids]), \
             mock.patch.object(data_collection.misp_store, "_scraper_misp", return_value=scraper_misp), \
             mock.patch.object(data_collection.misp_store, "_misp", return_value=webapp_misp) as open_webapp, \
             mock.patch.object(data_collection.job_store, "update_job") as update, \
             mock.patch.object(data_collection.job_store, "heartbeat"), \
             mock.patch.object(data_collection, "_generate_ai_summary",
                               return_value=(True, "ok", 200)) as generate:
            data_collection._run_summarise_job("job-1", batch, "koen@example.org")
        return SimpleNamespace(list_sources=list_sources, open_webapp=open_webapp,
                               scraper_misp=scraper_misp, webapp_misp=webapp_misp,
                               generate=generate, update=update)

    def test_each_event_is_loaded_from_its_own_source(self):
        run = self._run([{"uuid": "a" * 36, "sourceId": "scraper"},
                         {"uuid": "b" * 36, "sourceId": "manual-slack"}])
        self.assertEqual(run.scraper_misp.get_event.call_args[0][0], "a" * 36)
        self.assertEqual(run.webapp_misp.get_event.call_args[0][0], "b" * 36)
        self.assertEqual([call[0][2] for call in run.generate.call_args_list],
                         ["scraper", "manual-slack"])

    def test_the_source_list_is_read_once_for_the_whole_batch(self):
        """It is fetched from MISP, so reading it per event would put two extra
        round trips in front of every summary in the batch."""
        run = self._run([{"uuid": "a" * 36, "sourceId": "scraper"},
                         {"uuid": "b" * 36, "sourceId": "manual-slack"},
                         {"uuid": "c" * 36, "sourceId": "manual-slack"}])
        run.list_sources.assert_called_once()

    def test_all_manual_sources_share_one_connection(self):
        """Opening a PyMISP client costs a round trip of its own."""
        run = self._run(
            [{"uuid": "b" * 36, "sourceId": "manual-slack"},
             {"uuid": "c" * 36, "sourceId": "manual-newsletter"}],
            sources=_ALL_SOURCES + [{"id": "manual-newsletter", "kind": "manual", "label": "News"}])
        self.assertEqual(run.webapp_misp.get_event.call_count, 2)
        run.open_webapp.assert_called_once()

    def test_an_event_the_collection_does_not_list_is_skipped(self):
        """A manual source writes to zsazsa's own MISP, where an id from the
        request could name a stakeholder or a product."""
        run = self._run([{"uuid": "b" * 36, "sourceId": "manual-slack"}], cached=[])
        run.generate.assert_not_called()
        run.webapp_misp.get_event.assert_not_called()

    def test_an_event_from_an_unwritable_source_is_skipped(self):
        run = self._run([{"uuid": "c" * 36, "sourceId": "partner-misp"}])
        run.generate.assert_not_called()
        self.assertEqual(run.update.call_args.kwargs["result"]["skipped"], 1)


# The layout zsazsaprompts/summarise_misp_report.md asks the model for. The
# context lines are what the scope tags are read from.
_SUMMARY = """**Summary**

**What happened:** A campaign delivered Overlord RAT to hauliers.
**Recommended action:** Investigate.

**Severity:** High
**Urgency:** This week

**MISP context** (extract from the article content - always include all five lines):
- **Targeted sector:** Transportation
- **Geographic scope:** Belgium
- **MITRE ATT&CK techniques:** T1190
- **Threat actor:** Lazarus Group
- **Vendor/Technology:** None identified
"""

_MITRE_CLUSTERS = {
    "Exploit Public-Facing Application - T1190":
        'misp-galaxy:mitre-attack-pattern="Exploit Public-Facing Application - T1190"',
    "Phishing - T1566": 'misp-galaxy:mitre-attack-pattern="Phishing - T1566"',
}


class _FakeMisp:
    def __init__(self, article="An article about a RAT."):
        self.reports = [SimpleNamespace(name="Article", content=article)]
        self.tagged = []

    def get_event_reports(self, event_id, pythonify=True):
        return self.reports

    def add_event_report(self, event_id, report):
        self.reports.append(report)

    def tag(self, event, tag_name):
        self.tagged.append(tag_name)


class SummaryScopeTags(unittest.TestCase):
    """Summarising from data collection tags the event with the scope its
    summary names, the same tags the analyser applies when it writes one. The
    two read the same model output, so they have to read it the same way: the
    page had its own parser for an older, plain-text layout and silently tagged
    nothing once the prompt moved to markdown."""

    def summarise(self, summary, galaxies=None):
        """`galaxies` maps a galaxy to its clusters; a galaxy not in it gets the ATT&CK ones."""
        misp = _FakeMisp()
        event = SimpleNamespace(id=7, uuid="u" * 36, info="Overlord RAT campaign", tags=[])
        scope_calls = []

        def build_scope_tags(data):
            scope_calls.append(data)
            tags = []
            for sector in data.get("sectors") or []:
                tags.append(f'misp-galaxy:sector="{sector}"')
            for geo in data.get("geographic_scope") or []:
                tags.append(f'misp-galaxy:country="{geo}"')
            for actor in data.get("threat_actors") or []:
                tags.append(f'misp-galaxy:threat-actor="{actor}"')
            return tags

        with mock.patch("analyser.llm.summarise_report", return_value=summary), \
             mock.patch("analyser.tagger.set_workflow_state"), \
             mock.patch.object(data_collection.collection_cache, "mark_ai_summary"), \
             mock.patch.object(data_collection, "_refresh_cached_event"), \
             mock.patch.object(data_collection.audit, "record") as audit_record, \
             mock.patch.object(data_collection.misp_store, "_build_scope_tags", build_scope_tags), \
             mock.patch.object(data_collection.misp_store, "_galaxy_tag_map",
                               side_effect=lambda galaxy: (galaxies or {}).get(galaxy, _MITRE_CLUSTERS)):
            ok, message, status = data_collection._generate_ai_summary(misp, event, "scraper")

        self.assertEqual((ok, status), (True, 200), message)
        return misp.tagged, (scope_calls[0] if scope_calls else {}), dict(audit_record.call_args.kwargs)

    def test_the_context_lines_become_galaxy_tags(self):
        tagged, scope, _audit = self.summarise(_SUMMARY)
        self.assertEqual(scope["sectors"], ["Transportation"])
        self.assertEqual(scope["geographic_scope"], ["Belgium"])
        self.assertEqual(scope["threat_actors"], ["Lazarus Group"])
        self.assertIn('misp-galaxy:sector="Transportation"', tagged)
        self.assertIn('misp-galaxy:country="Belgium"', tagged)
        self.assertIn('misp-galaxy:threat-actor="Lazarus Group"', tagged)

    def test_only_the_techniques_named_are_tagged(self):
        tagged, _scope, _audit = self.summarise(_SUMMARY)
        self.assertIn(_MITRE_CLUSTERS["Exploit Public-Facing Application - T1190"], tagged)
        self.assertNotIn(_MITRE_CLUSTERS["Phishing - T1566"], tagged)

    def test_the_applied_tags_are_recorded_in_the_audit_trail(self):
        _tagged, _scope, audit = self.summarise(_SUMMARY)
        self.assertIn('misp-galaxy:sector="Transportation"', audit["details"])

    def test_a_sector_whose_name_holds_a_comma_stays_one_sector(self):
        """The line is split on commas, which cut "Government, Administration"
        in two and matched neither half."""
        summary = _SUMMARY.replace("Transportation", "Finance, Government, Administration")
        sectors = {"Finance": "s1", "Government, Administration": "s2"}
        _tagged, scope, _audit = self.summarise(summary, {misp_store.GALAXY_SECTOR: sectors})
        self.assertEqual(scope["sectors"], ["Finance", "Government, Administration"])

    def test_a_summary_that_identifies_nothing_tags_nothing(self):
        empty = _SUMMARY.replace("Transportation", "None identified") \
                        .replace("Belgium", "None identified") \
                        .replace("T1190", "None identified") \
                        .replace("Lazarus Group", "None identified")
        tagged, scope, _audit = self.summarise(empty)
        self.assertEqual(tagged, [])
        self.assertEqual(scope, {})


class NamesWithCommas(unittest.TestCase):
    """Galaxy names that hold a comma, read off a comma-separated context line."""

    LINE = """- **Targeted sector:** Finance, Government, Administration
- **Geographic scope:** Belgium, Bonaire, Saint Eustatius and Saba
"""
    NAMES = frozenset({"government, administration", "bonaire, saint eustatius and saba"})

    def test_two_neighbours_that_make_a_known_name_stay_together(self):
        context = analyser_pipeline.parse_misp_context(self.LINE, self.NAMES)
        self.assertEqual(context["sectors"], ["Finance", "Government, Administration"])
        self.assertEqual(context["geographies"], ["Belgium", "Bonaire, Saint Eustatius and Saba"])

    def test_without_the_names_the_line_is_split_as_before(self):
        context = analyser_pipeline.parse_misp_context(self.LINE)
        self.assertEqual(context["sectors"], ["Finance", "Government", "Administration"])

    def test_the_names_come_from_the_sector_and_country_galaxies(self):
        galaxies = {misp_store.GALAXY_SECTOR: {"Finance": "s1", "Government, Administration": "s2"},
                    misp_store.GALAXY_COUNTRY: {"bonaire, saint eustatius and saba ": "c1", "belgium": "c2"}}
        with mock.patch.object(misp_store, "_galaxy_tag_map", side_effect=lambda g: galaxies.get(g, {})):
            self.assertEqual(analyser_pipeline.galaxy_names_with_commas(), self.NAMES)

    def test_the_analyser_tags_them_too_trailing_space_and_all(self):
        """MISP's country galaxy writes Bonaire with a space at the end, so it
        never matched a name read off a line, comma or not."""
        galaxies = {misp_store.GALAXY_SECTOR: {"Government, Administration": "sector-tag"},
                    misp_store.GALAXY_COUNTRY: {"bonaire, saint eustatius and saba ": "country-tag"}}
        misp = _FakeMisp()
        with mock.patch.object(misp_store, "_galaxy_tag_map", side_effect=lambda g: galaxies.get(g, {})):
            lookup = analyser_pipeline._build_galaxy_lookup()
            context = analyser_pipeline.parse_misp_context(self.LINE, analyser_pipeline.galaxy_names_with_commas())
            analyser_pipeline._apply_misp_context_tags(misp, SimpleNamespace(uuid="e"), context, lookup)
            scope_tags = misp_store._build_scope_tags({"geographic_scope": context["geographies"],
                                                       "sectors": context["sectors"]})
        self.assertEqual(sorted(misp.tagged), ["country-tag", "sector-tag"])
        self.assertEqual(sorted(scope_tags), ["country-tag", "sector-tag"])


if __name__ == "__main__":
    unittest.main()
