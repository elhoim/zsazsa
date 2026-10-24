"""What the scheduled analyser makes, as Settings > System switches it on.

The flash intel alerts from focus points are what it always made, and stay on
by default; switched off, the run reads no scraper events and leaves the
watermark where it is, so switching them on again picks up from there. The
dashboard's three options run after them, each only when switched on, in the
order flash intel, advisories, briefing: the briefing rejects what it finds
irrelevant, which would take those events out of the other two. They read
yesterday's events as well as today's, or an event that came in after the last
run of a day would never be read. The briefing comes once a day, from its hour
on, and a day only counts as briefed when the run went through. An event gets
one flash intel alert at most, whichever run made it: the alerts themselves say
which events they came from.

The state file, the database and the log are temporary; every MISP and model
call is stubbed.

    python -m unittest tests.test_scheduled_analyser
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

from pymisp import PyMISP

import config
import run_analyser
from analyser import reader

SWITCHES = {"ANALYSER_FLASH_INTEL": True, "ANALYSER_FLASH_INTEL_REQUIREMENTS": False,
            "ANALYSER_VULNERABILITY_ADVISORIES": False, "ANALYSER_DAILY_BRIEFING": False,
            "ANALYSER_DAILY_BRIEFING_HOUR": 21}
EVENING = datetime(2026, 10, 24, 21, 15, tzinfo=timezone.utc)


def _switches(**on):
    return mock.patch.multiple(config, create=True, **{**SWITCHES, **on})


class Due(unittest.TestCase):
    def due(self, now=EVENING, briefed=None, **on):
        with _switches(**on), mock.patch.object(run_analyser, "load_last_briefing", return_value=briefed):
            return run_analyser.scheduled_actions(now)

    def test_out_of_the_box_nothing_of_the_dashboard_runs(self):
        self.assertEqual(self.due(), [])

    def test_everything_switched_on_runs_with_the_briefing_last(self):
        self.assertEqual(self.due(ANALYSER_FLASH_INTEL_REQUIREMENTS=True, ANALYSER_VULNERABILITY_ADVISORIES=True,
                                  ANALYSER_DAILY_BRIEFING=True),
                         ["flash-intel", "vea", "daily-briefing"])

    def test_the_briefing_waits_for_its_hour_and_comes_once_a_day(self):
        self.assertEqual(self.due(EVENING.replace(hour=20), ANALYSER_DAILY_BRIEFING=True), [])
        self.assertEqual(self.due(briefed="2026-10-24", ANALYSER_DAILY_BRIEFING=True), [])
        self.assertEqual(self.due(briefed="2026-10-23", ANALYSER_DAILY_BRIEFING=True), ["daily-briefing"])


class RunScheduled(unittest.TestCase):
    def run_them(self, actions, result):
        jobs = []
        with mock.patch.object(run_analyser, "scheduled_actions", return_value=actions), \
             mock.patch.object(run_analyser.job_store, "create_job",
                               side_effect=lambda action, **kw: jobs.append((action, kw["label"])) or {"id": action}), \
             mock.patch.object(run_analyser.analyser_pipeline, "run_action", return_value=result) as run, \
             mock.patch.object(run_analyser, "save_last_briefing") as briefed:
            run_analyser.run_scheduled_actions()
        return jobs, run, briefed

    def test_each_runs_as_a_job_the_way_the_dashboard_starts_one(self):
        jobs, run, _briefed = self.run_them(["flash-intel", "vea"], {"message": "Created 1 draft."})
        self.assertEqual(jobs, [("flash-intel", "Scheduled flash intel alert"),
                                ("vea", "Scheduled vulnerability advisory")])
        self.assertEqual(run.call_args_list, [mock.call("flash-intel", "analyser", triggered_by="schedule", days=2),
                                              mock.call("vea", "analyser", triggered_by="schedule", days=2)])

    def test_the_day_is_briefed_only_when_the_briefing_went_through(self):
        _jobs, _run, briefed = self.run_them(["daily-briefing"], {"message": "Daily briefing draft created."})
        briefed.assert_called_once()
        _jobs, _run, briefed = self.run_them(["daily-briefing"], None)
        briefed.assert_not_called()


class RunAction(unittest.TestCase):
    """The dashboard's runner, which the schedule uses too."""

    def run_action(self, outcome):
        pipeline = run_analyser.analyser_pipeline
        with mock.patch.object(pipeline, "run_vea_action", **outcome), \
             mock.patch.object(pipeline.job_store, "get_job", return_value={"action": "vea"}), \
             mock.patch.multiple(pipeline.job_store, update_job=mock.DEFAULT, append_log=mock.DEFAULT,
                                 set_step=mock.DEFAULT, complete_open_steps=mock.DEFAULT), \
             mock.patch.object(pipeline.audit, "record"), \
             mock.patch.object(pipeline, "save_last_action"), \
             mock.patch.object(pipeline, "log_pipeline_run_start", return_value=1) as started, \
             mock.patch.object(pipeline, "log_pipeline_run_end"):
            result = pipeline.run_action("job-1", "analyser", triggered_by="schedule")
        return result, started

    def test_it_says_who_ran_it_and_returns_what_it_made(self):
        result, started = self.run_action({"return_value": {"message": "Created 2 drafts."}})
        self.assertEqual(result, {"message": "Created 2 drafts."})
        started.assert_called_once_with("vea", triggered_by="schedule")

    def test_a_failed_action_returns_nothing(self):
        with self.assertLogs("webapp.analyser_pipeline", level="ERROR"):
            result, _started = self.run_action({"side_effect": RuntimeError("MISP down")})
        self.assertIsNone(result)


class Candidates(unittest.TestCase):
    def test_the_schedule_reads_yesterday_as_well(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = []
        today = datetime.now(timezone.utc).date()
        pipeline = run_analyser.analyser_pipeline
        with mock.patch.object(pipeline, "scraper_enabled", return_value=True), \
             mock.patch.object(pipeline.misp_store, "_scraper_misp", return_value=misp):
            pipeline._incomplete_scraper_events()
            self.assertEqual(misp.search.call_args.kwargs["date_from"], today.isoformat())
            pipeline._incomplete_scraper_events(days=2)
            self.assertEqual(misp.search.call_args.kwargs["date_from"], (today - timedelta(days=1)).isoformat())

    def test_the_run_on_requirements_skips_an_event_with_an_alert(self):
        pipeline = run_analyser.analyser_pipeline
        events = [SimpleNamespace(uuid="a" * 36, info="Alerted", tags=[], galaxies=[]),
                  SimpleNamespace(uuid="b" * 36, info="New", tags=[], galaxies=[])]
        with mock.patch.object(pipeline, "_common_candidate_events", return_value=(None, events, {}, {}, {})), \
             mock.patch.object(pipeline.misp_store, "flash_intel_source_uuids", return_value={"a" * 36}), \
             mock.patch.object(pipeline.req_matching, "get_requirements", return_value=([], [])), \
             mock.patch.object(pipeline.req_matching, "match_events", return_value={}) as match, \
             mock.patch.object(pipeline, "_log"):
            pipeline.run_flash_intel_action(days=2)
        self.assertEqual([e["uuid"] for e in match.call_args.args[0]], ["b" * 36])


class FlashIntelSources(unittest.TestCase):
    def test_every_alert_counts_whatever_became_of_it(self):
        alerts = [SimpleNamespace(source_event_uuids=["a" * 36], review_state="rejected"),
                  SimpleNamespace(source_event_uuids=["b" * 36, "c" * 36], review_state="pending-review")]
        with mock.patch.object(run_analyser.misp_store, "list_fias", return_value=alerts):
            self.assertEqual(run_analyser.misp_store.flash_intel_source_uuids(), {"a" * 36, "b" * 36, "c" * 36})


class BriefingDay(unittest.TestCase):
    def test_it_is_kept_next_to_the_watermark(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write(json.dumps({"analyser_last_run": 1000}))
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        with mock.patch.object(config, "STATE_FILE", handle.name):
            self.assertIsNone(reader.load_last_briefing())
            reader.save_last_briefing("2026-10-24")
            self.assertEqual(reader.load_last_briefing(), "2026-10-24")
            self.assertEqual(reader.load_last_run(), 1000)


class Main(unittest.TestCase):
    def run_main(self, events=(), alerted=(), **on):
        with _switches(**on), \
             mock.patch.object(run_analyser, "setup_logging"), \
             mock.patch.object(run_analyser, "init_db"), \
             mock.patch.object(run_analyser, "log_pipeline_run_start", return_value=1), \
             mock.patch.object(run_analyser, "log_pipeline_run_end"), \
             mock.patch.object(run_analyser, "scraper_enabled", return_value=True), \
             mock.patch.object(run_analyser, "get_misp"), \
             mock.patch.object(run_analyser, "get_misp_webapp"), \
             mock.patch.object(run_analyser, "get_new_scraper_events", return_value=list(events)) as read, \
             mock.patch.object(run_analyser.misp_store, "flash_intel_source_uuids", return_value=set(alerted)), \
             mock.patch.object(run_analyser, "process_flash_intel",
                               return_value={"outcome": "not_relevant"}) as self.process, \
             mock.patch.object(run_analyser, "log_event"), \
             mock.patch.object(run_analyser.job_store, "create_job", return_value={"id": "job-1"}), \
             mock.patch.object(run_analyser.job_store, "update_job"), \
             mock.patch.object(run_analyser, "save_last_run") as watermark, \
             mock.patch.object(run_analyser.feed_cache, "refresh_due", return_value=0), \
             mock.patch.object(run_analyser, "run_scheduled_actions") as scheduled:
            run_analyser.main()
        return read, watermark, scheduled

    def test_the_alerts_from_focus_points_run_as_before(self):
        read, watermark, scheduled = self.run_main()
        read.assert_called_once()
        watermark.assert_called_once()
        scheduled.assert_called_once_with()

    def test_an_event_an_alert_was_made_from_gets_no_second_one(self):
        events = [SimpleNamespace(uuid="a" * 36, info="Alerted"), SimpleNamespace(uuid="b" * 36, info="New")]
        self.run_main(events=events, alerted={"a" * 36})
        self.assertEqual([c.args[2].uuid for c in self.process.call_args_list], ["b" * 36])

    def test_switched_off_the_scraper_queue_is_left_where_it_is(self):
        """Moving the watermark over events nobody read would skip them for good."""
        read, watermark, scheduled = self.run_main(ANALYSER_FLASH_INTEL=False)
        read.assert_not_called()
        watermark.assert_not_called()
        scheduled.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
