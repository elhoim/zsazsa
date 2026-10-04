"""Drafting a whole briefing in the background, after it has been saved.

"Draft all stories" used to be a loop in the browser writing into unsaved text
areas, so closing the tab threw the work away. It now saves the briefing first
and a job drafts into the stored copy, which means three things have to hold:
the job writes once rather than leaving a briefing half rewritten, it carries
across every field it is not drafting, and a second job cannot start against a
briefing one is already working on.

    python -m unittest tests.test_briefing_draft_job
"""

import re
import unittest
from types import SimpleNamespace
from unittest import mock

from webapp import job_store
from webapp.routes import api
from webapp.routes import daily_briefing as briefing_routes


def _briefing(**over):
    base = dict(
        uuid="b" * 36, date="2026-09-25", title="Daily briefing", author="koen",
        tlp="amber", escalations="", notes="", detection_rules="", summary="",
        summary_stale=False, review_state="draft",
        stories=[SimpleNamespace(title="One", content="", source_event_uuid="e1",
                                 source_id="scraper", drafted_by="",
                                 threat_actor_types=[])],
        geographic_scope=["Belgium"], sectors=["Energy"], threat_actors=[],
        mitre_attack_techniques=["T1190"], threat_types=[], technology=[],
        vendor=[], incident=[], campaign=[],
    )
    base.update(over)
    return SimpleNamespace(**base)


class ScopeFieldsStayInStep(unittest.TestCase):
    """The job hands update_briefing the scope back whole, from its own list.

    The form builds the same set from the posted values. Two lists of nine
    field names in different modules drift, and the symptom would be a briefing
    quietly losing its sectors the first time the AI drafted it.
    """

    def test_the_job_and_the_form_agree_on_the_field_names(self):
        import inspect
        src = inspect.getsource(briefing_routes._parse_briefing_scope_from_form)
        from_form = set(re.findall(r'"(\w+)":', src))
        self.assertEqual(from_form, set(api._BRIEFING_SCOPE_FIELDS))


class TheJobWritesOnce(unittest.TestCase):
    def run_job(self, briefing, drafted=("What happened: it did.", "State-Nexus Actors"),
                with_summary=False, summary="A summary.", content="article text"):
        saved = []
        with mock.patch.object(api.misp_store, "get_briefing", return_value=briefing), \
             mock.patch.object(api.misp_store, "update_briefing",
                               side_effect=lambda u, d, **kw: saved.append((u, d, kw))), \
             mock.patch.object(api.misp_store, "briefing_scope_summary", return_value=[]), \
             mock.patch.object(api, "_get_event_content_and_scope",
                               return_value=(content, {})), \
             mock.patch.object(api, "_focus_points", return_value={}), \
             mock.patch.object(api, "_threat_actor_types", return_value=[]), \
             mock.patch.object(api.audit, "record"), \
             mock.patch("analyser.llm.draft_briefing_story",
                        **({"side_effect": drafted} if callable(drafted) else {"return_value": drafted})), \
             mock.patch("analyser.llm.draft_briefing_summary", return_value=summary):
            job = job_store.create_job("briefing-draft")
            api._run_briefing_draft_job(job["id"], briefing.uuid, with_summary, "koen@example.org")
        return saved, job_store.get_job(job["id"])

    def test_one_update_for_the_whole_briefing(self):
        saved, job = self.run_job(_briefing())
        self.assertEqual(len(saved), 1)
        self.assertEqual(job["status"], "completed")

    def test_the_drafted_text_and_its_actor_type_are_saved(self):
        saved, _ = self.run_job(_briefing())
        story = saved[0][1]["stories"][0]
        self.assertEqual(story["content"], "What happened: it did.")
        self.assertEqual(story["threat_actor_types"], ["State-Nexus Actors"])
        self.assertEqual(story["drafted_by"], "ai")

    def test_scope_the_job_never_touched_survives(self):
        saved, _ = self.run_job(_briefing())
        data = saved[0][1]
        self.assertEqual(data["geographic_scope"], ["Belgium"])
        self.assertEqual(data["sectors"], ["Energy"])
        self.assertEqual(data["mitre_attack_techniques"], ["T1190"])
        self.assertEqual(data["review_state"], "draft")

    def test_an_actor_type_the_analyst_picked_is_not_replaced(self):
        """The story button only fills this in when nothing is ticked yet.

        The suggestion is a starting point, so drafting a whole briefing must
        not quietly overwrite a choice someone made by hand.
        """
        briefing = _briefing(stories=[
            SimpleNamespace(title="One", content="", source_event_uuid="e1", source_id="s",
                            drafted_by="", threat_actor_types=["Hacktivists"])])
        saved, _ = self.run_job(briefing)
        self.assertEqual(saved[0][1]["stories"][0]["threat_actor_types"], ["Hacktivists"])

    def test_a_story_whose_model_call_raises_does_not_cost_the_others(self):
        """Eight stories are eight calls, and one timing out used to lose the lot."""
        briefing = _briefing(stories=[
            SimpleNamespace(title=name, content="", source_event_uuid=name, source_id="s",
                            drafted_by="", threat_actor_types=[])
            for name in ("one", "two", "three")])
        calls = []

        def flaky(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("the model timed out")
            return ("What happened: it did.", "")

        saved, job = self.run_job(briefing, drafted=flaky)
        contents = [s["content"] for s in saved[0][1]["stories"]]
        self.assertEqual(contents, ["What happened: it did.", "", "What happened: it did."])
        self.assertEqual(job["status"], "completed")
        self.assertIn("2 of 3", job["message"])

    def test_a_story_with_no_source_content_is_left_alone(self):
        saved, job = self.run_job(_briefing(stories=[
            SimpleNamespace(title="One", content="Written by hand.",
                            source_event_uuid="", source_id="",
                            drafted_by="", threat_actor_types=[])]), content=None)
        self.assertEqual(saved[0][1]["stories"][0]["content"], "Written by hand.")
        self.assertIn("0 of 1", job["message"])

    def test_the_summary_is_only_written_when_it_was_asked_for(self):
        saved, _ = self.run_job(_briefing(), with_summary=False)
        self.assertEqual(saved[0][1]["summary"], "")
        saved, _ = self.run_job(_briefing(), with_summary=True)
        self.assertEqual(saved[0][1]["summary"], "A summary.")
        self.assertFalse(saved[0][1]["summary_stale"])

    def test_drafting_stories_alone_marks_an_existing_summary_out_of_date(self):
        saved, _ = self.run_job(_briefing(summary="Written earlier."), with_summary=False)
        self.assertTrue(saved[0][1]["summary_stale"])

    def test_a_summary_the_model_failed_to_write_is_left_marked_out_of_date(self):
        """Asking for one and getting nothing back is the case that bit.

        The stories are redrafted either way, so the summary sitting on the
        briefing now describes text that is gone. Publishing it unmarked would
        send a summary that does not match its own stories.
        """
        saved, _ = self.run_job(_briefing(summary="Written earlier."),
                                with_summary=True, summary="")
        self.assertEqual(saved[0][1]["summary"], "Written earlier.")
        self.assertTrue(saved[0][1]["summary_stale"])

    def test_a_briefing_with_nothing_drafted_keeps_the_flag_it_had(self):
        saved, _ = self.run_job(_briefing(summary="Written earlier."),
                                content=None, with_summary=False)
        self.assertFalse(saved[0][1]["summary_stale"])

    def test_a_briefing_that_vanished_fails_the_job_rather_than_raising(self):
        with mock.patch.object(api.misp_store, "get_briefing", return_value=None):
            job = job_store.create_job("briefing-draft")
            api._run_briefing_draft_job(job["id"], "gone", False, "koen@example.org")
        self.assertEqual(job_store.get_job(job["id"])["status"], "failed")


class APublishWhileDraftingIsNotUndone(unittest.TestCase):
    """The job reads the briefing, then spends minutes on the model.

    If an analyst publishes in that time, writing the copy it read back would
    put the briefing back to draft under the approval just given, with stories
    nobody approved. The save is conditional on the state the job read.
    """

    def test_the_save_names_the_state_it_was_based_on(self):
        saved, _ = TheJobWritesOnce.run_job(self, _briefing())
        self.assertEqual(saved[0][2], {"expected_state": "draft"})

    def test_a_briefing_published_meanwhile_fails_the_job_and_is_left_alone(self):
        def published_meanwhile(uuid, data, expected_state=None):
            raise api.misp_store.BriefingStateChanged("published")

        with mock.patch.object(api.misp_store, "get_briefing", return_value=_briefing()), \
             mock.patch.object(api.misp_store, "update_briefing", side_effect=published_meanwhile), \
             mock.patch.object(api, "_get_event_content_and_scope", return_value=("text", {})), \
             mock.patch.object(api, "_focus_points", return_value={}), \
             mock.patch.object(api, "_threat_actor_types", return_value=[]), \
             mock.patch.object(api.audit, "record") as record, \
             mock.patch("analyser.llm.draft_briefing_story", return_value=("Drafted.", "")):
            job = job_store.create_job("briefing-draft")
            api._run_briefing_draft_job(job["id"], "b" * 36, False, "koen@example.org")
        job = job_store.get_job(job["id"])
        self.assertEqual(job["status"], "failed")
        self.assertIn("published while", job["message"])
        record.assert_not_called()


class TheStoreRefusesAStaleCopy(unittest.TestCase):
    def test_update_with_an_expected_state_that_moved_on_writes_nothing(self):
        from webapp import misp_store
        misp = mock.MagicMock()
        misp.get_event.return_value = SimpleNamespace(uuid="b" * 36, objects=[])
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_briefing_ns",
                               return_value=SimpleNamespace(review_state="published", stories=[])):
            with self.assertRaises(misp_store.BriefingStateChanged):
                misp_store.update_briefing("b" * 36, {"stories": []}, expected_state="draft")
        misp.delete_object.assert_not_called()
        misp.add_object.assert_not_called()

    def test_publish_waits_for_an_update_in_progress(self):
        import threading
        from webapp import misp_store
        ran = threading.Event()
        with mock.patch.object(misp_store, "_publish_briefing", side_effect=lambda u: ran.set()):
            with misp_store._briefing_write_lock:
                worker = threading.Thread(target=misp_store.publish_briefing, args=("b" * 36,))
                worker.start()
                self.assertFalse(ran.wait(0.3), "publish ran while an update held the lock")
            worker.join(2)
        self.assertTrue(ran.is_set())

class OnlyOneJobPerBriefing(unittest.TestCase):
    def test_a_second_start_returns_the_job_already_running(self):
        uuid = "c" * 36
        first = job_store.create_job("briefing-draft")
        job_store.update_job(first["id"], entity=uuid, status="running")
        try:
            with mock.patch.object(api.threading, "Thread") as thread:
                again = api.start_briefing_draft_job(uuid, "label", False, "koen@example.org")
            self.assertEqual(again["id"], first["id"])
            thread.assert_not_called()
        finally:
            job_store.forget_job(first["id"])

    def test_an_unknown_button_value_starts_nothing(self):
        with mock.patch.object(briefing_routes, "flash"):
            self.assertFalse(briefing_routes._start_ai_draft("u", "label", ""))
            self.assertFalse(briefing_routes._start_ai_draft("u", "label", "everything"))


if __name__ == "__main__":
    unittest.main()
