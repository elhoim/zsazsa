"""The flash intel draft the analyser files: its object, and the tag on its source.

MISP refused the zsazsa-flash-intel object because it was built without its
template, so it had no meta-category, and every draft was filed without the
fields the wizard edits while the log said it was created. It also answered
Invalid Target to the source-type tag put on an event report. A model that
answers "relevant" without naming a focus point the article matches does not
get a draft: the local model did so on an article about none of them. The
draft names its source event, which is what keeps that event from a second
alert, and the source event is tagged as one, as the dashboard's alerts tag it.

    python -m unittest tests.test_flash_intel_object
"""

import unittest
from unittest import mock

from pymisp import MISPEvent, PyMISP

from analyser.products import flash_intel


class Object(unittest.TestCase):
    reachable = "SOC, CTI"

    def add(self, reply):
        misp_webapp = mock.create_autospec(PyMISP, instance=True)
        misp_webapp.add_object.return_value = reply
        source = mock.MagicMock(uuid="s" * 36, info="An article", tags=[])
        with mock.patch.object(flash_intel.tagger, "get_source_feed", return_value="feed"), \
             mock.patch("webapp.misp_store.subscriber_audience", return_value=self.reachable) as self.audience:
            saved = flash_intel._add_flash_intel_object(
                misp_webapp, MISPEvent(), "FIA-00007", source, "## Summary\nOne line.", ["energy"])
        return saved, misp_webapp.add_object.call_args[0][1]

    def test_it_is_built_from_its_template(self):
        _saved, obj = self.add({"Object": {}})
        self.assertEqual(obj.to_dict()["meta-category"], "intelligence")
        relations = {a.object_relation for a in obj.attributes}
        self.assertLessEqual({"fia-id", "review-state", "summary", "source-event-uuid"}, relations)

    def test_its_audience_is_everyone_it_can_reach(self):
        """A draft without one cannot be published, and an analyser draft had none."""
        _saved, obj = self.add({"Object": {}})
        self.audience.assert_called_once_with("Flash intel alert", "amber")
        self.assertEqual({a.object_relation: a.value for a in obj.attributes}["audience"], "SOC, CTI")

    def test_it_is_a_draft_that_names_its_source(self):
        """A draft, as everything else the analyser makes is, and its source is
        what keeps the event from a second alert."""
        _saved, obj = self.add({"Object": {}})
        values = {a.object_relation: a.value for a in obj.attributes}
        self.assertEqual((values["review-state"], values["source-event-uuid"]), ("draft", "s" * 36))

    def test_a_refused_object_is_reported(self):
        with self.assertLogs(flash_intel.logger, "ERROR") as logs:
            saved, _obj = self.add({"errors": "No valid template found"})
        self.assertFalse(saved)
        self.assertIn("FIA-00007", logs.output[0])

    def test_a_saved_object_is_not(self):
        with self.assertNoLogs(flash_intel.logger, "ERROR"):
            saved, _obj = self.add({"Object": {}})
        self.assertTrue(saved)


class Process(unittest.TestCase):
    RELEVANT = {"relevant": True, "matched_focus_points": ["energy"], "source_type": "news-report"}

    def run_process(self, object_saved=True, relevance=RELEVANT, keep_open_for=""):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp_webapp = mock.create_autospec(PyMISP, instance=True)
        created = MISPEvent()
        created.id, created.uuid = 7, "p" * 36
        misp_webapp.add_event.return_value = created
        event = mock.MagicMock(uuid="e" * 36, info="An event", tags=[], date=None)
        report = mock.MagicMock()
        with mock.patch.object(flash_intel, "_get_http_error", return_value=None), \
             mock.patch.object(flash_intel, "_get_reports", return_value=("article", [report])), \
             mock.patch.object(flash_intel.llm, "check_relevance", return_value=relevance), \
             mock.patch.object(flash_intel.llm, "generate_flash_intel", return_value="## Summary\nx") as generate, \
             mock.patch.object(flash_intel, "_add_flash_intel_object", return_value=object_saved), \
             mock.patch.object(flash_intel, "_automated_subscribers", return_value=[]), \
             mock.patch.object(flash_intel, "tagger") as tagger:
            result = flash_intel.process(misp, misp_webapp, event, {}, keep_open_for=keep_open_for)
        self.generate, self.misp_webapp = generate, misp_webapp
        return result, tagger, event, report

    def test_the_source_type_goes_on_the_event_not_on_its_report(self):
        _result, tagger, event, report = self.run_process(True)
        self.assertIn(mock.call(mock.ANY, event, 'osint:source-type="news-report"'), tagger.add_tag.call_args_list)
        self.assertFalse(any(report in c.args for c in tagger.add_tag.call_args_list))

    def test_the_source_event_is_marked_as_the_source_of_an_alert(self):
        _result, tagger, event, _report = self.run_process(True)
        self.assertIn(mock.call(mock.ANY, event, 'zsazsa:product="flash-intel"'), tagger.add_tag.call_args_list)

    def test_an_event_kept_open_is_not_rejected_for_the_focus_points(self):
        """The daily briefing only reads the events nobody rejected."""
        result, tagger, event, _report = self.run_process(
            relevance={"relevant": False, "reason": "Off topic", "matched_focus_points": []},
            keep_open_for="the daily briefing")
        self.assertEqual((result["outcome"], result["detail"]),
                         ("not_relevant", "Off topic Kept open for the daily briefing."))
        tagger.set_workflow_state.assert_not_called()
        result, tagger, event, _report = self.run_process(
            relevance={"relevant": False, "reason": "Off topic", "matched_focus_points": []})
        tagger.set_workflow_state.assert_called_once_with(mock.ANY, event, "rejected")

    def test_its_event_has_the_draft_workflow_state(self):
        self.run_process(True)
        self.assertIn(mock.call("p" * 36, 'workflow:state="draft"', local=True), self.misp_webapp.tag.call_args_list)

    def test_a_draft_without_its_object_says_so(self):
        result, _tagger, _event, _report = self.run_process(False)
        self.assertEqual(result["outcome"], "product_created")
        self.assertIn("draft object not saved", result["detail"])

    def test_a_complete_draft_does_not(self):
        result, _tagger, _event, _report = self.run_process(True)
        self.assertEqual(result["detail"], "FIA-00007")

    def test_relevant_without_a_matched_focus_point_gets_no_draft(self):
        relevance = {"relevant": True, "matched_focus_points": [], "reason": "Cloud account takeover."}
        result, tagger, event, _report = self.run_process(relevance=relevance)
        self.assertEqual(result["outcome"], "not_relevant")
        self.assertIn("no focus point matched", result["detail"])
        self.assertIn("Cloud account takeover.", result["detail"])
        tagger.set_workflow_state.assert_called_once_with(mock.ANY, event, "rejected")
        self.generate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
