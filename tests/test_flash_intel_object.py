"""The flash intel draft the analyser files: its object, and the tag on its source.

MISP refused the zsazsa-flash-intel object because it was built without its
template, so it had no meta-category, and every draft was filed without the
fields the wizard edits while the log said it was created. It also answered
Invalid Target to the source-type tag put on an event report.

    python -m unittest tests.test_flash_intel_object
"""

import unittest
from unittest import mock

from pymisp import MISPEvent, PyMISP

from analyser.products import flash_intel


class Object(unittest.TestCase):
    def add(self, reply):
        misp_webapp = mock.create_autospec(PyMISP, instance=True)
        misp_webapp.add_object.return_value = reply
        source = mock.MagicMock(uuid="s" * 36, info="An article", tags=[])
        with mock.patch.object(flash_intel.tagger, "get_source_feed", return_value="feed"):
            saved = flash_intel._add_flash_intel_object(
                misp_webapp, MISPEvent(), "FIA-00007", source, "## Summary\nOne line.", ["energy"])
        return saved, misp_webapp.add_object.call_args[0][1]

    def test_it_is_built_from_its_template(self):
        _saved, obj = self.add({"Object": {}})
        self.assertEqual(obj.to_dict()["meta-category"], "intelligence")
        relations = {a.object_relation for a in obj.attributes}
        self.assertLessEqual({"fia-id", "review-state", "summary", "source-event-uuid"}, relations)

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
    def run_process(self, object_saved):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp_webapp = mock.create_autospec(PyMISP, instance=True)
        created = MISPEvent()
        created.id, created.uuid = 7, "p" * 36
        misp_webapp.add_event.return_value = created
        event = mock.MagicMock(uuid="e" * 36, info="An event", tags=[], date=None)
        report = mock.MagicMock()
        with mock.patch.object(flash_intel, "_get_http_error", return_value=None), \
             mock.patch.object(flash_intel, "_get_reports", return_value=("article", [report])), \
             mock.patch.object(flash_intel.llm, "check_relevance",
                               return_value={"relevant": True, "matched_focus_points": [], "source_type": "news-report"}), \
             mock.patch.object(flash_intel.llm, "generate_flash_intel", return_value="## Summary\nx"), \
             mock.patch.object(flash_intel, "_add_flash_intel_object", return_value=object_saved), \
             mock.patch.object(flash_intel, "_automated_subscribers", return_value=[]), \
             mock.patch.object(flash_intel, "tagger") as tagger:
            result = flash_intel.process(misp, misp_webapp, event, {})
        return result, tagger, event, report

    def test_the_source_type_goes_on_the_event_not_on_its_report(self):
        _result, tagger, event, report = self.run_process(True)
        tagger.add_tag.assert_called_once_with(mock.ANY, event, 'osint:source-type="news-report"')
        self.assertNotIn(report, tagger.add_tag.call_args[0])

    def test_a_draft_without_its_object_says_so(self):
        result, _tagger, _event, _report = self.run_process(False)
        self.assertEqual(result["outcome"], "product_created")
        self.assertIn("draft object not saved", result["detail"])

    def test_a_complete_draft_does_not(self):
        result, _tagger, _event, _report = self.run_process(True)
        self.assertEqual(result["detail"], "FIA-00007")


if __name__ == "__main__":
    unittest.main()
