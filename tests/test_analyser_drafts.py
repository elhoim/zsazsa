"""What the analyser's drafts start with, and a run one model call fails on.

An alert or advisory cannot be published without an audience, and the analyser
left it empty on every draft. An alert from a PIR or GIR now takes the roles of
the requirement's owner and of the stakeholders it is distributed to, and falls
back, as an alert from the focus points and an advisory do, to the roles of
everyone the product can reach: its subscribers cleared for its TLP.

One event the model or MISP fails on no longer ends the run: its summary is
left out, and a briefing relevance check that fails keeps the story, as an
answer that cannot be read already did.

MISP and the model are stubbed.

    python -m unittest tests.test_analyser_drafts
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from webapp import analyser_pipeline, misp_store


def _stakeholder(uuid, role, name="", products=(), tlp="amber"):
    return SimpleNamespace(uuid=uuid, role=role, name=name or uuid, email="", products=list(products),
                           tlp_clearance=tlp)


STAKEHOLDERS = [_stakeholder("owner", "Cyber Threat Intelligence"), _stakeholder("soc", "SOC"),
                _stakeholder("ir", "Incident Response"), _stakeholder("soc2", "SOC")]


class Audience(unittest.TestCase):
    def test_a_requirement_s_owner_and_distribution(self):
        pir = SimpleNamespace(owner_uuid="owner", distribution=["soc", "soc2"])
        self.assertEqual(misp_store.requirement_audience(pir, STAKEHOLDERS), "Cyber Threat Intelligence, SOC")

    def test_everyone_a_product_can_reach(self):
        subscribed = [_stakeholder("a", "SOC", products=["Flash intel alert"]),
                      _stakeholder("b", "Management", products=["Flash intel alert"], tlp="green"),
                      _stakeholder("c", "Incident Response", products=["Daily threat briefing"])]
        with mock.patch.object(misp_store, "list_stakeholders", return_value=subscribed):
            self.assertEqual(misp_store.subscriber_audience("Flash intel alert", "amber"), "SOC")


class AlertFromARequirement(unittest.TestCase):
    def alert(self, pir):
        event = SimpleNamespace(uuid="e" * 36, info="Phishing against Belgian banks", tags=[], galaxies=[])
        created = []
        with mock.patch.object(analyser_pipeline, "_common_candidate_events",
                               return_value=(None, [event], {}, {}, {})), \
             mock.patch.object(analyser_pipeline.misp_store, "flash_intel_source_uuids", return_value=set()), \
             mock.patch.object(analyser_pipeline, "requirement_matches",
                               return_value={event.uuid: [{"id": "PIR-0003", "uuid": "p", "type": "pir"}]}), \
             mock.patch.object(analyser_pipeline.req_matching, "get_requirements", return_value=([pir], [])), \
             mock.patch.object(analyser_pipeline.misp_store, "list_stakeholders", return_value=STAKEHOLDERS), \
             mock.patch.object(analyser_pipeline.misp_store, "subscriber_audience", return_value="SOC") as reachable, \
             mock.patch.object(analyser_pipeline.misp_store, "create_fia", side_effect=created.append), \
             mock.patch.object(analyser_pipeline, "_log"):
            analyser_pipeline.run_flash_intel_action()
        return created[0]["audience"], reachable

    def test_it_is_for_the_requirement_s_stakeholders(self):
        audience, _reachable = self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=["ir"]))
        self.assertEqual(audience, "Cyber Threat Intelligence, Incident Response")

    def test_without_their_roles_it_is_for_everyone_it_can_reach(self):
        audience, reachable = self.alert(SimpleNamespace(uuid="p", owner_uuid="", distribution=[]))
        self.assertEqual(audience, "SOC")
        reachable.assert_called_once_with("Flash intel alert", "amber")


class OneFailedCall(unittest.TestCase):
    def test_a_summary_that_fails_leaves_the_other_events_alone(self):
        """On Saturday a dropped connection ended an advisory run at summary 7 of 12."""
        events = [SimpleNamespace(uuid=c * 36, info=f"Event {c}", tags=[]) for c in "abc"]
        article = [SimpleNamespace(name="Article", content="An article")]

        def summarise(misp, event, reports, galaxy_lookup):
            if event.info == "Event b":
                raise ConnectionError("Connection error.")
            return f"Summary of {event.info}", True
        with mock.patch.object(analyser_pipeline, "_refresh_scraper_cache"), \
             mock.patch.object(analyser_pipeline, "_incomplete_scraper_events", return_value=(None, events)), \
             mock.patch.object(analyser_pipeline, "_event_reports", return_value=article), \
             mock.patch.object(analyser_pipeline, "_event_http_error", return_value=False), \
             mock.patch.object(analyser_pipeline, "_build_galaxy_lookup", return_value={}), \
             mock.patch.object(analyser_pipeline, "_ensure_ai_summary", side_effect=summarise), \
             self.assertLogs("webapp.analyser_pipeline", level="WARNING"):
            _misp, kept, summaries, stats, _reports = analyser_pipeline._common_candidate_events()
        self.assertEqual([e.info for e in kept], ["Event a", "Event b", "Event c"])
        self.assertEqual(summaries, {"a" * 36: "Summary of Event a", "b" * 36: "", "c" * 36: "Summary of Event c"})
        self.assertEqual((stats["summary_created"], stats["summary_failed"]), (2, 1))

    def test_a_relevance_check_that_fails_keeps_the_story(self):
        events = [SimpleNamespace(uuid=c * 36, info=f"Event {c}", tags=[], galaxies=[]) for c in "ab"]
        created = []
        with mock.patch.object(analyser_pipeline, "_common_candidate_events", return_value=(
                None, events, {}, {"event_decisions": []},
                {e.uuid: [SimpleNamespace(name="Article", content="An article")] for e in events})), \
             mock.patch.object(analyser_pipeline, "daily_briefing_title_exclusions", return_value=[]), \
             mock.patch.object(analyser_pipeline, "requirement_matches", return_value={}), \
             mock.patch.object(analyser_pipeline.llm, "review_briefing_relevance",
                               side_effect=[ConnectionError("Connection error."), {"include": True}]), \
             mock.patch.object(analyser_pipeline.llm, "draft_briefing_story", return_value=("A story", "")), \
             mock.patch.object(analyser_pipeline.llm, "detect_story_overlaps", return_value={"overlaps": []}), \
             mock.patch.object(analyser_pipeline.llm, "draft_briefing_summary", return_value="The day"), \
             mock.patch.object(analyser_pipeline, "galaxy_names_with_commas", return_value=frozenset()), \
             mock.patch.object(analyser_pipeline.tagger, "get_source_feed", return_value="feed"), \
             mock.patch.object(analyser_pipeline.misp_store, "extract_source_url", return_value=""), \
             mock.patch.object(analyser_pipeline.misp_store, "briefing_scope_summary", return_value=""), \
             mock.patch.object(analyser_pipeline.misp_store, "create_briefing",
                               side_effect=lambda data: created.append(data) or "u" * 36), \
             mock.patch.object(analyser_pipeline, "log_event"), \
             self.assertLogs("webapp.analyser_pipeline", level="WARNING"):
            analyser_pipeline.run_daily_briefing_action()
        self.assertEqual([s["title"] for s in created[0]["stories"]], ["Event a", "Event b"])


if __name__ == "__main__":
    unittest.main()
