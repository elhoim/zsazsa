"""What a threat actor profile actually says when it reaches a stakeholder.

The notification body carried the title, the actors, the summary and the
attribution, and stopped there. The recommendations were never in it, so the one
part a reader is meant to act on only existed on the product page, and a
detection rule attached to the profile never reached the mail or Mattermost at
all. Both channels send this same markdown.

    python -m unittest tests.test_tap_notification
"""

import unittest
from datetime import date, datetime
from types import SimpleNamespace

from notifier import product_email
from webapp.routes import threat_actor_profile as tap_routes


def _tap(**over):
    base = dict(title="Actor X", tap_id="TAP-00001", tlp="amber",
                threat_actors=["Bear"], summary="What they do.",
                attribution_rationale="Why we think so.",
                rec_prevention="", rec_detection="", rec_response="")
    base.update(over)
    return SimpleNamespace(**base)


class Recommendations(unittest.TestCase):
    def body(self, **over):
        return tap_routes._markdown(_tap(**over))

    def test_all_three_recommendations_are_in_the_body(self):
        md = self.body(rec_prevention="Segment the network.",
                       rec_detection="Watch for ARP floods.",
                       rec_response="Isolate the host.")
        self.assertIn("## Recommendations", md)
        for text in ("Segment the network.", "Watch for ARP floods.", "Isolate the host."):
            self.assertIn(text, md)

    def test_a_rulezet_rule_reaches_the_stakeholder(self):
        """Rules are attached to the profile as "title - url" lines in the
        detection recommendation, so they travel with it or not at all."""
        rule = "arp_poison.detection - https://rulezet.org/rule/detail_rule/740025"
        self.assertIn(rule, self.body(rec_detection=rule))

    def test_only_the_recommendations_that_were_filled_in_are_listed(self):
        md = self.body(rec_detection="Watch for ARP floods.")
        self.assertIn("**Detection:**", md)
        self.assertNotIn("**Prevention:**", md)
        self.assertNotIn("**Response:**", md)

    def test_a_profile_without_recommendations_has_no_empty_section(self):
        self.assertNotIn("Recommendations", self.body())

    def test_the_rest_of_the_body_is_unchanged(self):
        md = self.body()
        for text in ("# Actor X", "TAP-00001", "TLP:AMBER", "**Threat actors:** Bear",
                     "## Summary", "What they do.", "## Attribution", "Why we think so."):
            self.assertIn(text, md)


def _full_tap(**over):
    base = dict(
        title="Actor X", tap_id="TAP-00001", tlp="amber", threat_actors=["Bear"],
        summary="What they do.", attribution_rationale="Why we think so.",
        rec_prevention="Segment the network.", rec_detection="", rec_response="",
        created_at=datetime(2026, 9, 1, 10, 0), author="analyst", audience="SOC\nand CERT",
        assessment_confidence="high", review_date=date(2026, 12, 1),
        actor_types=["State-sponsored"], synonyms="Fancy Bear", suspected_origin="RU",
        origin_confidence="moderate", motivation="Espionage", sponsorship="",
        capabilities="Custom malware.", mode_of_operation="Spearphishing.",
        infrastructure="Rented VPS.", geographic_scope=["Belgium"], sectors=["Military"],
        mitre_attack_techniques=["Phishing - T1566"], threat_types=["APT"],
        time_frame="Past 12 months", technology=["Windows"], vendor=["Microsoft"],
        external_references=["https://example.org/a"],
    )
    base.update(over)
    return SimpleNamespace(**base)


class MatchesThePdf(unittest.TestCase):
    """The mail carried a fraction of what the PDF does: no metadata grid, no
    actor details, no scope and no references. The body now follows the PDF's
    sections and order, so a stakeholder reading the mail misses nothing."""

    def body(self, pir=None, **over):
        return tap_routes._markdown(_full_tap(**over), pir)

    def test_the_metadata_rows_reach_the_email_meta_grid(self):
        pir = SimpleNamespace(pir_id="PIR-7", question="Who targets us?")
        title, meta, _ = product_email._split_markdown(self.body(pir))
        self.assertEqual(title, "Actor X")
        self.assertEqual(dict(meta), {
            "ID": "TAP-00001", "Date": "2026-09-01", "Author": "analyst",
            "Classification": "TLP:AMBER", "Assessment confidence": "High",
            "Review date": "2026-12-01", "Threat actors": "Bear",
            # A line break in a value would end the grid early.
            "Audience": "SOC and CERT", "Linked PIR": "PIR-7: Who targets us?",
        })

    def test_the_sections_follow_the_pdf_order(self):
        md = self.body()
        headings = [line[3:] for line in md.splitlines() if line.startswith("## ")]
        self.assertEqual(headings, ["Summary", "Threat actor details", "Attribution",
                                    "Scope", "Recommendations", "References"])

    def test_the_actor_details_scope_and_references_are_carried(self):
        md = self.body()
        for text in ("**Type:** State-sponsored", "**Synonyms:** Fancy Bear",
                     "**Suspected origin:** RU (Moderate confidence)",
                     "**Motivation:** Espionage", "Custom malware.", "Spearphishing.",
                     "Rented VPS.", "**Geographic scope:** Belgium", "**Sector:** Military",
                     "**Techniques:** Phishing - T1566", "**Threat types:** APT",
                     "**Time frame:** Past 12 months", "**Technology:** Windows",
                     "**Vendor:** Microsoft", "- https://example.org/a"):
            self.assertIn(text, md)

    def test_empty_fields_and_sections_are_left_out(self):
        md = self.body(actor_types=[], synonyms="", suspected_origin="", motivation="",
                       capabilities="", mode_of_operation="", infrastructure="",
                       geographic_scope=[], sectors=[], mitre_attack_techniques=[],
                       threat_types=[], time_frame="", technology=[], vendor=[],
                       external_references=[], author="", review_date=None)
        for text in ("Sponsorship", "Threat actor details", "## Scope", "References",
                     "**Author:**", "**Review date:**", "**Linked PIR:**"):
            self.assertNotIn(text, md)

    def test_no_body_text_lands_in_an_unheaded_box(self):
        """The old "as of" line stopped the metadata parse, which left the threat
        actors in a box with no heading above the summary."""
        _, _, body = product_email._split_markdown(self.body())
        self.assertTrue(all(heading for heading, _ in product_email._sections(body)))


if __name__ == "__main__":
    unittest.main()
