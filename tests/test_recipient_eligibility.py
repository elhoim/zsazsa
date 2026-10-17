"""Who is eligible for a product, and why they are not.

This is the rule the whole notification feature turns on: the preview page shows
it before publishing, and delivery collects channels only from the stakeholders it
marks green. Getting it wrong either drops a recipient silently or sends a product
past a clearance it should have stopped at.

    python -m unittest tests.test_recipient_eligibility
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from webapp import misp_store

_PRODUCT = "Flash intel alert"


def _stakeholder(name, role="SOC", clearance="amber", products=(_PRODUCT,)):
    return SimpleNamespace(name=name, uuid=name.lower(), role=role,
                           tlp_clearance=clearance, products=list(products))


class Eligibility(unittest.TestCase):
    def preview(self, stakeholders, tlp="amber", audience="SOC"):
        with mock.patch.object(misp_store, "list_stakeholders", return_value=stakeholders):
            rows = misp_store.recipient_preview(_PRODUCT, tlp, audience)
        return {r["name"]: r["status"] for r in rows}

    def test_subscribed_cleared_and_in_the_audience(self):
        self.assertEqual(self.preview([_stakeholder("Acme")]), {"Acme": "green"})

    def test_not_subscribed_is_grey(self):
        self.assertEqual(self.preview([_stakeholder("Acme", products=[])]), {"Acme": "grey"})

    def test_clearance_below_the_product_blocks_delivery(self):
        self.assertEqual(self.preview([_stakeholder("Acme", clearance="green")]), {"Acme": "yellow"})

    def test_a_role_outside_the_audience_blocks_delivery(self):
        self.assertEqual(self.preview([_stakeholder("Acme", role="IT Security")]), {"Acme": "yellow"})

    def test_a_product_with_no_audience_reaches_nobody(self):
        """A product that names no audience has no one to send to, which the page
        has to show rather than quietly widening it to everybody."""
        self.assertEqual(self.preview([_stakeholder("Acme")], audience=""), {"Acme": "yellow"})

    def test_role_aliases_count_as_the_role_they_name(self):
        rows = self.preview([_stakeholder("Acme", role="cti")], audience="Cyber Threat Intelligence")
        self.assertEqual(rows, {"Acme": "green"})

    def test_the_reason_names_what_blocked_a_subscriber(self):
        with mock.patch.object(misp_store, "list_stakeholders",
                               return_value=[_stakeholder("Acme", clearance="clear")]):
            row = misp_store.recipient_preview(_PRODUCT, "red", "SOC")[0]
        self.assertIn("clear", row["reason"])
        self.assertIn("red", row["reason"])

    def test_green_recipients_sort_ahead_of_blocked_and_unsubscribed(self):
        with mock.patch.object(misp_store, "list_stakeholders", return_value=[
            _stakeholder("Unsubscribed", products=[]),
            _stakeholder("Blocked", clearance="clear"),
            _stakeholder("Receiving"),
        ]):
            rows = misp_store.recipient_preview(_PRODUCT, "amber", "SOC")
        self.assertEqual([r["name"] for r in rows], ["Receiving", "Blocked", "Unsubscribed"])

    def test_delivery_goes_to_the_green_rows_and_nobody_else(self):
        """The product pages deliver to eligible_recipients() and show
        recipient_preview(), so the two may not disagree."""
        people = [_stakeholder("Receiving"), _stakeholder("Alias", role="soc"),
                  _stakeholder("Blocked", clearance="green"), _stakeholder("Elsewhere", role="IT Security"),
                  _stakeholder("Unsubscribed", products=[])]
        for audience in ("SOC", "", "SOC, IT Security"):
            with self.subTest(audience=audience), \
                 mock.patch.object(misp_store, "list_stakeholders", return_value=people):
                green = [r["name"] for r in misp_store.recipient_preview(_PRODUCT, "amber", audience)
                         if r["status"] == "green"]
                delivered = [s.name for s in misp_store.eligible_recipients(_PRODUCT, "amber", audience)]
            self.assertEqual(sorted(delivered), sorted(green))


class BriefingRecipients(unittest.TestCase):
    """The daily briefing names no audience, so recipient_preview would block
    everybody and cannot pick its recipients. Subscription alone was standing in,
    which let an amber briefing reach a stakeholder cleared only for green."""

    def cleared(self, stakeholders, tlp):
        with mock.patch.object(misp_store, "list_stakeholders", return_value=stakeholders):
            picked = misp_store.stakeholders_cleared_for("Daily threat briefing", tlp)
        return [s.name for s in picked]

    def setUp(self):
        self.people = [
            _stakeholder("Comms", clearance="clear", products=["Daily threat briefing"]),
            _stakeholder("SOC", clearance="green", products=["Daily threat briefing"]),
            _stakeholder("CISO", clearance="amber", products=["Daily threat briefing"]),
            _stakeholder("Outsider", clearance="red", products=[]),
        ]

    def test_an_amber_briefing_stops_at_the_clearance_line(self):
        self.assertEqual(self.cleared(self.people, "amber"), ["CISO"])

    def test_a_clear_briefing_reaches_every_subscriber(self):
        self.assertEqual(self.cleared(self.people, "clear"), ["Comms", "SOC", "CISO"])

    def test_clearance_does_not_subscribe_anyone(self):
        self.assertNotIn("Outsider", self.cleared(self.people, "clear"))


class Clearance(unittest.TestCase):
    """TLP ranks run least to most restrictive, and clearance covers everything at
    or below it. Unset is amber on both sides; a value that names no level fails
    closed, red for a product and clear for a clearance."""

    def test_a_clearance_covers_its_own_level_and_below(self):
        self.assertTrue(misp_store._tlp_cleared("red", "amber"))
        self.assertTrue(misp_store._tlp_cleared("amber", "amber"))
        self.assertTrue(misp_store._tlp_cleared("amber", "clear"))
        self.assertFalse(misp_store._tlp_cleared("green", "amber"))
        self.assertFalse(misp_store._tlp_cleared("clear", "red"))

    def test_amber_strict_sits_between_amber_and_red(self):
        self.assertTrue(misp_store._tlp_cleared("amber+strict", "amber"))
        self.assertFalse(misp_store._tlp_cleared("amber+strict", "red"))

    def test_unset_levels_are_treated_as_amber(self):
        self.assertTrue(misp_store._tlp_cleared("", ""))
        self.assertTrue(misp_store._tlp_cleared(None, "amber"))
        self.assertTrue(misp_store._tlp_cleared("AMBER", "amber"))

    def test_spellings_from_misp_and_older_data_are_read(self):
        # Read as amber before, each of these reached amber-cleared stakeholders.
        for red in ("tlp:red", "TLP:RED", "red ", " Red"):
            with self.subTest(tlp=red):
                self.assertFalse(misp_store._tlp_cleared("amber", red))
                self.assertTrue(misp_store._tlp_cleared("red", red))
        for strict in ("amber-strict", "amber_strict", "tlp:amber+strict", "AMBER+STRICT"):
            with self.subTest(tlp=strict):
                self.assertFalse(misp_store._tlp_cleared("amber", strict))
                self.assertTrue(misp_store._tlp_cleared("amber+strict", strict))

    def test_white_is_clear(self):
        self.assertTrue(misp_store._tlp_cleared("white", "clear"))
        self.assertFalse(misp_store._tlp_cleared("white", "green"))
        self.assertTrue(misp_store._tlp_cleared("green", "tlp:white"))

    def test_a_product_level_that_names_nothing_reaches_only_red(self):
        self.assertFalse(misp_store._tlp_cleared("amber+strict", "secret"))
        self.assertTrue(misp_store._tlp_cleared("red", "secret"))

    def test_a_clearance_that_names_nothing_covers_only_clear(self):
        self.assertFalse(misp_store._tlp_cleared("nonsense", "red"))
        self.assertFalse(misp_store._tlp_cleared("nonsense", "green"))
        self.assertTrue(misp_store._tlp_cleared("nonsense", "clear"))


if __name__ == "__main__":
    unittest.main()
