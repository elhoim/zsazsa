"""What a threat actor profile does with the indicator feeds it links to, and
what publishing one keeps.

A profile stores feed UUIDs, not feeds, and embeds each feed's indicators into
the product that goes out to stakeholders. Both ends of that link can move
under it: a feed can match more indicators than it lists, a feed can be
deleted while a profile still points at it, and a feed can be classified above
the profile it is linked to.

    python -m unittest tests.test_threat_actor_profile_feeds
"""

import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from webapp import misp_store
from webapp.routes import threat_actor_profile as tap_routes


def _feed(**over):
    data = dict(uuid="f" * 36, feed_id="FEED-001", name="Actor infrastructure", tlp="clear",
                description="", query={"types": ["ip-dst"], "limit": 3})
    data.update(over)
    return SimpleNamespace(**data)


def _rows(n):
    return [{"value": f"10.0.0.{i}", "type": "ip-dst"} for i in range(n)]


class EmbeddedFeeds(unittest.TestCase):
    def setUp(self):
        self.tap = SimpleNamespace(tap_id="TAP-001", tlp="amber", indicator_feeds=["f" * 36])

    def _markdown(self, feed, rows):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=feed), \
             mock.patch.object(misp_store, "search_indicators", return_value=rows):
            return tap_routes._linked_feeds_markdown(self.tap)

    def test_the_feed_is_embedded_as_csv(self):
        md = self._markdown(_feed(), _rows(2))
        self.assertIn("## Indicator feed: Actor infrastructure", md)
        self.assertIn("10.0.0.0", md)
        self.assertIn("10.0.0.1", md)

    def test_a_feed_that_hit_its_limit_says_so(self):
        """Otherwise the stakeholder reads 3 indicators as the whole picture."""
        md = self._markdown(_feed(), _rows(3))
        self.assertIn("limit of 3 indicators was reached", md)

    def test_a_feed_below_its_limit_says_nothing(self):
        self.assertNotIn("was reached", self._markdown(_feed(), _rows(2)))

    def test_a_feed_with_no_stored_limit_uses_the_default(self):
        feed = _feed(query={"types": ["ip-dst"]})
        md = self._markdown(feed, _rows(misp_store.DEFAULT_INDICATOR_LIMIT))
        self.assertIn(f"limit of {misp_store.DEFAULT_INDICATOR_LIMIT} indicators", md)

    def test_the_notice_counts_what_was_listed_not_what_was_asked_for(self):
        """A feed can store a limit above the cap the search applies, and the
        notice has to name the number that is actually in the product."""
        feed = _feed(query={"types": ["ip-dst"], "limit": 50000})
        md = self._markdown(feed, _rows(10000))
        self.assertIn("limit of 10000 indicators", md)
        self.assertNotIn("50000", md)

    def test_a_corrupt_stored_limit_does_not_break_the_product(self):
        # The feed page degrades to an empty result for this; so must the embed.
        md = self._markdown(_feed(query={"types": ["ip-dst"], "limit": "abc"}), _rows(2))
        self.assertIn("## Indicator feed: Actor infrastructure", md)
        self.assertNotIn("was reached", md)

    def test_a_feed_with_no_matches_says_so_instead_of_an_empty_block(self):
        self.assertIn("(no indicators)", self._markdown(_feed(), []))

    def test_a_feed_that_could_not_be_read_says_so_rather_than_nothing(self):
        """The product goes to stakeholders. "(no indicators)" would tell them
        the feed is empty, which is not what happened."""
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()), \
             mock.patch.object(misp_store, "search_indicators", side_effect=RuntimeError("MISP down")):
            md = tap_routes._linked_feeds_markdown(self.tap)
        self.assertIn("## Indicator feed: Actor infrastructure", md)
        self.assertIn("could not be read from MISP", md)
        self.assertNotIn("(no indicators)", md)

    def test_a_feed_classified_above_the_profile_is_left_out(self):
        """Everyone the profile reaches is cleared for its TLP, and the feed's
        indicators went to them whatever the feed was classified."""
        md = self._markdown(_feed(tlp="red"), _rows(2))
        self.assertIn("FEED-001 is left out: it is TLP:RED, above this profile's TLP:AMBER", md)
        self.assertNotIn("10.0.0.0", md)
        self.assertNotIn("Actor infrastructure", md)

    def test_a_deleted_feed_is_skipped(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=None):
            self.assertEqual(tap_routes._linked_feeds_markdown(self.tap), "")

    def test_a_profile_without_feeds_embeds_nothing(self):
        empty = SimpleNamespace(tap_id="TAP-002", indicator_feeds=[])
        self.assertEqual(tap_routes._linked_feeds_markdown(empty), "")


class Publishing(unittest.TestCase):
    """Publishing rewrites the whole profile object. A field the rewrite forgets
    is gone, which is how PIR scope items were lost before 1.0.0."""

    def _publish(self, tap):
        with mock.patch.object(misp_store, "get_threat_actor_profile", return_value=tap), \
             mock.patch.object(misp_store, "update_threat_actor_profile") as update:
            misp_store.publish_threat_actor_profile("u" * 36)
        return update.call_args[0][1]

    def test_it_carries_every_field_the_object_can_hold(self):
        # The MISP object template is the independent list of what a profile
        # stores; nothing in it may be dropped by a publish.
        template = json.loads(
            (Path(__file__).parent.parent / "webapp" / "misp_objects" / "objects"
             / "zsazsa-threat-actor-profile" / "definition.json").read_text())
        tap = SimpleNamespace(**{f: f"v-{f}" for f in misp_store._TAP_FIELDS})
        written = {a.object_relation for a in misp_store._tap_obj(self._publish(tap)).attributes}
        self.assertEqual(set(template["attributes"]) - written, set())

    def test_the_dates_survive_as_dates(self):
        """These two arrive as date objects, and the rewrite used to convert
        them by hand. _oa stringifies them the same way, so publishing must not
        turn a review date into something _parse_date reads back as nothing."""
        from datetime import date
        tap = SimpleNamespace(**{f: f"v-{f}" for f in misp_store._TAP_FIELDS})
        tap.review_date = date(2026, 1, 15)
        tap.feedback_deadline = date(2026, 2, 1)
        obj = misp_store._tap_obj(self._publish(tap))
        stored = {a.object_relation: a.value for a in obj.attributes}
        self.assertEqual(misp_store._parse_date(stored["review-date"]), date(2026, 1, 15))
        self.assertEqual(misp_store._parse_date(stored["feedback-deadline"]), date(2026, 2, 1))

    def test_it_marks_the_profile_published_today(self):
        from datetime import date
        tap = SimpleNamespace(**{f: f"v-{f}" for f in misp_store._TAP_FIELDS})
        data = self._publish(tap)
        self.assertEqual(data["status"], "Published")
        self.assertEqual(data["published_at"], date.today().isoformat())

    def test_publishing_a_profile_that_is_gone_raises(self):
        with mock.patch.object(misp_store, "get_threat_actor_profile", return_value=None):
            with self.assertRaises(RuntimeError):
                misp_store.publish_threat_actor_profile("u" * 36)


class ProfilesUsingAFeed(unittest.TestCase):
    def test_it_finds_the_profiles_that_link_the_feed(self):
        profiles = [
            SimpleNamespace(tap_id="TAP-001", indicator_feeds=["a", "b"]),
            SimpleNamespace(tap_id="TAP-002", indicator_feeds=[]),
            SimpleNamespace(tap_id="TAP-003", indicator_feeds=["b"]),
        ]
        with mock.patch.object(misp_store, "list_threat_actor_profiles", return_value=profiles):
            self.assertEqual([t.tap_id for t in misp_store.profiles_using_indicator_feed("b")],
                             ["TAP-001", "TAP-003"])
            self.assertEqual(misp_store.profiles_using_indicator_feed("z"), [])


if __name__ == "__main__":
    unittest.main()
