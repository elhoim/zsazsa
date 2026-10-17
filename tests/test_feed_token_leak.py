"""A feed query must not return zsazsa's own records as indicator values.

Each indicator feed's public-URL capability token is stored as a cleartext MISP
text attribute on a feed event on the webapp store. A broad feed query against
that store would otherwise return another feed's token as an indicator value to
whoever holds this feed's URL. zsazsa's own product/record events carry
zsazsa:type / zsazsa:ctiproduct tags; collected intelligence carries
zsazsa:source / zsazsa:collection and must still come through.

    python -m unittest tests.test_feed_token_leak
"""

import unittest

from webapp import misp_store

TOKEN = "tok-should-never-appear-as-a-value"


def _attr(type_, value, event_tag):
    return {
        "type": type_,
        "value": value,
        "timestamp": "1700000000",
        "Event": {"id": "1", "uuid": "e" * 36, "info": "x", "Tag": [{"name": event_tag}]},
    }


class OwnRecordPredicate(unittest.TestCase):
    def test_product_and_record_tags_are_own_records(self):
        self.assertTrue(misp_store._is_own_record(['zsazsa:ctiproduct="indicator-feed"']))
        self.assertTrue(misp_store._is_own_record(['zsazsa:type="stakeholder"']))

    def test_collected_and_other_tags_are_not_own_records(self):
        self.assertFalse(misp_store._is_own_record(['zsazsa:source="misp-scraper"']))
        self.assertFalse(misp_store._is_own_record(["tlp:clear"]))
        self.assertFalse(misp_store._is_own_record([]))


class RowFiltering(unittest.TestCase):
    def _rows(self, attrs):
        raw = {"Attribute": attrs}
        return misp_store._parse_attribute_rows(raw, 1, "store", "https://misp", {})

    def test_a_feed_token_is_dropped_but_a_real_indicator_is_kept(self):
        rows = self._rows([
            _attr("text", TOKEN, 'zsazsa:ctiproduct="indicator-feed"'),
            _attr("ip-dst", "1.2.3.4", "tlp:clear"),
        ])
        values = [r["value"] for r in rows]
        self.assertIn("1.2.3.4", values)
        self.assertNotIn(TOKEN, values)
        self.assertEqual(len(rows), 1)

    def test_collected_indicators_still_come_through(self):
        rows = self._rows([_attr("domain", "evil.example", 'zsazsa:source="misp-scraper"')])
        self.assertEqual([r["value"] for r in rows], ["evil.example"])


if __name__ == "__main__":
    unittest.main()
