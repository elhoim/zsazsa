"""Indicator-feed value de-duplication and the result count.

The plain-text export lists each value once; the CSV keeps a row per attribute
with its event/server context. count_indicators has to end up at the same total
as the table, which means applying the same local tag refinement.

    python -m unittest tests.test_indicator_feed_dedup_count
"""

import unittest
from unittest import mock

import requests

import config
from flask import Flask

from webapp import misp_store


class ValuesText(unittest.TestCase):
    def test_a_value_seen_on_several_attributes_is_listed_once(self):
        rows = [
            {"value": "1.2.3.4"},
            {"value": "evil.example"},
            {"value": "1.2.3.4"},
            {"value": "8.8.8.8"},
            {"value": "evil.example"},
        ]
        self.assertEqual(
            misp_store.indicator_export(rows, "txt"),
            "1.2.3.4\nevil.example\n8.8.8.8",
        )

    def test_no_rows_is_an_empty_export(self):
        self.assertEqual(misp_store.indicator_export([], "txt"), "")

    def test_the_csv_export_keeps_the_duplicates(self):
        rows = [
            {"value": "1.2.3.4", "server_label": "One"},
            {"value": "1.2.3.4", "server_label": "Two"},
        ]
        self.assertEqual(misp_store.indicator_export(rows, "csv").count("1.2.3.4"), 2)


class FakeClient:
    """A MISP server returning one page of attributes, recording the query."""

    def __init__(self, attrs):
        self._attrs = attrs
        self.kwargs = None

    def search(self, **kwargs):
        self.kwargs = kwargs
        return {"Attribute": self._attrs}


class FeedServers(unittest.TestCase):
    """Which MISP servers a feed can be built from, and in what order."""

    def _config(self, servers, store_url="https://store", store_key="k"):
        return [
            mock.patch.object(config, "MISP_SERVERS", servers, create=True),
            mock.patch.object(config, "MISP_WEBAPP_URL", store_url, create=True),
            mock.patch.object(config, "MISP_WEBAPP_KEY", store_key, create=True),
        ]

    def servers(self, servers, **store):
        for patcher in self._config(servers, **store):
            patcher.start()
            self.addCleanup(patcher.stop)
        return misp_store.indicator_feed_servers()

    def test_zsazsas_own_store_comes_first(self):
        listed = self.servers([{"id": "a", "url": "https://a", "api_key": "k"}])
        self.assertEqual([s["id"] for s in listed], [misp_store.WEBAPP_STORE_ID, "a"])
        self.assertTrue(listed[0]["store"])
        self.assertTrue(listed[0]["enabled"])
        self.assertFalse(listed[1]["store"])

    def test_a_server_without_an_api_key_is_listed_but_not_usable(self):
        """It used to vanish from the list, which reads as the setting not
        having worked rather than as a key being missing."""
        listed = self.servers([{"id": "a", "url": "https://a", "api_key": ""}])
        self.assertIn("a", [s["id"] for s in listed])
        self.assertFalse([s for s in listed if s["id"] == "a"][0]["usable"])

    def test_no_client_is_built_for_a_server_without_a_key(self):
        for patcher in self._config([{"id": "a", "url": "https://a", "api_key": ""}]):
            patcher.start()
            self.addCleanup(patcher.stop)
        with mock.patch.object(misp_store, "PyMISP", return_value=mock.Mock()):
            built = [sid for sid, _l, _u, _c in misp_store._indicator_feed_clients()]
        self.assertEqual(built, [misp_store.WEBAPP_STORE_ID])

    def test_each_server_gets_its_own_client_even_if_two_share_an_id(self):
        """Clients are kept for the length of a request so a page does not pay
        for the connection twice. Keyed on the id, two servers written with the
        same one would have shared a client and the second would have been
        queried at the first one's address."""
        built = []

        def fake_pymisp(url, key, verify, timeout=None):
            built.append(url)
            return mock.Mock()

        app = Flask(__name__)
        with app.app_context(), \
             mock.patch.object(misp_store, "PyMISP", side_effect=fake_pymisp), \
             mock.patch.object(misp_store, "_feed_server_configs", return_value=[
                 {"id": "dup", "url": "https://one", "api_key": "k1"},
                 {"id": "dup", "url": "https://two", "api_key": "k2"}]):
            clients = misp_store._indicator_feed_clients()
            again = misp_store._indicator_feed_clients()
        self.assertEqual(built, ["https://one", "https://two"])
        self.assertEqual(len({id(c[3]) for c in clients}), 2)
        # And the second call in the same request builds nothing new.
        self.assertEqual([a[3] is b[3] for a, b in zip(clients, again)], [True, True])

    def test_a_source_claiming_the_store_id_keeps_it(self):
        """Two entries answering to one id would tick and query together, and
        the configured server is the one somebody wrote."""
        listed = self.servers([{"id": misp_store.WEBAPP_STORE_ID, "label": "Mine",
                                "url": "https://m", "api_key": "k"}])
        self.assertEqual([(s["id"], s["label"]) for s in listed],
                         [(misp_store.WEBAPP_STORE_ID, "Mine")])

    def test_the_store_drops_out_when_it_has_no_keys(self):
        listed = self.servers([{"id": "a", "url": "https://a", "api_key": "k"}], store_key="")
        self.assertEqual([s["id"] for s in listed], ["a"])


class ValuesAcrossServers(unittest.TestCase):
    """The same indicator sitting on two servers is one indicator to a feed."""

    def _server(self, values):
        client = mock.Mock()
        client.search.return_value = {"Attribute": [
            {"id": f"{v}-{i}", "value": v, "type": "ip-dst", "timestamp": "1700000000"}
            for i, v in enumerate(values)]}
        return client

    def _both(self):
        return [("s1", "First", "https://a", self._server(["1.1.1.1", "2.2.2.2", "2.2.2.2"])),
                ("s2", "Second", "https://b", self._server(["2.2.2.2", "3.3.3.3"]))]

    def test_the_first_server_carrying_a_value_is_the_one_that_reports_it(self):
        with mock.patch.object(misp_store, "_indicator_feed_clients", return_value=self._both()):
            rows = misp_store.search_indicators({"limit": 100})
        self.assertEqual([(r["value"], r["server_label"]) for r in rows],
                         [("1.1.1.1", "First"), ("2.2.2.2", "First"),
                          ("2.2.2.2", "First"), ("3.3.3.3", "Second")])

    def test_two_attributes_on_one_server_are_still_two_rows(self):
        # Same value, separate attributes on separate events: the CSV keeps both,
        # and only the copy on the *other* server is the redundant one.
        with mock.patch.object(misp_store, "_indicator_feed_clients", return_value=self._both()):
            rows = misp_store.search_indicators({"limit": 100})
        self.assertEqual(sum(1 for r in rows if r["value"] == "2.2.2.2"), 2)

    def test_a_value_past_the_first_server_s_page_is_not_a_duplicate(self):
        """Precedence is over what a server reports, not over what it holds.

        With a limit of 2, the first server never reports its third value, so
        the second server reporting it is the only mention of it and has to be
        kept. Dropping it would lose an indicator to a server that never
        offered it.
        """
        def holding(*values):
            client = mock.Mock()
            client.search.return_value = {"Attribute": [
                {"id": f"{v}-{i}", "value": v, "type": "ip-dst", "timestamp": "1700000000"}
                for i, v in enumerate(values)]}
            return client

        first = holding("1.1.1.1", "2.2.2.2", "3.3.3.3")
        second = holding("3.3.3.3", "4.4.4.4")
        clients = [("s1", "First", "https://a", first), ("s2", "Second", "https://b", second)]
        with mock.patch.object(misp_store, "_indicator_feed_clients", return_value=clients):
            rows = misp_store.search_indicators({"limit": 2})
        self.assertEqual([(r["value"], r["server_label"]) for r in rows],
                         [("1.1.1.1", "First"), ("2.2.2.2", "First"),
                          ("3.3.3.3", "Second"), ("4.4.4.4", "Second")])

    def test_the_count_agrees_with_the_table(self):
        with mock.patch.object(misp_store, "_indicator_feed_clients", return_value=self._both()):
            rows = misp_store.search_indicators({"limit": 100})
        with mock.patch.object(misp_store, "_indicator_feed_clients", return_value=self._both()):
            total, _capped = misp_store.count_indicators({"limit": 100})
        self.assertEqual(total, len(rows))


class TagsAskedOfMisp(unittest.TestCase):
    """What the query hands MISP, which is what makes the limit mean anything.

    A flat list of tags is an OR to MISP, and it applies the limit to that. Two
    included tags then asked for a far larger set, cut it at the limit, and left
    the refinement below nothing to keep: a feed came back empty while thousands
    matched. The operators put the real filter in front of the limit.
    """

    # zsazsa's own records, which every query leaves out (GHSA-jw7f-22fc-mmvc).
    OWN = ['zsazsa:type=%', 'zsazsa:ctiproduct=%']

    def tags(self, **filters):
        return misp_store._indicator_search_kwargs(filters).get("tags")

    def test_included_tags_are_asked_for_as_an_and(self):
        self.assertEqual(self.tags(tags_include=["tlp:red", "actor:x"]),
                         {"AND": ["tlp:red", "actor:x"], "NOT": self.OWN})

    def test_excluded_tags_are_asked_for_as_a_not(self):
        # NOT over a list means carrying none of them, which is what the feed
        # means by an exclusion, rather than not carrying all of them.
        self.assertEqual(self.tags(tags_exclude=["tlp:red", "actor:x"]),
                         {"NOT": ["tlp:red", "actor:x"] + self.OWN})

    def test_the_two_travel_together(self):
        self.assertEqual(self.tags(tags_include=["tlp:red"], tags_exclude=["actor:x"]),
                         {"AND": ["tlp:red"], "NOT": ["actor:x"] + self.OWN})

    def test_a_query_without_tags_still_leaves_out_zsazsas_records(self):
        self.assertEqual(self.tags(), {"NOT": self.OWN})


class WarninglistRefill(unittest.TestCase):
    """MISP applies the limit and then drops the warninglisted values from what
    it fetched, so asking for the limit answers short. The page is refilled once
    rather than handing the analyst a page that is short for no visible reason.
    """

    class Server:
        """A MISP that keeps `rate` of whatever it was asked for."""

        def __init__(self, rate, matching=10000):
            self.rate, self.matching, self.limits = rate, matching, []

        def search(self, **kwargs):
            self.limits.append(kwargs["limit"])
            kept = int(min(kwargs["limit"], self.matching) * self.rate)
            return {"Attribute": [{"id": str(i), "value": f"v{i}", "timestamp": "1700000000"}
                                  for i in range(kept)]}

    def _rows(self, server, **filters):
        with mock.patch.object(misp_store, "_indicator_feed_clients",
                               return_value=[("s1", "S1", "https://misp", server)]):
            return misp_store.search_indicators(dict({"limit": 100}, **filters))

    def test_a_short_page_is_asked_for_again_and_filled(self):
        server = self.Server(rate=0.4)
        rows = self._rows(server, enforce_warninglist="yes")
        self.assertEqual(len(rows), 100)
        # 100 wanted, 40 of the first 100 survived, so ask for 100/0.4 with half
        # again on top, rounded up past the truncation.
        self.assertEqual(server.limits, [100, 376])

    def test_a_full_page_is_not_asked_for_twice(self):
        server = self.Server(rate=1.0)
        self.assertEqual(len(self._rows(server, enforce_warninglist="yes")), 100)
        self.assertEqual(server.limits, [100])

    def test_a_query_that_keeps_them_is_never_refilled(self):
        # Nothing is dropped, so a short answer means that is all there is.
        server = self.Server(rate=0.4)
        self.assertEqual(len(self._rows(server, enforce_warninglist="")), 40)
        self.assertEqual(server.limits, [100])

    def test_a_query_with_fewer_matches_than_the_limit_settles_after_one_retry(self):
        server = self.Server(rate=1.0, matching=30)
        self.assertEqual(len(self._rows(server, enforce_warninglist="yes")), 30)
        self.assertEqual(len(server.limits), 2)

    def test_a_refill_that_fails_keeps_the_page_it_already_had(self):
        """The rows from the first ask are good rows. Losing them because the
        second ask timed out would turn a short page into no page at all."""
        flaky = mock.Mock()
        flaky.search.side_effect = [
            {"Attribute": [{"id": str(i), "value": f"v{i}", "timestamp": "1700000000"}
                           for i in range(40)]},
            ConnectionError("down"),
        ]
        self.assertEqual(len(self._rows(flaky, enforce_warninglist="yes")), 40)
        self.assertEqual(flaky.search.call_count, 2)

    def test_the_refill_never_asks_for_more_than_the_cap(self):
        self.assertEqual(misp_store._refill_limit(100, 0), misp_store.MAX_SEARCH_LIMIT)


class CountIndicators(unittest.TestCase):
    def _servers(self, *clients):
        servers = [(f"s{i}", f"Server {i}", f"https://misp{i}", c)
                   for i, c in enumerate(clients, start=1)]
        patcher = mock.patch.object(misp_store, "_indicator_feed_clients", return_value=servers)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_every_attribute_counts_when_no_tag_filter_is_set(self):
        self._servers(FakeClient([{"id": "1", "value": "a"}, {"id": "2", "value": "b"}]))
        self.assertEqual(misp_store.count_indicators({}), (2, False))

    def test_the_totals_of_all_servers_are_added_up(self):
        self._servers(FakeClient([{"id": "1", "value": "a"}]),
                      FakeClient([{"id": "2", "value": "b"}, {"id": "3", "value": "c"}]))
        self.assertEqual(misp_store.count_indicators({}), (3, False))

    def test_an_included_tag_has_to_be_on_every_counted_attribute(self):
        # The query asks MISP to AND them; the count applies it again locally,
        # so a server that did not narrow the set cannot inflate the total.
        self._servers(FakeClient([
            {"id": "1", "value": "a", "Tag": [{"name": "tlp:red"}, {"name": "actor:x"}]},
            {"id": "2", "value": "b", "Tag": [{"name": "tlp:red"}]},
        ]))
        self.assertEqual(misp_store.count_indicators({"tags_include": ["tlp:red", "actor:x"]}), (1, False))

    def test_a_tag_on_the_event_counts_as_a_tag_on_the_attribute(self):
        self._servers(FakeClient([
            {"id": "1", "value": "a", "Event": {"Tag": [{"name": "tlp:red"}]}},
            {"id": "2", "value": "b", "Event": {"Tag": [{"name": "tlp:green"}]}},
        ]))
        self.assertEqual(misp_store.count_indicators({"tags_include": ["tlp:red"]}), (1, False))

    def test_an_excluded_tag_drops_the_attribute(self):
        self._servers(FakeClient([
            {"id": "1", "value": "a", "Tag": [{"name": "tlp:red"}]},
            {"id": "2", "value": "b", "Tag": [{"name": "tlp:green"}]},
        ]))
        self.assertEqual(misp_store.count_indicators({"tags_exclude": ["tlp:red"]}), (1, False))

    def test_the_event_context_is_only_fetched_when_tags_are_filtered(self):
        plain = FakeClient([{"id": "1", "value": "a"}])
        self._servers(plain)
        misp_store.count_indicators({})
        self.assertNotIn("include_context", plain.kwargs)

        tagged = FakeClient([{"id": "1", "value": "a", "Tag": [{"name": "tlp:red"}]}])
        self._servers(tagged)
        misp_store.count_indicators({"tags_include": ["tlp:red"]})
        self.assertTrue(tagged.kwargs["include_context"])

    def test_a_server_filling_the_cap_marks_the_total_as_incomplete(self):
        self._servers(FakeClient([{"id": str(i), "value": str(i)} for i in range(3)]),
                      FakeClient([{"id": "9", "value": "x"}]))
        self.assertEqual(misp_store.count_indicators({}, cap=3), (4, True))

    def test_the_cap_is_measured_before_the_tag_refinement(self):
        # Only one attribute survives the filter, but the fetch still hit the
        # cap, so the analyst has to be told the total may be higher.
        self._servers(FakeClient([
            {"id": "1", "value": "a", "Tag": [{"name": "tlp:red"}]},
            {"id": "2", "value": "b", "Tag": [{"name": "tlp:green"}]},
        ]))
        self.assertEqual(misp_store.count_indicators({"tags_include": ["tlp:red"]}, cap=2), (1, True))

    def test_a_server_that_cannot_be_reached_is_skipped(self):
        broken = mock.Mock()
        broken.search.side_effect = ConnectionError("down")
        self._servers(broken, FakeClient([{"id": "1", "value": "a"}]))
        self.assertEqual(misp_store.count_indicators({}), (1, False))

    def test_the_failure_says_which_server_and_what_happened(self):
        """The count button prints this, so "count failed" on its own sent the
        analyst to the log for something the page could have said."""
        timed_out = mock.Mock()
        timed_out.search.side_effect = requests.exceptions.ReadTimeout(
            "HTTPSConnectionPool(host='misp-intern'): Read timed out. (read timeout=30)")
        self._servers(timed_out)
        with self.assertRaises(RuntimeError) as caught:
            misp_store.count_indicators({})
        self.assertEqual(str(caught.exception),
                         f"Server 1 did not answer within {misp_store.HTTP_TIMEOUT}s")

    def test_a_server_that_refused_the_query_is_named_too(self):
        refused = mock.Mock()
        refused.search.side_effect = ValueError("nope")
        self._servers(refused)
        with self.assertRaises(RuntimeError) as caught:
            misp_store.count_indicators({})
        self.assertEqual(str(caught.exception), "Server 1 could not be queried (ValueError)")


if __name__ == "__main__":
    unittest.main()
