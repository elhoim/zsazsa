"""A feed's public-URL token stays on this MISP, and can be replaced.

The token is the whole credential for a feed's public URL. It is stored on the
feed's MISP object, so it gets distribution 0 (your organisation only) whatever
distribution zsazsa gives its events: otherwise a MISP set to share wider syncs
every feed's token to the connected instances. A token that did get out is
replaced with New token, which only a publisher may do; the old link then answers
like an unknown one. GHSA-jw7f-22fc-mmvc.

    python -m unittest tests.test_feed_token_secret
"""

import unittest
from datetime import date
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from webapp import misp_store
from webapp.routes import indicator_feed

UUID = "u" * 36
TOKEN = "t" * 22


def _feed(token=TOKEN):
    return SimpleNamespace(uuid=UUID, id=UUID, feed_id="FEED-001", name="demo", description="about",
                           query={"types": ["ip-dst"]}, tlp="amber", audience="SOC", author="me",
                           linked_pir_uuid="p" * 36, creator="a@example.org", token=token,
                           public_url_enabled=True, cache_interval="daily", cache_anchor="2026-10-01T10:00",
                           feedback_by=date(2026, 11, 1), created_at=None)


def _token_attribute(obj):
    return next(a for a in obj.attributes if a.object_relation == "token")


def _values(obj):
    return {a.object_relation: a.value for a in obj.attributes}


class TokenDistribution(unittest.TestCase):
    def test_the_token_is_kept_to_this_organisation(self):
        obj = misp_store._indicator_feed_obj({"token": TOKEN})
        self.assertEqual(_token_attribute(obj).distribution, 0)

    def test_the_other_fields_follow_the_event(self):
        obj = misp_store._indicator_feed_obj({"token": TOKEN, "name": "demo"})
        name = next(a for a in obj.attributes if a.object_relation == "name")
        self.assertNotEqual(getattr(name, "distribution", None), 0)


class NewToken(unittest.TestCase):
    def test_only_the_token_changes(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()), \
             mock.patch.object(misp_store, "update_indicator_feed") as update:
            token = misp_store.new_indicator_feed_token(UUID)
        self.assertNotEqual(token, TOKEN)
        self.assertGreaterEqual(len(token), 22)
        written = misp_store._indicator_feed_obj(update.call_args.args[1])
        before = misp_store._indicator_feed_obj(vars(_feed()))
        self.assertEqual(_values(written), {**_values(before), "token": token})

    def test_the_old_link_stops_working(self):
        with mock.patch.object(misp_store, "list_indicator_feeds", return_value=[_feed("n" * 22)]):
            self.assertIsNone(misp_store.get_indicator_feed_by_token(TOKEN))

    def test_a_record_that_is_not_a_feed_is_refused(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=None), \
             mock.patch.object(misp_store, "update_indicator_feed") as update:
            with self.assertRaises(ValueError):
                misp_store.new_indicator_feed_token(UUID)
        update.assert_not_called()


class NewTokenRoute(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(indicator_feed.bp)
        self.client = app.test_client()
        for patcher in (mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()),
                        mock.patch.object(misp_store, "new_indicator_feed_token", return_value="n" * 22),
                        mock.patch.object(indicator_feed.audit, "record")):
            patcher.start()
            self.addCleanup(patcher.stop)

    def post(self, can_publish):
        with mock.patch("webapp.misp_session.current_user_can_publish", return_value=can_publish):
            return self.client.post(f"/products/indicator-feed/{UUID}/new-token")

    def test_a_publisher_gets_a_new_token(self):
        resp = self.post(can_publish=True)
        self.assertEqual(resp.status_code, 302)
        misp_store.new_indicator_feed_token.assert_called_once_with(UUID)
        indicator_feed.audit.record.assert_called_once()

    def test_anyone_else_is_refused(self):
        resp = self.post(can_publish=False)
        self.assertEqual(resp.status_code, 302)
        misp_store.new_indicator_feed_token.assert_not_called()
        indicator_feed.audit.record.assert_not_called()

    def test_an_unknown_feed_is_not_found(self):
        misp_store.get_indicator_feed.return_value = None
        self.assertEqual(self.post(can_publish=True).status_code, 404)
        misp_store.new_indicator_feed_token.assert_not_called()


if __name__ == "__main__":
    unittest.main()
