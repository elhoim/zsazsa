"""The follow-up flag on the collection page follows the tag on the event.

Flagging tags the event in MISP with a local tag and records it in the cache's
flagged_events table, which is what the page reads. A refresh brings the table
back in line with the tags it fetched: a rebuilt cache gets its flags back, and
a tag added or removed in MISP itself shows up. A flag set while the search was
running, one on an event another source still has tagged, and every flag after
a failed refresh are left alone. The searches ask for local tags, which MISP
leaves out for a key with sync permission otherwise.

MISP is an autospec of PyMISP; the cache is a temporary file.

    python -m unittest tests.test_collection_flags
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pymisp import MISPEvent, PyMISP

import config
from webapp import collection_cache

FOLLOW_UP = 'zsazsa:collection="follow-up"'
PARTNER = {"id": "partner", "kind": "misp", "label": "Partner", "url": "https://partner.example.org",
           "api_key": "k", "verify_tls": True, "tags": [], "tags_and": [], "tags_not": []}
UUID = "00000000-0000-4000-8000-000000000001"


def _event(*tags, uuid=UUID):
    event = MISPEvent()
    event.uuid = uuid
    event.id = 1
    event.info = "Event"
    event.date = "2026-10-20"
    for tag in tags:
        event.add_tag(tag)
    return event


class Flags(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp.name) / "cache.db")),
                        mock.patch.object(config, "TAG_COLLECTION_FOLLOWUP", FOLLOW_UP, create=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        collection_cache.init_db()

    def refresh(self, src=PARTNER, events=(), **search):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = list(events)
        misp.search.configure_mock(**search)
        with mock.patch.object(collection_cache, "PyMISP", return_value=misp):
            collection_cache.refresh_source(src)
        return misp

    def flag_earlier(self, uuid=UUID):
        with collection_cache._db() as conn:
            conn.execute("INSERT INTO flagged_events (uuid, flagged_at) VALUES (?, 0)", (uuid,))

    def test_a_rebuilt_cache_gets_the_flags_back_from_the_tags(self):
        self.refresh(events=[_event(FOLLOW_UP)])
        self.assertTrue(collection_cache.is_flagged(UUID))

    def test_a_tag_removed_in_misp_takes_the_flag_away(self):
        self.flag_earlier()
        self.refresh(events=[_event("tlp:clear")])
        self.assertFalse(collection_cache.is_flagged(UUID))

    def test_a_flag_set_while_the_search_ran_is_kept(self):
        def flag_meanwhile(**_):
            collection_cache.flag_event(UUID)
            return [_event()]
        self.refresh(side_effect=flag_meanwhile)
        self.assertTrue(collection_cache.is_flagged(UUID))

    def test_another_source_with_the_tag_keeps_the_flag(self):
        collection_cache.insert_event({"source_id": "other", "uuid": UUID, "tags": [FOLLOW_UP]})
        self.flag_earlier()
        self.refresh(events=[_event()])
        self.assertTrue(collection_cache.is_flagged(UUID))

    def test_an_event_the_refresh_did_not_return_keeps_its_flag(self):
        self.flag_earlier()
        self.refresh(events=[_event(uuid="00000000-0000-4000-8000-000000000002")])
        self.assertTrue(collection_cache.is_flagged(UUID))

    def test_a_failed_refresh_leaves_the_flags_alone(self):
        self.flag_earlier()
        with self.assertLogs("webapp.collection_cache", level="WARNING"):
            self.refresh(side_effect=ConnectionError("MISP is down"))
        self.assertTrue(collection_cache.is_flagged(UUID))

    def test_every_kind_of_source_asks_for_local_tags(self):
        manual = {"id": "manual-newsletter", "kind": "manual", "url": "https://misp.example.org",
                  "api_key": "k", "source_tag": 'zsazsa:source="newsletter"'}
        for src in ({"id": "scraper", "kind": "scraper"}, PARTNER, manual):
            misp = self.refresh(src)
            self.assertIs(misp.search.call_args.kwargs["excludeLocalTags"], False, src["id"])


if __name__ == "__main__":
    unittest.main()
