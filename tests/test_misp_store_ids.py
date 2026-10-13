"""Tests for sequential id allocation (C-2) and paged MISP searches.

create_pir/gir/rfi and friends scan MISP for the highest id in use and then
claim the next one from a counter in the local database. Here we pin the
allocation, reuse and paging semantics.

    python -m unittest tests.test_misp_store_ids
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from core import db
from webapp import misp_store


class FakeMisp:
    def __init__(self, infos):
        self._infos = infos

    def search(self, **kwargs):
        return [type("E", (), {"info": i, "uuid": f"event-{n}"})() for n, i in enumerate(self._infos)]


class PagedMisp:
    """A MISP that hands out one prepared page per `page` number."""

    def __init__(self, pages):
        self.pages = pages
        self.requested = []

    def search(self, **kwargs):
        self.requested.append(kwargs["page"])
        return self.pages[kwargs["page"] - 1]


class SequenceId(unittest.TestCase):
    def test_scan_returns_highest_number(self):
        misp = FakeMisp(["[zsazsa:pir] PIR-001", "[zsazsa:pir] PIR-007: q", "noise"])
        self.assertEqual(misp_store._scan_max_sequence(misp, "tag", "PIR"), 7)

    def test_scan_empty_store_is_zero(self):
        self.assertEqual(misp_store._scan_max_sequence(FakeMisp([]), "tag", "PIR"), 0)

    def test_scan_ignores_malformed_numbers(self):
        misp = FakeMisp(["[zsazsa:pir] PIR-abc", "[zsazsa:pir] PIR-003"])
        self.assertEqual(misp_store._scan_max_sequence(misp, "tag", "PIR"), 3)

    def test_allocate_next_when_blank(self):
        misp = FakeMisp(["[zsazsa:rfi] RFI-004"])
        self.assertEqual(misp_store._sequence_id(misp, "tag", "RFI", ""), "RFI-005")

    def test_first_id_on_empty_store(self):
        self.assertEqual(misp_store._sequence_id(FakeMisp([]), "tag", "GIR", ""), "GIR-001")

    def test_existing_id_is_reused_not_reallocated(self):
        # Recreate path: an explicit id must be kept as-is.
        misp = FakeMisp(["[zsazsa:pir] PIR-009"])
        self.assertEqual(misp_store._sequence_id(misp, "tag", "PIR", "PIR-002"), "PIR-002")

    def test_whitespace_only_id_is_treated_as_blank(self):
        misp = FakeMisp(["[zsazsa:pir] PIR-009"])
        self.assertEqual(misp_store._sequence_id(misp, "tag", "PIR", "   "), "PIR-010")


class ReservedId(unittest.TestCase):
    """Creates claim their id from a counter in the local database, so the
    number survives a deleted event and two workers cannot both take it."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        db.init_db()

    def test_a_claimed_id_is_never_handed_out_twice(self):
        # The second scan comes back lower: PIR-008's event was deleted again.
        first = misp_store._reserve_sequence_id(FakeMisp(["[zsazsa:pir] PIR-007"]), "tag", "PIR", "")
        second = misp_store._reserve_sequence_id(FakeMisp(["[zsazsa:pir] PIR-002"]), "tag", "PIR", "")
        self.assertEqual((first, second), ("PIR-008", "PIR-009"))

    def test_counters_do_not_share_numbers_across_products(self):
        self.assertEqual(misp_store._reserve_sequence_id(FakeMisp([]), "tag", "PIR", ""), "PIR-001")
        self.assertEqual(misp_store._reserve_sequence_id(FakeMisp([]), "tag", "GIR", ""), "GIR-001")

    def test_an_explicit_id_consumes_nothing(self):
        misp = FakeMisp(["[zsazsa:pir] PIR-004"])
        self.assertEqual(misp_store._reserve_sequence_id(misp, "tag", "PIR", "PIR-002"), "PIR-002")
        self.assertEqual(misp_store._reserve_sequence_id(misp, "tag", "PIR", ""), "PIR-005")


class UncheckedTitles(unittest.TestCase):
    """Anyone who can tag an event in MISP writes the titles the scan reads. A
    40-digit number in one failed every create of that type, since SQLite cannot
    store it, and a smaller long one moved the counter there for good."""

    LONG = ("[zsazsa:pir] PIR-" + "9" * 40, "[zsazsa:pir] PIR-1000000000000")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        db.init_db()

    def misp(self, *extra):
        return FakeMisp([f"[zsazsa:pir] PIR-{n:03d}" for n in range(1, 41)] + list(extra))

    def test_the_form_suggests_the_next_real_id(self):
        for title in self.LONG:
            with self.subTest(title=title[:30]), self.assertLogs(misp_store.logger, "WARNING"):
                self.assertEqual(misp_store._sequence_id(self.misp(title), "tag", "PIR", ""), "PIR-041")

    def test_a_create_takes_the_next_real_id_and_the_counter_stays(self):
        ids = []
        for title in self.LONG:
            with self.assertLogs(misp_store.logger, "WARNING"):
                ids.append(misp_store._reserve_sequence_id(self.misp(title), "tag", "PIR", ""))
        self.assertEqual(ids, ["PIR-041", "PIR-042"])

    def test_six_digits_still_count_and_seven_do_not(self):
        self.assertEqual(misp_store._scan_max_sequence(self.misp("PIR-999999"), "tag", "PIR"), 999999)
        with self.assertLogs(misp_store.logger, "WARNING"):
            self.assertEqual(misp_store._scan_max_sequence(self.misp("PIR-1000000"), "tag", "PIR"), 40)

    def test_only_plain_digits_are_read_as_a_number(self):
        """int() alone reads all of these as numbers. None is an id zsazsa wrote,
        and none is worth a warning: they are not long numbers, just not ids."""
        with self.assertNoLogs(misp_store.logger, "WARNING"):
            for number in ("1_000", "+50", "\u0663", "\u00b2"):
                with self.subTest(number=number):
                    self.assertEqual(misp_store._scan_max_sequence(
                        self.misp(f"PIR-{number}"), "tag", "PIR"), 40)


class SearchAll(unittest.TestCase):
    def test_every_page_is_fetched_until_a_short_one(self):
        misp = PagedMisp([["one", "two"], ["three"]])
        self.assertEqual(misp_store._search_all(misp, limit=2, tags=["tag"]), ["one", "two", "three"])
        self.assertEqual(misp.requested, [1, 2])

    def test_an_exactly_full_last_page_ends_on_the_empty_one(self):
        misp = PagedMisp([["one", "two"], []])
        self.assertEqual(misp_store._search_all(misp, limit=2, tags=["tag"]), ["one", "two"])
        self.assertEqual(misp.requested, [1, 2])

    def test_an_error_on_the_first_page_is_returned_for_the_caller_to_see(self):
        # Every caller tests `isinstance(events, dict)` to spot a failed search.
        error = {"errors": (403, "Authentication failed")}
        misp = PagedMisp([error])
        self.assertEqual(misp_store._search_all(misp, limit=2, tags=["tag"]), error)

    def test_an_error_part_way_through_keeps_what_was_already_read(self):
        misp = PagedMisp([["one", "two"], {"errors": (500, "boom")}])
        self.assertEqual(misp_store._search_all(misp, limit=2, tags=["tag"]), ["one", "two"])

    def test_a_server_that_ignores_paging_does_not_loop_forever(self):
        # Every page comes back full, so only the page cap ends the loop.
        misp = PagedMisp([["one", "two"]] * (misp_store._SEARCH_MAX_PAGES + 5))
        events = misp_store._search_all(misp, limit=2, tags=["tag"])
        self.assertEqual(misp.requested[-1], misp_store._SEARCH_MAX_PAGES)
        self.assertEqual(len(events), 2 * misp_store._SEARCH_MAX_PAGES)


class EventDistribution(unittest.TestCase):
    """The System config tab offers "Your organisation only" through "All
    communities"; anything else in a hand-edited config falls back to 0."""

    def test_the_configured_levels_are_used(self):
        for distribution in (0, 1, 2, 3):
            with mock.patch.object(config, "MISP_EVENT_DISTRIBUTION", distribution, create=True):
                self.assertEqual(misp_store._make_event("test").distribution, distribution)

    def test_a_level_outside_the_offered_ones_falls_back_to_organisation_only(self):
        # 4 needs a sharing group zsazsa never sets, 5 is attribute-only.
        for distribution in (4, 5, -1, 99):
            with mock.patch.object(config, "MISP_EVENT_DISTRIBUTION", distribution, create=True):
                self.assertEqual(misp_store._make_event("test").distribution, 0)


if __name__ == "__main__":
    unittest.main()
