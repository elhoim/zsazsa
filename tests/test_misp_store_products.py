"""What "Products by threat actor type" counts, on the statistics page and the
dashboard: published products only, each once per actor type.

The briefing, alert and profile lists are patched so it runs without MISP.

    python -m unittest tests.test_misp_store_products
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from webapp import misp_store


class ProductCountsByThreatActorType(unittest.TestCase):
    """Only what went out counts: a published briefing, an approved alert and a
    published profile. The stand-ins filter by state as the store's lists do."""

    def _run(self, briefings, fias, taps=()):
        with mock.patch.object(misp_store, "list_briefings", return_value=list(briefings)), \
             mock.patch.object(misp_store, "list_fias",
                               side_effect=lambda review_state=None: [
                                   f for f in fias if review_state in (None, f.review_state)]), \
             mock.patch.object(misp_store, "list_threat_actor_profiles",
                               side_effect=lambda status=None: [t for t in taps if status in (None, t.status)]):
            return misp_store.product_counts_by_threat_actor_type()

    def by_type(self, *args, **kwargs):
        return {r["actor_type"]: r for r in self._run(*args, **kwargs)}

    def test_counts_briefings_alerts_and_profiles_per_type(self):
        briefings = [_briefing(["State-sponsored"]), _briefing(["State-sponsored", "Hacktivist"])]
        rows = self.by_type(briefings, [_fia(["State-sponsored"])], [_tap(["Hacktivist"])])
        self.assertEqual(rows["State-sponsored"]["daily_briefings"], 2)
        self.assertEqual(rows["State-sponsored"]["flash_intel_alerts"], 1)
        self.assertEqual(rows["State-sponsored"]["total"], 3)
        self.assertEqual(rows["Hacktivist"]["daily_briefings"], 1)
        self.assertEqual(rows["Hacktivist"]["threat_actor_profiles"], 1)

    def test_a_product_is_counted_once_per_type_not_per_story(self):
        rows = self.by_type([_briefing(["State-sponsored"], ["State-sponsored"])], [])
        self.assertEqual(rows["State-sponsored"]["daily_briefings"], 1)

    def test_what_did_not_go_out_is_left_out(self):
        """The analyser leaves many rejected alerts behind, and they counted."""
        rows = self.by_type([_briefing(["Hacktivist"], state="draft")],
                            [_fia(["Hacktivist"], state="rejected"), _fia(["Hacktivist"], state="draft")],
                            [_tap(["Hacktivist"], status="Draft")])
        self.assertEqual(rows, {})

    def test_missing_type_falls_under_unspecified_sorted_last(self):
        rows = self._run([_briefing([])], [_fia([])])
        self.assertEqual(rows[-1]["actor_type"], "Unspecified")
        self.assertEqual(rows[-1]["total"], 2)


def _briefing(*story_types, state="published"):
    return SimpleNamespace(review_state=state,
                           stories=[SimpleNamespace(threat_actor_types=list(t)) for t in story_types])


def _fia(actor_types, state="approved"):
    return SimpleNamespace(actor_types=actor_types, review_state=state)


def _tap(actor_types, status="Published"):
    return SimpleNamespace(actor_types=actor_types, status=status)


if __name__ == "__main__":
    unittest.main()
