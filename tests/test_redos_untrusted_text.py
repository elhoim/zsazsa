"""Regex denial-of-service guards on attacker-supplied text.

Each pattern below once backtracked super-linearly on a long whitespace run, so
one crafted e-mail (or steered model output) could stall the IMAP collector or
freeze the web app. The rewritten patterns are linear; these tests give each a
pathological input and assert it returns well within a generous time budget. A
quadratic/cubic pattern would take minutes on the same input.

    python -m unittest tests.test_redos_untrusted_text
"""

import time
import unittest

from analyser.llm import _unfence
from core import imap_collector
from webapp import newsletter_parsers

# Large enough that the old patterns took minutes; the bound is loose so the
# test does not flake on a busy host.
N = 200_000
BUDGET_S = 2.0


class _Timed(unittest.TestCase):
    def assertFast(self, fn):
        start = time.perf_counter()
        fn()
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, BUDGET_S, f"took {elapsed:.2f}s")


class Patterns(_Timed):
    def test_priority_line_with_trailing_whitespace(self):
        line = "Priority: 1 - a" + " " * N + "b"
        self.assertFast(lambda: newsletter_parsers._PRIORITY_RE.match(line))

    def test_relevance_line_with_trailing_whitespace(self):
        line = "Relevance: a" + " " * N + "b"
        self.assertFast(lambda: newsletter_parsers._RELEVANCE_RE.match(line))

    def test_atx_heading_with_trailing_whitespace(self):
        line = "# a" + " " * N + "b"
        self.assertFast(lambda: newsletter_parsers._ATX_RE.match(line))

    def test_forward_marker_over_a_blank_line_run(self):
        text = "---------- Forwarded message ----------" + "\n" * N + "tail"
        self.assertFast(lambda: imap_collector._strip_forward_preamble(text))

    def test_unfence_on_unterminated_fence(self):
        text = "```" + " " * N
        self.assertFast(lambda: _unfence(text))


class EndToEnd(_Timed):
    def test_parse_etda_on_a_pathological_body(self):
        body = "# a" + " " * N + "b\n" + "Priority: 1 - x" + " " * N + "y\n"
        self.assertFast(lambda: newsletter_parsers.parse_etda(body))


class BehaviourPreserved(unittest.TestCase):
    def test_atx_closing_hashes_still_stripped(self):
        m = newsletter_parsers._ATX_RE.match("## Heading ##")
        self.assertEqual(newsletter_parsers._atx_text(m), "Heading")

    def test_priority_label_still_captured_and_stripped(self):
        m = newsletter_parsers._PRIORITY_RE.match("Priority: 2 - Something   ")
        self.assertEqual(m.group(1), "2")
        self.assertEqual(m.group(2).strip(), "Something")

    def test_bullet_still_matches_a_title(self):
        m = newsletter_parsers._BULLET_RE.match("* A title here")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1).strip(), "A title here")

    def test_bullet_still_rejects_a_horizontal_rule(self):
        self.assertIsNone(newsletter_parsers._BULLET_RE.match("* * *"))

    def test_unfence_strips_a_json_fence(self):
        self.assertEqual(_unfence('```json\n{"a": 1}\n```'), '{"a": 1}')

    def test_unfence_leaves_bare_text_alone(self):
        self.assertEqual(_unfence('{"a": 1}'), '{"a": 1}')


if __name__ == "__main__":
    unittest.main()
