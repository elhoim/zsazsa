"""Mailed newsletters and model answers are parsed in linear time (GHSA-v4mq-r4g8-g35w).

Anyone who can mail a monitored mailbox decides what the IMAP collector and the
ETDA parser read, and scraped text can steer what a model answers. A pattern
that backtracks over a long run of whitespace let one such mail hold the
collector for hours on every cron run, and the web app with it when the mail
was opened for review. Each timed check below took seconds to hours before
the fix. The parsing itself is pinned as it was, edge cases included, and so
are the CRLF line endings and non-breaking spaces of real mail, which a pattern
narrowed to [ \t] stops recognising.

    python -m unittest tests.test_untrusted_text_patterns
"""

import base64
import email
import time
import unittest
from unittest import mock

import run_imap_collector
from analyser import llm
from core import imap_collector
from webapp import newsletter_parsers

RUN = 50_000


class Linear(unittest.TestCase):
    """What tests/test_redos_untrusted_text.py does not already time."""

    def assertQuick(self, func, text):
        started = time.perf_counter()
        func(text)
        self.assertLess(time.perf_counter() - started, 1, repr(text)[:60])

    def test_the_bullet_rule_and_overview_patterns(self):
        # Many lines, each under the parser's length cap, as a mail can hold
        # without any of them being cut short.
        blank = " " * 19_000
        for text in ("".join(f"* {blank}*x\n" for _ in range(20)),
                     "Quick overview\n" + "".join(f"a{blank}b\n" for _ in range(20)),
                     "Quick overview\n" + "".join(f"a{blank}<x> 1 2 3\n" for _ in range(20)),
                     "Quick overview\n" + "<" * 19_000 + " 1 2 3"):
            with self.subTest(text=text[:30]):
                self.assertQuick(newsletter_parsers.parse_etda, text)

    def test_the_collector_gets_through_the_reported_mail(self):
        """The advisory's reproduction: one base64 line of a heading and a long
        run of spaces. The run never finished, so the mail was never marked
        processed and every cron run started on it again."""
        body = base64.b64encode(("# a" + " " * RUN + "b\n").encode()).decode()
        msg = email.message_from_string(
            "Subject: ETDA CTI\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n" + body)
        mailbox = {"name": "inbox", "sources": [
            {"name": "ETDA", "parser": "ETDA CTI Robot", "subjects": ["etda"], "mode": "manual"}]}
        with mock.patch.object(imap_collector, "fetch_unprocessed", return_value=[("conn", b"7", msg)]), \
             mock.patch.object(imap_collector, "mark_processed", return_value=True) as processed, \
             mock.patch.object(run_imap_collector.misp_store, "create_newsletter_event", return_value="uuid"), \
             mock.patch.object(run_imap_collector.misp_store, "mark_newsletter_pending"):
            self.assertQuick(run_imap_collector._poll_mailbox, mailbox)
        processed.assert_called_once_with("conn", b"7")


class SameParsing(unittest.TestCase):
    """What the rewritten patterns still match, including the cases they nearly didn't."""

    def kinds(self, *lines):
        return newsletter_parsers._etda_kinds(list(lines))

    def test_a_heading_loses_its_closing_hashes_only(self):
        self.assertEqual(self.kinds("## Section ##", "### C#")[0], ("section", "Section"))
        self.assertEqual(self.kinds("### C#")[0], ("title", "C"))
        self.assertEqual(self.kinds("### Issue  #12")[0], ("title", "Issue  #12"))

    def test_a_row_of_markers_is_not_a_bullet(self):
        self.assertEqual([kind for kind, _ in self.kinds("* * *", "+   - -")], ["text", "text"])
        self.assertEqual(self.kinds("*   Real title")[0], ("title", "Real title"))

    def test_priority_and_relevance_need_text(self):
        self.assertIsNone(newsletter_parsers._PRIORITY_RE.match("Priority: 1 -"))
        self.assertEqual(newsletter_parsers._PRIORITY_RE.match("priority:\t1\t-\tCritical").group(2), "Critical")
        self.assertEqual(newsletter_parsers._RELEVANCE_RE.match("Relevance:  Thai banks").group(1), "Thai banks")

    def test_an_overview_row_and_its_anchor(self):
        names = newsletter_parsers._etda_section_names
        self.assertEqual(names(["Quick overview", "Industrial Sector <x-msg://3/#ICS>\t1 2 3"]),
                         ["Industrial Sector"])
        # The anchor starts at the first '<' after any earlier '>', as before.
        self.assertEqual(names(["Quick overview", "a <b <c> 1 2 3"]), ["a"])
        self.assertEqual(names(["Quick overview", "a <b> c <d> 1 2 3"]), ["a <b> c"])
        self.assertEqual(names(["Quick overview", "Name\xa0 1 2 3"]), ["Name"])
        self.assertEqual(names(["Quick overview", "1 2 3"]), [])

    def test_the_forward_marker_is_one_line(self):
        strip = imap_collector._strip_forward_preamble
        self.assertEqual(strip("Hi\r\n  -------- Forwarded Message --------\r\nFrom: a\r\n\r\nBody"), "Body")
        self.assertEqual(strip("x\x0c-- Forwarded message --\nFrom: a\nBody"), "x\x0c-- Forwarded message --\nFrom: a\nBody")
        # A rule, a blank line and the words on their own read as one marker
        # only because the old pattern let \s* cross lines.
        text = "-\n\nForwarded message --\nFrom: a\nBody"
        self.assertEqual(strip(text), text)

    def test_a_forward_from_the_mailbox_loses_its_header_block(self):
        """IMAP hands over CRLF line endings, so the marker line ends in \r."""
        raw = ("Subject: Fwd: CTI\r\nContent-Type: text/plain\r\n\r\n"
               "---------- Forwarded message ---------\r\nFrom: ETDA <r@etda.or.th>\r\n"
               "Subject: CTI\r\n\r\n[FIRST] ETDA Cyber Threat Intelligence\r\n").encode()
        self.assertEqual(imap_collector.extract_body(email.message_from_bytes(raw)),
                         "[FIRST] ETDA Cyber Threat Intelligence")

    def test_non_breaking_spaces_from_converted_html(self):
        """markdownify turns &nbsp; into \xa0, which sits where a space would."""
        self.assertEqual(imap_collector._strip_forward_preamble(
            "----------\xa0Forwarded message\xa0---------\nFrom: x\n\nBody"), "Body")
        [article] = newsletter_parsers.parse_etda("###\xa0Title\nPriority:\xa01\xa0-\xa0Critical")["articles"]
        self.assertEqual((article["title"], article["priority_label"]), ("Title", "Critical"))

    def test_a_fenced_answer_is_unwrapped(self):
        self.assertEqual(llm._unfence('```json\n{"a": 1}\n```'), '{"a": 1}')
        self.assertEqual(llm._unfence('  ```\n[1]\n```\n'), "[1]")
        self.assertEqual(llm._unfence("``````"), "")
        self.assertEqual(llm._unfence("```jsonx```"), "x")

    def test_anything_else_is_left_alone(self):
        for text in ('{"a": 1}', "````", "```json {} ``", 'Here:\n```{}```', '```{}```\nThanks', "", None):
            with self.subTest(text=text):
                self.assertEqual(llm._unfence(text), text)


if __name__ == "__main__":
    unittest.main()
