"""Tests for the Microsoft Teams notifier.

Pins how product Markdown becomes Adaptive Card elements (card text has no
headings, tables or code of its own), that a long product is split into
messages Teams accepts without losing any of it, that a Workflows URL's `sig`
never reaches the log, and that the dispatcher hands Teams channels to this
sender.

    python -m unittest tests.test_teams
"""

import json
import logging
import unittest
from io import StringIO
from types import SimpleNamespace
from unittest import mock

import requests

import config
from notifier import dispatcher, mattermost, teams

_WORKFLOW_URL = ("https://default0123.07.environment.api.powerplatform.com:443/powerautomate/"
                 "automations/direct/workflows/abc/triggers/manual/paths/invoke"
                 "?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=TOPSECRETSIGNATURE")


def _elements(markdown):
    return [el for unit in teams.markdown_to_units(markdown) for el in unit]


def _texts(card_json):
    """Every string in a card, so a test can ask whether some text survived."""
    found = []

    def walk(node):
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str):
            found.append(node)

    walk(card_json)
    return found


class MarkdownToCard(unittest.TestCase):
    def test_a_heading_becomes_bold_text_without_its_hashes(self):
        [el] = _elements("## Summary")
        self.assertEqual(el["type"], "TextBlock")
        self.assertEqual(el["text"], "Summary")
        self.assertEqual(el["weight"], "Bolder")

    def test_a_table_becomes_a_table_with_its_header_row(self):
        [table] = _elements("| Field | Details |\n|---|---|\n| **Product** | Exchange |\n| Fixed | 15.2 |")
        self.assertEqual(table["type"], "Table")
        self.assertTrue(table["firstRowAsHeaders"])
        self.assertEqual(len(table["columns"]), 2)
        cells = [[c["items"][0]["text"] for c in row["cells"]] for row in table["rows"]]
        self.assertEqual(cells, [["Field", "Details"], ["**Product**", "Exchange"], ["Fixed", "15.2"]])

    def test_an_escaped_pipe_stays_inside_its_cell(self):
        """misp_store writes a pipe in an indicator value as \\|."""
        [table] = _elements("| Value | Type |\n| --- | --- |\n| cmd.exe \\| more | text |")
        cells = [c["items"][0]["text"] for c in table["rows"][1]["cells"]]
        self.assertEqual(cells, ["cmd.exe | more", "text"])

    def test_a_row_of_dashes_is_data_not_a_separator(self):
        [table] = _elements("| Owner | SLA |\n|---|---|\n| - | - |")
        self.assertEqual(len(table["rows"]), 2)

    def test_a_short_table_row_is_padded_to_the_width_of_the_table(self):
        [table] = _elements("| a | b | c |\n|---|---|---|\n| only |")
        self.assertEqual([len(row["cells"]) for row in table["rows"]], [3, 3])

    def test_a_code_fence_becomes_a_code_block_with_a_fallback_for_mobile(self):
        [el] = _elements("```yara\nrule x {\n  condition: true\n}\n```")
        self.assertEqual(el["type"], "CodeBlock")
        self.assertEqual(el["language"], "PlainText")
        self.assertEqual(el["codeSnippet"], "rule x {\n  condition: true\n}")
        self.assertEqual(el["fallback"]["type"], "Container")

    def test_key_value_lines_become_a_fact_set(self):
        [facts] = _elements("**ID:** VEA-00001\n**Classification:** tlp:amber\n**Date**: 2026-10-20")
        self.assertEqual(facts["type"], "FactSet")
        self.assertEqual(facts["facts"], [
            {"title": "ID", "value": "VEA-00001"},
            {"title": "Classification", "value": "tlp:amber"},
            {"title": "Date", "value": "2026-10-20"},
        ])

    def test_a_single_key_value_line_stays_text(self):
        [el] = _elements("**Action required:** patch now")
        self.assertEqual(el["type"], "TextBlock")
        self.assertEqual(el["text"], "**Action required:** patch now")

    def test_each_line_of_a_paragraph_keeps_its_own_line(self):
        els = _elements("first line\nsecond line")
        self.assertEqual([el["text"] for el in els], ["first line", "second line"])
        self.assertEqual(els[1]["spacing"], "None")

    def test_a_list_is_joined_the_way_card_markdown_expects(self):
        [el] = _elements("- one\n- two\n  wrapped\n1. three")
        self.assertEqual(el["text"], "- one\r- two wrapped\r1. three")

    def test_a_rule_puts_a_separator_above_what_follows(self):
        els = _elements("before\n\n---\n\n## After")
        self.assertNotIn("separator", els[0])
        self.assertTrue(els[1]["separator"])

    def test_a_quote_loses_its_markers(self):
        [el] = _elements("> quoted\n> more")
        self.assertEqual(el["type"], "Container")
        self.assertEqual([item["text"] for item in el["items"]], ["quoted", "more"])

    def test_a_vea_shaped_document_renders(self):
        md = ("# Vulnerability advisory: CVE-2026-1\n\n**ID:** VEA-1\n**Date:** 2026-10-20\n\n---\n\n"
              "## Affected technology\n\n| Field | Details |\n|-------|---------|\n| **Product** | X |\n\n"
              "### Immediate\n\n- patch\n- isolate\n\n```\nalert tcp any any\n```\n")
        types = [el["type"] for el in _elements(md)]
        self.assertEqual(types, ["TextBlock", "FactSet", "TextBlock", "Table", "TextBlock", "TextBlock", "CodeBlock"])


class SendCard(unittest.TestCase):
    def setUp(self):
        self.sent = []
        patches = [
            mock.patch.object(teams, "_active_webhooks", return_value=[{"url": _WORKFLOW_URL}]),
            mock.patch.object(teams, "_post",
                              side_effect=lambda targets, payload, label: self.sent.append(payload) or True),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _sizes(self):
        return [len(json.dumps(m, ensure_ascii=False).encode("utf-8")) for m in self.sent]

    def test_a_short_product_is_one_card(self):
        self.assertTrue(teams.send_card("VEA-1: Vulnerability advisory", "# Hi\n\ntext", "VEA-1", ["t1"]))
        self.assertEqual(len(self.sent), 1)
        body = self.sent[0]["attachments"][0]["content"]["body"]
        self.assertEqual(body[0]["text"], "VEA-1: Vulnerability advisory")

    def test_a_long_product_is_split_under_the_teams_limit_and_loses_nothing(self):
        paragraphs = [f"paragraph {i} " + "é" * 400 for i in range(200)]
        teams.send_card("Daily briefing", "\n\n".join(paragraphs), "briefing", ["t1"])
        self.assertGreater(len(self.sent), 1)
        for size in self._sizes():
            self.assertLess(size, 28 * 1024)
        delivered = [t for m in self.sent for t in _texts(m)]
        for paragraph in paragraphs:
            self.assertIn(paragraph, delivered)
        titles = [m["attachments"][0]["content"]["body"][0]["text"] for m in self.sent]
        self.assertEqual(titles[0], f"Daily briefing (part 1/{len(self.sent)})")

    def test_a_table_too_long_for_one_card_repeats_its_header(self):
        rows = "\n".join(f"| 198.51.100.{i % 250} | indicator {i} " + "x" * 80 + " |" for i in range(600))
        teams.send_card("Feed", "| Value | Comment |\n|---|---|\n" + rows, "feed", ["t1"])
        self.assertGreater(len(self.sent), 1)
        for size in self._sizes():
            self.assertLess(size, 28 * 1024)
        tables = [el for m in self.sent for el in m["attachments"][0]["content"]["body"] if el["type"] == "Table"]
        for table in tables:
            self.assertEqual(table["rows"][0]["cells"][0]["items"][0]["text"], "Value")
        self.assertEqual(sum(len(t["rows"]) - 1 for t in tables), 600)

    def test_one_huge_line_is_cut_without_losing_characters(self):
        line = "z" * 70_000
        teams.send_card("Big", line, "big", ["t1"])
        for size in self._sizes():
            self.assertLess(size, 28 * 1024)
        body_text = "".join(t for m in self.sent for t in _texts(m) if set(t) == {"z"})
        self.assertEqual(body_text, line)

    def test_a_head_too_big_for_any_card_goes_out_once(self):
        names = [f"Stakeholder {i}" for i in range(3000)]
        teams.send_card("PIR-1 shared", "Some body text", "PIR-1", ["t1"], facts=[("Recipients", ", ".join(names))])
        self.assertEqual(len(self.sent), 1)

    def test_the_tlp_comes_from_the_product_and_is_coloured(self):
        fia = SimpleNamespace(fia_id="FIA-00003", uuid="u-1", tlp="amber")
        teams.send_flash_intel_alert(fia, "A model-written alert without a classification line.", ["t1"])
        card = self.sent[0]["attachments"][0]["content"]
        self.assertEqual(card["body"][1], {"type": "TextBlock", "text": "TLP:AMBER", "wrap": True,
                                           "weight": "Bolder", "spacing": "None", "color": "Warning"})
        self.assertTrue(card["actions"][0]["url"].endswith("/events/view/u-1"))

    def test_a_requirement_has_no_tlp_line(self):
        pir = SimpleNamespace(pir_id="PIR-001", question="Who?", status="Active", priority="High")
        teams.send_pir_notification(pir, "", channel_ids=["t1"])
        self.assertNotIn("TLP", " ".join(_texts(self.sent[0])))

    def test_links_become_buttons_on_the_card(self):
        teams.send_card("FIA-1", "body", "FIA-1", ["t1"], links=[("Open in MISP", "https://misp.test/e/1"),
                                                                  ("Missing", "")])
        actions = self.sent[0]["attachments"][0]["content"]["actions"]
        self.assertEqual(actions, [{"type": "Action.OpenUrl", "title": "Open in MISP", "url": "https://misp.test/e/1"}])


class Channels(unittest.TestCase):
    def setUp(self):
        self._orig = config.NOTIFICATION_CHANNELS
        config.NOTIFICATION_CHANNELS = [
            {"id": "mm1", "name": "MM", "type": "mattermost", "url": "https://mm.test/hooks/x", "enabled": True},
            {"id": "t1", "name": "SOC", "type": "teams", "url": _WORKFLOW_URL, "enabled": True},
            {"id": "t2", "name": "Paused", "type": "teams", "url": "https://paused.test/x", "enabled": False},
        ]

    def tearDown(self):
        config.NOTIFICATION_CHANNELS = self._orig

    def test_only_enabled_teams_channels_are_targets(self):
        self.assertEqual([t["url"] for t in teams._active_webhooks()], [_WORKFLOW_URL])
        self.assertEqual(teams._active_webhooks(["mm1", "t2"]), [])

    def test_nothing_to_send_to_is_not_a_success(self):
        self.assertFalse(teams.send_card("x", "y", "x", ["t2"]))

    def test_the_dispatcher_hands_teams_channels_to_the_teams_sender(self):
        vea = SimpleNamespace(vea_id="VEA-00001", cve_id="CVE-2026-1", title="Bug", tlp="amber")
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["mm1", "t1"])
        with mock.patch.object(dispatcher.teams, "send_vea_notification", return_value=True) as to_teams, \
             mock.patch.object(dispatcher.mattermost, "send_vea_notification", return_value=True):
            summary = dispatcher.send_vea(vea, "# VEA", [stakeholder])
        self.assertEqual(sorted(summary["sent_types"]), ["mattermost", "teams"])
        to_teams.assert_called_once_with(vea, "# VEA", channel_ids=["t1"])

    def test_a_flash_intel_alert_reaches_teams_as_the_alert_itself(self):
        fia = SimpleNamespace(fia_id="FIA-00003", uuid="u-1", tlp="red")
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["t1"])
        with mock.patch.object(dispatcher.teams, "send_flash_intel_alert", return_value=True) as to_teams:
            summary = dispatcher.send_flash_intel(fia, "# Alert", [stakeholder])
        self.assertEqual(summary["sent_types"], ["teams"])
        to_teams.assert_called_once_with(fia, "# Alert", channel_ids=["t1"])

    def test_a_pir_preview_reaches_teams_with_its_recipients(self):
        pir = SimpleNamespace(pir_id="PIR-001", question="Who targets us?", status="Active", priority="High")
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["t1"])
        with mock.patch.object(teams, "_post", return_value=True) as post:
            summary = dispatcher.send_pir_preview(pir, "https://zsazsa.test/pir/1", "# PIR", [stakeholder])
        self.assertEqual(summary["sent_types"], ["teams"])
        card = post.call_args[0][1]["attachments"][0]["content"]
        self.assertIn("Acme", _texts(card))
        self.assertEqual(card["actions"][0]["url"], "https://zsazsa.test/pir/1")


class WebhookSecrets(unittest.TestCase):
    """A Workflows URL is signed in its query string, not its path."""

    def setUp(self):
        self.buffer = StringIO()
        handler = logging.StreamHandler(self.buffer)
        logger = logging.getLogger("notifier.teams")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        self.addCleanup(logger.removeHandler, handler)

    def test_a_failing_webhook_does_not_log_its_signature(self):
        failure = requests.HTTPError(f"400 Client Error: Bad Request for url: {_WORKFLOW_URL}")
        with mock.patch.object(teams.requests, "post", side_effect=failure):
            self.assertFalse(teams._post([{"url": _WORKFLOW_URL}], teams.ping_message(), "VEA-1"))
        logged = self.buffer.getvalue()
        self.assertNotIn("TOPSECRETSIGNATURE", logged)
        self.assertIn("powerplatform.com", logged)

    def test_a_signature_quoted_differently_is_still_masked(self):
        message = "Max retries exceeded with url: /workflows/abc/invoke?api-version=1&sp=/triggers/manual/run&sig=TOPSECRETSIGNATURE"
        self.assertNotIn("TOPSECRETSIGNATURE", mattermost.without_secret(message, _WORKFLOW_URL))

    def test_the_card_goes_out_as_utf8(self):
        with mock.patch.object(teams.requests, "post") as post:
            post.return_value.raise_for_status.return_value = None
            teams._post([{"url": _WORKFLOW_URL}], {"text": "café"}, "x")
        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs["data"], '{"text": "café"}'.encode("utf-8"))
        self.assertEqual(kwargs["timeout"], 10)


if __name__ == "__main__":
    unittest.main()
