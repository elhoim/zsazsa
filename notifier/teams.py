"""Microsoft Teams channels, reached through a Workflows webhook.

Teams retired its Office 365 connector webhooks in May 2026. A channel is now
reached through the URL of a Workflows flow ("Send webhook alerts to a
channel"), which takes a message with an Adaptive Card attached and posts the
card as the Workflows bot.

Card text understands only a little Markdown: bold, italic, links and lists.
Headings, tables, code and quotes show as the raw characters, so the product
Markdown is turned into card elements here instead: a heading into larger bold
text, a table into a Table, code into a CodeBlock, a run of "**Key:** value"
lines into a FactSet.
"""

import json
import logging
import re

import requests

import config
from notifier.mattermost import webhook_host, without_secret
from webapp.utils import normalize_notification_channels

logger = logging.getLogger(__name__)

# Teams refuses a message over 28 KB. The rest is room for the envelope.
_CARD_BUDGET = 24_000

_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_RULE = re.compile(r"^\s*([-*_])(\s*\1){2,}\s*$")
_LIST_ITEM = re.compile(r"^\s*([-*+]|\d+[.)])\s+")
_FACT = re.compile(r"^\*\*([^*]+?)(?::\*\*|\*\*:)\s*(.*)$")
_TABLE_SEPARATOR = re.compile(r"^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$")

_HEADING_SIZES = {1: "Large", 2: "Medium"}

# The card text colours closest to the TLP colours.
_TLP_COLOURS = {"red": "Attention", "amber": "Warning", "amber+strict": "Warning", "green": "Good"}

# Lines a split block repeats in every piece: a table its header row and the
# separator under it, a code block its opening fence.
_HEADER_LINES = {"table": 2, "code": 1}


def _active_webhooks(channel_ids: list | None = None) -> list[dict]:
    """Return webhook URLs for enabled Teams channels, limited to channel_ids if given."""
    targets = []
    for ch in normalize_notification_channels(getattr(config, "NOTIFICATION_CHANNELS", [])):
        if ch.get("type") != "teams" or not ch.get("enabled"):
            continue
        if channel_ids is not None and ch.get("id") not in channel_ids:
            continue
        url = (ch.get("url") or "").strip()
        if url:
            targets.append({"url": url, "verify_tls": bool(ch.get("verify_tls", True))})
    return targets


def _size(obj) -> int:
    return len(json.dumps(obj, ensure_ascii=False).encode("utf-8"))


def _text(text: str, **extra) -> dict:
    return {"type": "TextBlock", "text": text, "wrap": True, **extra}


def _starts_block(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped.startswith(("```", "|", ">")) or _HEADING.match(stripped)
                or _RULE.match(stripped) or _LIST_ITEM.match(line))


def _blocks(markdown: str) -> list[tuple[str, list[str]]]:
    """Split Markdown into (kind, lines) blocks."""
    lines = (markdown or "").replace("\r\n", "\n").split("\n")
    blocks = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            i += 1
        elif stripped.startswith("```"):
            end = i + 1
            while end < len(lines) and not lines[end].strip().startswith("```"):
                end += 1
            blocks.append(("code", lines[i:end]))
            i = end + 1
        elif _HEADING.match(stripped):
            blocks.append(("heading", [stripped]))
            i += 1
        elif _RULE.match(stripped):
            blocks.append(("rule", []))
            i += 1
        elif (stripped.startswith("|") and i + 1 < len(lines)
              and _TABLE_SEPARATOR.match(lines[i + 1])):
            end = i + 2
            while end < len(lines) and lines[end].strip().startswith("|"):
                end += 1
            blocks.append(("table", lines[i:end]))
            i = end
        elif stripped.startswith(">"):
            end = i
            while end < len(lines) and lines[end].strip().startswith(">"):
                end += 1
            blocks.append(("quote", lines[i:end]))
            i = end
        elif _LIST_ITEM.match(line):
            end = i + 1
            while end < len(lines) and lines[end].strip() and (
                    _LIST_ITEM.match(lines[end]) or not _starts_block(lines[end])):
                end += 1
            blocks.append(("list", lines[i:end]))
            i = end
        else:
            end = i + 1
            while end < len(lines) and lines[end].strip() and not _starts_block(lines[end]):
                end += 1
            blocks.append(("paragraph", lines[i:end]))
            i = end
    return blocks


def _lines_as_text(lines: list[str], **extra) -> list[dict]:
    """One TextBlock per line, set close together, since a card joins the
    lines of a single TextBlock into one."""
    return [_text(ln, **extra) if n == 0 else _text(ln, spacing="None", **extra)
            for n, ln in enumerate(lines)]


def _cells(line: str) -> list[str]:
    """The cells of a table row. A pipe inside a cell is written as \\|."""
    return [cell.strip().replace("\\|", "|")
            for cell in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


def _table(lines: list[str]) -> dict:
    # The second line is the |---| row under the header.
    rows = [_cells(ln) for ln in lines[:1] + lines[2:]]
    width = max(len(row) for row in rows)
    return {
        "type": "Table",
        "gridStyle": "accent",
        "firstRowAsHeaders": True,
        "columns": [{"width": 1} for _ in range(width)],
        "rows": [{
            "type": "TableRow",
            "cells": [{"type": "TableCell", "items": [_text(cell)] if cell else []}
                      for cell in row + [""] * (width - len(row))],
        } for row in rows],
    }


def _code(lines: list[str]) -> dict:
    code = lines[1:]
    # CodeBlock is a Teams extension the mobile clients do not render. Its
    # highlighting knows none of the rule formats a product has (Sigma, YARA,
    # KQL), so the fence label is left out.
    return {
        "type": "CodeBlock",
        "codeSnippet": "\n".join(code),
        "language": "PlainText",
        "fallback": {"type": "Container",
                     "items": _lines_as_text([ln or " " for ln in code], fontType="Monospace")},
    }


def _render(kind: str, lines: list[str]) -> list[dict]:
    """Card elements for one Markdown block."""
    if kind == "heading":
        match = _HEADING.match(lines[0])
        size = _HEADING_SIZES.get(len(match.group(1)), "Default")
        return [_text(match.group(2), weight="Bolder", size=size)]
    if kind == "table":
        return [_table(lines)]
    if kind == "code":
        return [_code(lines)]
    if kind == "quote":
        quoted = [re.sub(r"^\s*>\s?", "", ln) for ln in lines]
        return [{"type": "Container", "style": "emphasis",
                 "items": _lines_as_text([ln for ln in quoted if ln.strip()] or [" "])}]
    if kind == "list":
        items = []
        for ln in lines:
            if _LIST_ITEM.match(ln) or not items:
                items.append(ln.strip())
            else:
                items[-1] += " " + ln.strip()
        return [_text("\r".join(items))]
    stripped = [ln.strip() for ln in lines]
    facts = [_FACT.match(ln) for ln in stripped]
    if len(facts) > 1 and all(facts):
        return [{"type": "FactSet", "facts": [{"title": m.group(1).strip(), "value": m.group(2).strip()}
                                              for m in facts]}]
    return _lines_as_text(stripped)


def _split(kind: str, lines: list[str], budget: int) -> list[list[dict]]:
    """Render a block as one or more units, each small enough for one card.

    An oversized block is halved by its lines until every half fits, keeping a
    table's header and a code block's fence in each half. A single line that
    is still too long is cut in two as plain text.
    """
    elements = _render(kind, lines)
    if _size(elements) <= budget:
        return [elements]
    keep = _HEADER_LINES.get(kind, 0)
    head, body = lines[:keep], lines[keep:]
    if len(body) > 1:
        half = len(body) // 2
        return _split(kind, head + body[:half], budget) + _split(kind, head + body[half:], budget)
    text = body[0] if body else lines[0]
    half = len(text) // 2
    return _split("paragraph", [text[:half]], budget) + _split("paragraph", [text[half:]], budget)


def markdown_to_units(markdown: str, budget: int = _CARD_BUDGET) -> list[list[dict]]:
    """Turn Markdown into a list of units: card elements that stay together."""
    units = []
    separator = False
    for kind, lines in _blocks(markdown):
        if kind == "rule":
            separator = True
            continue
        for unit in _split(kind, lines, budget):
            if separator and unit:
                unit[0]["separator"] = True
                separator = False
            units.append(unit)
    return units


def _message(body: list[dict], actions: list[dict]) -> dict:
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.5",
        "msteams": {"width": "Full"},
        "body": body,
    }
    if actions:
        card["actions"] = actions
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": card,
        }],
    }


def ping_message() -> dict:
    """The card the settings page sends to check a channel."""
    return _message([_text("zsazsa test notification", weight="Bolder"),
                     _text("The Teams channel is reachable.")], [])


def _post(targets: list[dict], payload: dict, label: str) -> bool:
    # Sent as UTF-8 rather than with requests' ASCII escapes, which take six
    # bytes of the size limit for every accented letter.
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json; charset=utf-8"}
    sent_any = False
    for target in targets:
        url = target.get("url")
        try:
            r = requests.post(url, data=data, headers=headers, timeout=10,
                              verify=bool(target.get("verify_tls", True)))
            r.raise_for_status()
            logger.info("Teams notification sent (%s) to %s", label, webhook_host(url))
            sent_any = True
        except requests.RequestException as e:
            logger.error("Teams notification failed (%s) to %s: %s",
                         label, webhook_host(url), without_secret(str(e), url))
    return sent_any


def _head(title: str, subtitle: str, tlp: str, facts) -> list[dict]:
    head = [_text(title, weight="Bolder", size="Large")]
    if tlp:
        head.append(_text(f"TLP:{tlp.upper()}", weight="Bolder", spacing="None",
                          color=_TLP_COLOURS.get(tlp.lower(), "Default")))
    if subtitle:
        head.append(_text(subtitle, weight="Bolder", spacing="Small"))
    if facts:
        head.append({"type": "FactSet", "facts": [
            {"title": name, "value": "" if value is None else str(value)} for name, value in facts]})
    return head


def send_card(title: str, markdown: str, label: str, channel_ids: list[str] | None = None, *,
              subtitle: str = "", tlp: str = "", facts=(), links=(), image_url: str = "") -> bool:
    """Post a titled card with the Markdown body to the given Teams channels.

    The TLP is shown under the title, from the product rather than its
    Markdown, which a model may have written without the classification line.
    `facts` are (name, value) pairs shown under the title, `links` (title, url)
    pairs shown as buttons. A body too long for one message goes out as
    several cards, each named "part n/N": Workflows runs every request as its
    own flow, so the parts can arrive in a different order.
    """
    targets = _active_webhooks(channel_ids)
    if not targets:
        return False
    actions = [{"type": "Action.OpenUrl", "title": name, "url": url} for name, url in links if url]
    # Measured with the longest title a part can have.
    head = _head(f"{title} (part 99/99)", subtitle, tlp, facts)
    # A head that leaves less than this (thousands of recipients) makes a card
    # Teams refuses, which the log reports, rather than one per character.
    budget = max(_CARD_BUDGET - _size(head) - _size(actions), _CARD_BUDGET // 2)

    units = markdown_to_units(markdown, budget)
    if image_url:
        units.append([{"type": "Image", "url": image_url, "altText": title, "size": "Stretch"}])

    bodies, current, used = [], [], 0
    for unit in units:
        size = _size(unit)
        if current and used + size > budget:
            bodies.append(current)
            current, used = [], 0
        current.extend(unit)
        used += size
    bodies.append(current)

    total = len(bodies)
    all_sent = True
    for idx, body in enumerate(bodies, start=1):
        part_title = title if total == 1 else f"{title} (part {idx}/{total})"
        part_label = label if total == 1 else f"{label} part {idx}/{total}"
        message = _message(_head(part_title, subtitle, tlp, facts) + body, actions)
        all_sent = _post(targets, message, part_label) and all_sent
    return all_sent


def _recipients(names) -> list[tuple[str, str]]:
    return [("Recipients", ", ".join(names))] if names else []


def send_pir_notification(pir, markdown: str, preview_url: str = "",
                          channel_ids: list[str] | None = None,
                          stakeholder_names: list[str] | None = None) -> bool:
    """Notify that a PIR has been shared with stakeholders."""
    facts = [("Status", pir.status), ("Priority", pir.priority)] + _recipients(stakeholder_names)
    return send_card(f"{pir.pir_id} shared", "", f"PIR {pir.pir_id}", channel_ids,
                     subtitle=pir.question[:120], facts=facts,
                     links=[("Open PIR preview", preview_url)])


def send_pir_intake_notification(pir, new_status: str, reason: str = None,
                                 channel_ids: list[str] | None = None) -> bool:
    """Notify that a PIR's intake status has changed."""
    facts = [("Reason", reason)] if reason else []
    return send_card(f"{pir.pir_id} intake: {new_status}", "", f"PIR intake {pir.pir_id}",
                     channel_ids, subtitle=pir.question[:120], facts=facts)


def send_gir_notification(gir, markdown: str, preview_url: str = "",
                          channel_ids: list[str] | None = None,
                          stakeholder_names: list[str] | None = None) -> bool:
    """Notify that a GIR has been shared with stakeholders."""
    facts = [("Status", gir.status), ("Review cycle", gir.review_cycle)] + _recipients(stakeholder_names)
    return send_card(f"{gir.gir_id} shared", "", f"GIR {gir.gir_id}", channel_ids,
                     subtitle=gir.topic[:120], facts=facts,
                     links=[("Open GIR preview", preview_url)])


def send_rfi_notification(rfi, markdown: str, preview_url: str = "",
                          channel_ids: list[str] | None = None,
                          stakeholder_names: list[str] | None = None) -> bool:
    """Notify that an RFI has been received."""
    facts = [
        ("Requester", getattr(rfi, "requester_name", "") or "Unknown requester"),
        ("Priority", rfi.priority),
        ("Status", rfi.status),
    ] + _recipients(stakeholder_names)
    return send_card(f"{rfi.rfi_id} received", "", f"RFI {rfi.rfi_id}", channel_ids,
                     subtitle=(getattr(rfi, "question", "") or "")[:120],
                     tlp=getattr(rfi, "deliverable_tlp", "") or "", facts=facts,
                     links=[("Open RFI preview", preview_url)])


def send_daily_briefing_notification(briefing, markdown: str,
                                     channel_ids: list[str] | None = None) -> bool:
    """Send the full daily briefing to the given Teams channels."""
    date = getattr(briefing, "date", "")
    return send_card(f"Daily briefing {date}", markdown, f"Daily briefing {date}", channel_ids,
                     subtitle=getattr(briefing, "title", "") or "", tlp=getattr(briefing, "tlp", ""))


def send_indicator_feed_notification(feed, markdown: str, channel_ids: list[str] | None = None) -> bool:
    """Post an indicator feed (summary and values) to the given Teams channels."""
    feed_id = getattr(feed, "feed_id", "")
    return send_card(f"{feed_id}: {getattr(feed, 'name', '') or 'Indicator feed'}", markdown,
                     f"Indicator feed {feed_id}", channel_ids, tlp=getattr(feed, "tlp", ""))


def send_vea_notification(vea, markdown: str, channel_ids: list[str] | None = None) -> bool:
    """Send a vulnerability advisory to the given Teams channels."""
    vea_id = getattr(vea, "vea_id", "")
    cve_id, title = getattr(vea, "cve_id", "") or "", getattr(vea, "title", "") or ""
    subtitle = f"{cve_id}: {title}" if cve_id and title else cve_id or title
    return send_card(f"{vea_id}: Vulnerability advisory", markdown, f"VEA {vea_id}", channel_ids,
                     subtitle=subtitle, tlp=getattr(vea, "tlp", ""))


def send_detection_eng_request_notification(der, markdown: str,
                                            channel_ids: list[str] | None = None) -> bool:
    """Send a detection engineering request to the given Teams channels."""
    der_id = getattr(der, "der_id", "")
    return send_card(f"{der_id}: Detection engineering request", markdown,
                     f"detection engineering request {der_id}", channel_ids,
                     subtitle=getattr(der, "title", "") or "", tlp=getattr(der, "tlp", ""))


def send_threat_landscape_report_notification(tlr, markdown: str,
                                              channel_ids: list[str] | None = None) -> bool:
    """Send a threat landscape report to the given Teams channels."""
    tlr_id = getattr(tlr, "tlr_id", "")
    return send_card(f"{tlr_id}: Threat landscape report", markdown,
                     f"threat landscape report {tlr_id}", channel_ids,
                     subtitle=getattr(tlr, "title", "") or "", tlp=getattr(tlr, "tlp", ""))


def send_threat_actor_profile_notification(tap, markdown: str,
                                           channel_ids: list[str] | None = None,
                                           diamond_url: str | None = None) -> bool:
    """Send a threat actor profile to the given Teams channels.

    The Diamond Model goes in as an image by URL. Teams fetches it from
    Microsoft's side, so the URL has to be reachable from the internet, not
    only from the analysts' network.
    """
    tap_id = getattr(tap, "tap_id", "")
    return send_card(f"{tap_id}: Threat actor profile", markdown, f"threat actor profile {tap_id}",
                     channel_ids, subtitle=getattr(tap, "title", "") or "",
                     tlp=getattr(tap, "tlp", ""), image_url=diamond_url or "")


def send_flash_intel_alert(fia, content: str, channel_ids: list[str] | None = None) -> bool:
    """Send the full Flash Intel Alert to the given Teams channels."""
    fia_id = getattr(fia, "fia_id", "") or "FIA"
    event_ref = getattr(fia, "uuid", "") or getattr(fia, "id", "")
    misp_url = f"{config.MISP_WEBAPP_URL}/events/view/{event_ref}"
    return send_card(f"{fia_id}: Flash Intel Alert", content, fia_id, channel_ids,
                     tlp=getattr(fia, "tlp", "") or "", links=[("Open in MISP", misp_url)])
