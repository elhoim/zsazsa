"""Parsers for security newsletters, whether pasted into the importer or
collected from a mailbox.

Each parser turns a newsletter into a list of article dicts so the importer can
show them for selection. The same edition reaches a parser in several shapes: the
mailing list's own plain text, a copy pasted out of a mail client, a forward
(traditional or Apple Mail style), and the Markdown the collector produces when a
message carries no plain-text part at all. They differ only in decoration, so the
ETDA parser classifies every line before matching anything. Parsing is pure text
work; nothing here touches MISP or the network. New newsletters are added by
writing a parser and registering it in PARSERS.
"""

import re

# Untrusted newsletter text (pasted into the importer or mailed to a monitored
# box) is bounded before any line-by-line regex work. The patterns below are
# linear, so this only caps the pathological case; a real edition is far
# smaller than either limit.
_MAX_TEXT_LEN = 2_000_000
_MAX_LINE_LEN = 20_000


def _bounded(text: str) -> str:
    """Cap total and per-line length of untrusted newsletter text."""
    if len(text) > _MAX_TEXT_LEN:
        text = text[:_MAX_TEXT_LEN]
    if any(len(line) > _MAX_LINE_LEN for line in text.split("\n")):
        text = "\n".join(line[:_MAX_LINE_LEN] for line in text.split("\n"))
    return text


# These run per line on untrusted text, so none may backtrack over a long run of
# whitespace: a group that has to start or end on a non-space character, rather
# than a lazy group followed by \s*$, keeps every match linear. They keep \s
# rather than [ \t] between the parts, since an edition converted from HTML has
# non-breaking spaces there. The caller strips the groups.
_PRIORITY_RE = re.compile(r'^Priority:\s*(\d)\s*-\s*(\S.*)', re.IGNORECASE)
_RELEVANCE_RE = re.compile(r'^Relevance:\s*(\S.*)', re.IGNORECASE)
_URL_RE = re.compile(r'https?://\S+')
# A "Quick overview" row: a section name followed by three counts.
_OVERVIEW_ROW_RE = re.compile(r'^(.*?[^ \t])[ \t]+\d+[ \t]+\d+[ \t]+\d+\s*$')
_TLP_RE = re.compile(r'TLP:\s*(CLEAR|WHITE|GREEN|AMBER\+STRICT|AMBER|RED)', re.IGNORECASE)

_PRIORITY_KEYS = {1: "critical", 2: "urgent", 3: "important"}

_QUOTE_RE = re.compile(r'^> ?')
# Forwarded-message header lines, so the real newsletter title is not mistaken
# for the forward's Subject line.
_FWD_HEADER_RE = re.compile(
    r'^(From|Date|Subject|To|Sent|Cc|Reply-To|Delivered-To|Return-Path'
    r'|Begin forwarded message)\b', re.IGNORECASE)

# Markdown decoration, as it arrives when a message carried no plain-text part and
# the collector converted its HTML instead: headings, bullets, table rows, emphasis
# around a field label, and backslash-escaped punctuation.
_ATX_RE = re.compile(r'^(#{1,6})\s+(.*)$')
_RULE_RE = re.compile(r'^(=+|-+)$')
_BULLET_RE = re.compile(r'^[*+-]\s+([^\s*+-].*)$')
_TABLE_ROW_RE = re.compile(r'^\|.*\|$')
_EMPHASIS_RE = re.compile(r'^([*_]{1,2})(.+?)\1$')
_MD_ESCAPE_RE = re.compile(r'\\([\\`*_{}\[\]()#+.!-])')
# Back-to-top arrow: bare in the list mail, a link in converted HTML.
_ARROW_RE = re.compile(r'^(↑|\[↑\].*)$')


def _atx_text(match: re.Match) -> str:
    """The heading text of an ATX match, with any closing '#' run removed.

    The pattern captures the rest of the line greedily (linear); the optional
    closing hashes of '## Heading ##' are stripped here instead of in a regex
    group that would backtrack on trailing whitespace.
    """
    return match.group(2).rstrip().rstrip('#').rstrip()


def _parsed_tlp(match: re.Match | None) -> str:
    """The TLP of a newsletter header, with the retired WHITE read as CLEAR."""
    if not match:
        return ""
    tlp = match.group(1).lower()
    return "clear" if tlp == "white" else tlp


def _dequote(text: str) -> str:
    """Strip one level of '> ' e-mail quoting when the text is a quoted forward.

    Apple Mail and similar clients quote a forwarded newsletter by prefixing
    every line with '> ', which breaks the line-anchored parsing below. Only
    strip when most non-blank lines are quoted, so a pasted (unquoted)
    newsletter is left untouched.
    """
    lines = text.split("\n")
    nonblank = [ln for ln in lines if ln.strip()]
    if not nonblank:
        return text
    quoted = sum(1 for ln in nonblank if ln.startswith(">"))
    if quoted < len(nonblank) * 0.6:
        return text
    return "\n".join(_QUOTE_RE.sub("", ln) for ln in lines)


def _clean_url(token: str) -> str:
    return token.strip().strip("<>").rstrip(">.,);")


def _strip_quotes(text: str) -> str:
    return text.strip().strip('"').strip('“”').strip()


def _strip_emphasis(line: str) -> str:
    """The line without its Markdown emphasis, e.g. '*Priority: 1 - Critical*'."""
    stripped = line.strip()
    match = _EMPHASIS_RE.match(stripped)
    return match.group(2).strip() if match else stripped


def _clean_title(text: str) -> str:
    """Undo Markdown escaping and collapse the whitespace a converter leaves behind."""
    return " ".join(_MD_ESCAPE_RE.sub(r"\1", text).split())


def _without_anchor(name: str) -> str:
    """A "Quick overview" section name without its trailing in-mail anchor
    link, e.g. "Industrial Sector <x-msg://3/#ICS>". The anchor starts at the
    first '<' after any earlier '>'."""
    name = name.rstrip()
    if name.endswith(">"):
        start = name.find("<", name.rfind(">", 0, -1) + 1, len(name) - 1)
        if start != -1:
            name = name[:start]
    return name.strip()


def _etda_section_names(lines: list[str]) -> list[str]:
    """Section names in order, read from the 'Quick overview' table."""
    names = []
    in_overview = False
    for line in lines:
        if line.strip().lower().startswith("quick overview"):
            in_overview = True
            continue
        if in_overview:
            match = _OVERVIEW_ROW_RE.match(line.strip())
            if match:
                names.append(_without_anchor(match.group(1)))
            elif names:
                break
    return names


def _opens_section(lines: list[str], idx: int) -> bool:
    """Whether the line at idx is a section heading in the mailing list's layout.

    Nothing marks it up there: it sits alone between blank lines with the first
    '* ' title of its section below it. A URL or a Priority line can sit in the
    same place, so they are ruled out.
    """
    line = lines[idx].strip()
    prev = lines[idx - 1].strip() if idx else ""
    nxt = lines[idx + 1].strip() if idx + 1 < len(lines) else ""
    after = lines[idx + 2].strip() if idx + 2 < len(lines) else ""
    if prev or nxt or not _BULLET_RE.match(after):
        return False
    return not (_URL_RE.search(line) or _PRIORITY_RE.match(line)
                or _RELEVANCE_RE.match(line))


def _etda_kinds(lines: list[str]) -> list[tuple[str, str]]:
    """Classify every line as section, title, arrow, skip or text.

    A title and a section are marked up differently in each shape an edition
    arrives in: '* Title' under a bare section line in the list mail, '### Title'
    under a setext heading in converted HTML, and neither in a pasted copy, where
    the 'Quick overview' table names the sections instead.
    """
    kinds = []
    for idx, raw in enumerate(lines):
        line = _strip_emphasis(raw)
        nxt = lines[idx + 1].strip() if idx + 1 < len(lines) else ""
        atx = _ATX_RE.match(line)
        bullet = _BULLET_RE.match(line)
        if not line or _RULE_RE.match(line) or _TABLE_ROW_RE.match(line):
            kinds.append(("skip", ""))
        elif _ARROW_RE.match(line):
            kinds.append(("arrow", ""))
        elif _RULE_RE.match(nxt) and len(nxt) == len(line):
            # A converter underlines a heading to the width of its text. The rule
            # under the report title in the list mail is wider than the title.
            kinds.append(("title" if nxt[0] == "=" else "section", line))
        elif atx:
            kinds.append(("section" if len(atx.group(1)) <= 2 else "title", _atx_text(atx)))
        elif bullet:
            kinds.append(("title", bullet.group(1).strip()))
        elif _opens_section(lines, idx):
            kinds.append(("section", line))
        else:
            kinds.append(("text", line))
    return kinds


def _etda_report_title(kinds: list[tuple[str, str]]) -> str:
    """The edition's own title line, ignoring any forward header above it."""
    for _, line in kinds[:25]:
        if _FWD_HEADER_RE.match(line):
            continue
        if "cyber threat intelligence" in line.lower():
            return line
    return ""


def _etda_article(pending: list[tuple[str, str]], priority: re.Match, section: str,
                  relevance: str, urls: list) -> dict:
    """One article, from the lines above its Priority line and the ones below it.

    The title is the last of those lines classified as one, so a section heading
    or an excerpt above it cannot take its place. A pasted copy marks up no title
    at all, and there the first line is the title and the rest the intro.
    """
    marked = [n for n, (kind, _) in enumerate(pending) if kind == "title"]
    idx = marked[-1] if marked else 0
    title = pending[idx][1] if pending else ""
    intro = " ".join(text for n, (_, text) in enumerate(pending) if n != idx)
    rank = int(priority.group(1))
    return {
        "section": section,
        "title": _clean_title(title),
        "intro": _strip_quotes(intro),
        "priority_rank": rank,
        "priority_label": priority.group(2).strip(),
        "priority_key": _PRIORITY_KEYS.get(rank, "important"),
        "relevance": relevance,
        "primary_url": urls[0] if urls else "",
        "related_urls": urls[1:],
    }


def _etda_details(kinds: list[tuple[str, str]], i: int) -> tuple[str, list, int]:
    """Relevance and URLs following a Priority line, and the index to resume at."""
    relevance = ""
    urls = []
    while i < len(kinds):
        kind, line = kinds[i]
        match = _RELEVANCE_RE.match(line)
        if match:
            relevance = match.group(1).strip()
        elif _URL_RE.search(line):
            urls.extend(_clean_url(u) for u in _URL_RE.findall(line))
        elif kind != "skip":
            break  # the next title, section header or arrow
        i += 1
    return relevance, urls, i


def parse_etda(text: str) -> dict:
    """Parse an ETDA CTI Robot newsletter into report metadata and articles.

    An article starts at its 'Priority: N - Label' line, which every edition has
    for every article, whatever shape it arrived in.
    """
    text = _bounded(text)
    text = _dequote(text.replace("\r\n", "\n").replace("\r", "\n"))
    lines = text.split("\n")
    kinds = _etda_kinds(lines)
    overview = set(_etda_section_names(lines))
    report_title = _etda_report_title(kinds)

    articles = []
    section = ""
    pending = []  # (kind, text) gathered since the last article or section
    i = 0
    while i < len(kinds):
        kind, line = kinds[i]
        i += 1
        if kind == "skip":
            continue
        if kind == "arrow" or line == report_title:
            pending = []
            continue
        if kind == "section" or line in overview:
            section = line
            pending = []
            continue

        priority = _PRIORITY_RE.match(line)
        if not priority:
            pending.append((kind, line))
            continue

        relevance, urls, i = _etda_details(kinds, i)
        article = _etda_article(pending, priority, section, relevance, urls)
        pending = []
        if article["title"]:
            articles.append(article)

    return {"report_title": _clean_title(report_title),
            "tlp": _parsed_tlp(_TLP_RE.search(text)),
            "articles": articles}


# IT-ISAC lays each article out as labelled fields, separated by a rule. The
# labels wrap onto following lines, and an excerpt can run to several
# paragraphs, so a field keeps collecting until the next label, rule or title.
_ITISAC_RULE_RE = re.compile(r'^-{10,}$')
_ITISAC_FIELD_RE = re.compile(r'^(Title|Date Published|Excerpt)\s*:\s*(.*)$', re.IGNORECASE)
# The mail signature, '-- ' on its own line, which is not one of the rules above.
_ITISAC_SIGNATURE_RE = re.compile(r'^--\s*$')


def _itisac_article(block: list[str]) -> dict | None:
    """One article from one block of lines, or None if the block has no title."""
    fields = {"title": [], "excerpt": []}
    urls = []
    current = None

    for line in block:
        line = line.strip()
        label = _ITISAC_FIELD_RE.match(line)
        # The excerpt is the last field of a block, so once it starts everything
        # up to the next label is part of it: the blank lines between its
        # paragraphs, and any link in the quoted prose, which is not the
        # article's own URL and would take the rest of the sentence with it.
        if current == "excerpt" and not label:
            if line:
                fields["excerpt"].append(line)
            continue
        if not line:
            current = None
            continue
        if label:
            # "Date Published" is recognised but not kept: matching it is what
            # stops the title above from swallowing it.
            name = label.group(1).lower()
            current = name if name in fields else None
            if current:
                fields[current].append(label.group(2).strip())
            continue
        if _URL_RE.search(line):
            urls.extend(_clean_url(u) for u in _URL_RE.findall(line))
            current = None
            continue
        if current:
            fields[current].append(line)

    title = " ".join(fields["title"]).strip()
    if not title:
        return None
    return {
        "section": "",
        "title": title,
        "intro": _strip_quotes(" ".join(fields["excerpt"])),
        "priority_rank": 0,
        "priority_label": "",
        "priority_key": "",
        "relevance": "",
        "primary_url": urls[0] if urls else "",
        "related_urls": urls[1:],
    }


def parse_itisac(text: str) -> dict:
    """Parse an IT-ISAC Open Source News mail into report metadata and articles.

    IT-ISAC grades nothing, so the priority and section fields the ETDA parser
    fills stay empty rather than being invented here.
    """
    text = _bounded(text)
    text = _dequote(text.replace("\r\n", "\n").replace("\r", "\n"))
    lines = text.split("\n")

    report_title = ""
    for line in lines[:20]:
        if _FWD_HEADER_RE.match(line.strip()):
            continue
        if "[IT-ISAC]" in line:
            report_title = line.strip()
            break

    tlp_match = _TLP_RE.search(text)

    # A title opens an article and a rule closes one, so the mail's own header
    # and anything between two articles land in a block of their own and are
    # dropped for having no title. Splitting on the rule alone let a link above
    # the first title, a "view this online" banner, pass as that article's URL,
    # and folded two articles into one wherever an edition lost its rule.
    blocks = [[]]
    for line in lines:
        if _ITISAC_SIGNATURE_RE.match(line.rstrip()):
            break
        label = _ITISAC_FIELD_RE.match(line.strip())
        if label and label.group(1).lower() == "title":
            blocks.append([line])
        elif _ITISAC_RULE_RE.match(line.strip()):
            blocks.append([])
        else:
            blocks[-1].append(line)

    articles = [a for a in (_itisac_article(b) for b in blocks) if a]

    return {
        "report_title": report_title,
        "tlp": _parsed_tlp(tlp_match),
        "articles": articles,
    }


PARSERS = {
    "ETDA CTI Robot": parse_etda,
    "IT-ISAC Open Source News": parse_itisac,
}


def available_sources() -> list[str]:
    return sorted(PARSERS)


def parse(source_name: str, text: str) -> dict:
    parser = PARSERS.get(source_name)
    if parser is None:
        raise ValueError(f"No parser for newsletter source {source_name!r}")
    return parser(text or "")
