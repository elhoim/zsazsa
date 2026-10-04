"""Markdown rendered in the browser goes through DOMPurify.

Report and article text comes from outside: feeds, newsletters, the model. Two
pages fell back to inserting marked's raw HTML when DOMPurify was missing, so a
CDN that served marked but not DOMPurify turned a report into script on the
analyst's page. Every call to marked.parse now sits inside DOMPurify.sanitize,
and without DOMPurify the text is shown as text.

    python -m unittest tests.test_markdown_sanitising
"""

import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent / "webapp"


class MarkedOutputIsSanitised(unittest.TestCase):
    def test_every_marked_parse_is_wrapped_in_dompurify(self):
        sources = list((_ROOT / "templates").rglob("*.html")) + list((_ROOT / "static").rglob("*.js"))
        offenders = []
        for path in sources:
            text = path.read_text(encoding="utf-8")
            if text.count("marked.parse(") != text.count("DOMPurify.sanitize(marked.parse("):
                offenders.append(str(path.relative_to(_ROOT)))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
