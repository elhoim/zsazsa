"""Every configuration setting is documented in README.md.

config/__init__.py.example is what an admin copies and edits, the
"Configuration" section of README.md is where each setting is explained, and
the two are edited by hand. The six JOB_REDIS_* settings arrived in the example
without a word in the documentation and were documented two commits later.

    python -m unittest tests.test_docs_sync
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent
_SETTING = re.compile(r"^([A-Z][A-Z0-9_]*)\s*=", re.MULTILINE)


class ConfigSettingsDocumented(unittest.TestCase):
    def test_every_example_setting_is_in_the_readme(self):
        example = (ROOT / "config" / "__init__.py.example").read_text()
        readme = (ROOT / "README.md").read_text()
        # Whole word: PORT is not documented by SMTP_PORT.
        undocumented = sorted(
            name for name in set(_SETTING.findall(example))
            if not re.search(rf"\b{name}\b", readme)
        )
        self.assertEqual(undocumented, [], "settings missing from README.md")


if __name__ == "__main__":
    unittest.main()
