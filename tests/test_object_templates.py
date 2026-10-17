"""Every MISP object template has a UUID that every MISP accepts.

MISP checks an object's template_uuid when the object is created. Before 2.5.40
its UUID rule only took versions 0 to 5, so the version 7 UUID the threat
landscape report template had stopped every report from being created there
(issue #64), while newer MISP took it without a word.

    python -m unittest tests.test_object_templates
"""

import json
import re
import unittest
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parent.parent / "webapp" / "misp_objects" / "objects"

# CakePHP's Validation::uuid as MISP had it before 2.5.40.
MISP_UUID = re.compile(r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[0-5][a-fA-F0-9]{3}-[089aAbB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")


class TemplateUuids(unittest.TestCase):
    def test_every_template_uuid_passes_misps_validation(self):
        definitions = sorted(TEMPLATES.glob("*/definition.json"))
        self.assertTrue(definitions)
        for path in definitions:
            with self.subTest(template=path.parent.name):
                self.assertRegex(json.loads(path.read_text())["uuid"], MISP_UUID)


if __name__ == "__main__":
    unittest.main()
