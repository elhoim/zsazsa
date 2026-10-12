"""The example config checks the certificates of the MISP servers it holds keys for.

It shipped MISP_VERIFYCERT and MISP_WEBAPP_VERIFYCERT as False, so a new
install sent its MISP API keys without checking who answered.

    python -m unittest tests.test_config_example
"""

import ast
import unittest
from pathlib import Path

EXAMPLE = Path(__file__).parent.parent / "config" / "__init__.py.example"


def _settings():
    tree = ast.parse(EXAMPLE.read_text())
    return {target.id: node.value for node in tree.body if isinstance(node, ast.Assign)
            for target in node.targets if isinstance(target, ast.Name)}


class Example(unittest.TestCase):
    def test_misp_certificates_are_verified(self):
        settings = _settings()
        for name in ("MISP_VERIFYCERT", "MISP_WEBAPP_VERIFYCERT"):
            with self.subTest(setting=name):
                self.assertIs(ast.literal_eval(settings[name]), True)


if __name__ == "__main__":
    unittest.main()
