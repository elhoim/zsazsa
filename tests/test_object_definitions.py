"""Every relation zsazsa writes is declared in its object definition.

The flash intel and advisory objects wrote relations their definitions did not
name, and PyMISP logged a warning for each on every save. Each builder is run
with every field filled in, so a relation added to one without its definition
fails here.

    python -m unittest tests.test_object_definitions
"""

import inspect
import unittest

from webapp import misp_store


class EveryField(dict):
    """Data that answers every key, so a builder writes every relation it knows."""

    def get(self, key, default=None):
        return "1"

    def __getitem__(self, key):
        return "1"

    def __contains__(self, key):
        return True


def _builders():
    return {name: func for name, func in vars(misp_store).items()
            if inspect.isfunction(func) and name.endswith("_obj") and name != "_build_obj"
            and "_build_obj(" in inspect.getsource(func)}


class Definitions(unittest.TestCase):
    def test_every_builder_writes_only_declared_relations(self):
        builders = _builders()
        self.assertIn("_fia_obj", builders)
        for name, build in builders.items():
            with self.subTest(builder=name), self.assertNoLogs("pymisp", "WARNING"):
                build(EveryField())


if __name__ == "__main__":
    unittest.main()
