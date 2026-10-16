"""docker/configure.py, which writes config/__init__.py in the container.

It pins the type each value is written with. A VERIFYCERT written as the string
'False' made PyMISP look for a CA bundle file called False, and every call to
MISP failed. It also pins that a new config has a SECRET_KEY of its own and is
readable by its owner only, that an imported config keeps a backup, and that
the arguments can come in on standard input, where the keys among them are not
readable by other users of the host as command line arguments are.

    python -m unittest tests.test_docker_configure
"""

import importlib.util
import io
import re
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("configure", ROOT / "docker" / "configure.py")
configure = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(configure)


class Configure(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.config = Path(tmp.name) / "config" / "__init__.py"
        self.config.parent.mkdir()
        for name, path in (("CONFIG", self.config), ("EXAMPLE", ROOT / "config" / "__init__.py.example")):
            patcher = mock.patch.object(configure, name, path)
            patcher.start()
            self.addCleanup(patcher.stop)

    def settings(self):
        namespace = {}
        exec(self.config.read_text(), namespace)
        return namespace

    def test_a_new_config_has_a_secret_key_of_its_own_and_is_private(self):
        with mock.patch("sys.stdout", io.StringIO()):
            configure.main([])
        key = self.settings()["SECRET_KEY"]
        self.assertRegex(key, r"^[0-9a-f]{64}$")
        self.assertNotIn(key, (ROOT / "config" / "__init__.py.example").read_text())
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)

    def test_values_are_written_with_the_type_the_application_reads(self):
        with mock.patch("sys.stdout", io.StringIO()):
            configure.main(["MISP_WEBAPP_VERIFYCERT=False", "MISP_VERIFYCERT=True", "JOB_REDIS_PORT=6380",
                            "MISP_SESSION_REDIRECT_TO_LOGIN=true", "JOB_REDIS_HOST=redis",
                            "PORT=5055", "MISP_SCRAPER_ENABLED=False", "MISP_URL="])
        settings = self.settings()
        self.assertEqual(settings["PORT"], 5055)
        self.assertIs(settings["MISP_SCRAPER_ENABLED"], False)
        self.assertEqual(settings["MISP_URL"], "")
        self.assertIs(settings["MISP_WEBAPP_VERIFYCERT"], False)
        self.assertIs(settings["MISP_VERIFYCERT"], True)
        self.assertEqual(settings["JOB_REDIS_PORT"], 6380)
        self.assertIs(settings["MISP_SESSION_REDIRECT_TO_LOGIN"], True)
        self.assertEqual(settings["JOB_REDIS_HOST"], "redis")

    def test_a_key_an_older_config_does_not_have_is_added(self):
        self.config.write_text("SECRET_KEY = 'x'\n")
        with mock.patch("sys.stdout", io.StringIO()):
            configure.main(["JOB_REDIS_PASSWORD=s3cret"])
        self.assertEqual(self.settings()["JOB_REDIS_PASSWORD"], "s3cret")

    def test_an_imported_config_replaces_the_old_one_which_is_kept(self):
        self.config.write_text("SECRET_KEY = 'old'\n")
        imported = self.config.parent / "imported.py"
        imported.write_text("SECRET_KEY = 'imported'\n")
        with mock.patch("sys.stdout", io.StringIO()):
            configure.main(["--import", str(imported), "JOB_REDIS_HOST=redis"])
        self.assertEqual(self.settings()["SECRET_KEY"], "imported")
        self.assertEqual(self.settings()["JOB_REDIS_HOST"], "redis")
        self.assertIn("'old'", self.config.with_name("__init__.py.backup").read_text())
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)

    def test_arguments_on_standard_input_keep_their_empty_values(self):
        """The scripts send every argument this way, keys and passwords included."""
        arguments = ["JOB_REDIS_PASSWORD=s3cret", "MISP_WEBAPP_KEY=k3y", "MISP_URL="]
        with mock.patch("sys.stdin", io.StringIO("".join(a + "\0" for a in arguments))), \
             mock.patch("sys.stdout", io.StringIO()):
            configure.main(["-"])
        settings = self.settings()
        self.assertEqual(settings["JOB_REDIS_PASSWORD"], "s3cret")
        self.assertEqual((settings["MISP_WEBAPP_KEY"], settings["MISP_URL"]), ("k3y", ""))

    def test_nothing_on_standard_input_leaves_the_config_alone(self):
        """A run of setup.sh that keeps the configuration has nothing to pass."""
        self.config.write_text("SECRET_KEY = 'x'\n")
        with mock.patch("sys.stdin", io.StringIO("\0")), mock.patch("sys.stdout", io.StringIO()):
            configure.main(["-"])
        self.assertEqual(self.config.read_text(), "SECRET_KEY = 'x'\n")

    def test_a_value_that_spans_lines_is_replaced_whole(self):
        self.config.write_text("SECRET_KEY = 'x'\nMISP_URL = (\n    'https://old.example'\n)\nPORT = 5000\n")
        with mock.patch("sys.stdout", io.StringIO()):
            configure.main(["MISP_URL=https://new.example"])
        self.assertEqual((self.settings()["MISP_URL"], self.settings()["PORT"]), ("https://new.example", 5000))

    def test_starting_again_leaves_an_existing_config_alone(self):
        with mock.patch("sys.stdout", io.StringIO()):
            configure.main([])
            first = self.config.read_text()
            configure.main([])
        self.assertEqual(self.config.read_text(), first)
        self.assertEqual(len(re.findall(r"^SECRET_KEY", first, re.M)), 1)


if __name__ == "__main__":
    unittest.main()
