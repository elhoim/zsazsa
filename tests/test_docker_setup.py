"""docker/setup.sh, the questions that set zsazsa up in Docker, and the compose files.

It pins that the answers become the settings written to the config and the .env
the compose files read, that what an existing configuration holds is not asked
again, and that the keys among the answers reach the container on standard
input rather than as arguments. The script is sourced in a temporary copy of
docker/ and its functions are called one by one; docker itself is a stub, so
nothing is built or started.

    python -m unittest tests.test_docker_setup
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# What the script does after the questions, minus building and starting.
QUESTIONS = """source docker/setup.sh
init_answers
interview
confirm_plan
printf '%s\\0' ${SETTINGS[@]+"${SETTINGS[@]}"} > settings.bin
write_env
"""


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class SetupScript(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "zsazsa"
        shutil.copytree(ROOT / "docker", self.root / "docker", ignore=shutil.ignore_patterns("volumes", ".env", "__pycache__"))
        # configure.py writes the config through core.atomic_write.
        shutil.copytree(ROOT / "core", self.root / "core", ignore=shutil.ignore_patterns("__pycache__"))
        (self.root / "config").mkdir()
        shutil.copy(ROOT / "config" / "__init__.py.example", self.root / "config")
        self.bin = Path(tmp.name) / "bin"
        self.bin.mkdir()
        self.fake("docker", "exit 1")
        self.fake("getent", "exit 1")

    def fake(self, tool, body):
        """A stand-in for a command, so nothing depends on this machine."""
        (self.bin / tool).write_text(f"#!/bin/sh\n{body}\n")
        (self.bin / tool).chmod(0o755)

    def run_bash(self, script, answers=(), expect_success=True):
        (self.root / "run.sh").write_text(script)
        env = dict(os.environ, PATH=f"{self.bin}:{Path(sys.executable).parent}:/usr/bin:/bin", NO_COLOR="1")
        result = subprocess.run(["bash", "run.sh"], cwd=self.root, env=env, text=True, timeout=20,
                                input="".join(f"{a}\n" for a in answers), capture_output=True)
        self.assertEqual(result.returncode == 0, expect_success, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def settings(self):
        return [s for s in (self.root / "settings.bin").read_text().split("\0") if s]

    def env(self):
        return dict(line.split("=", 1) for line in (self.root / "docker" / ".env").read_text().splitlines()
                    if line and not line.startswith("#"))

    def existing_config(self, text):
        path = self.root / "docker" / "volumes" / "config" / "__init__.py"
        path.parent.mkdir(parents=True)
        path.write_text(text)

    def test_values_are_read_quoted_unquoted_and_missing(self):
        (self.root / "sample.py").write_text("A = 'one'\nB = \"two\"\nC = False  # note\nD = 5000\nE = ''\n")
        output = self.run_bash("source docker/setup.sh\nfor k in A B C D E F; do config_value $k sample.py; echo; done\n")
        self.assertEqual(output.split("\n")[:6], ["one", "two", "False", "5000", "", ""])

    def test_input_that_ends_stops_the_script_instead_of_asking_forever(self):
        output = self.run_bash(QUESTIONS, ["n", "1", ""], expect_success=False)
        self.assertIn("Input ended.", output)

    def test_a_new_configuration_with_redis_on_this_host(self):
        output = self.run_bash(QUESTIONS, [
            "n",                                           # nothing to import
            "1", "", "", "",                               # MISP on this host, its Redis on 127.0.0.1
            "https://misp.example.org", "key1", "y",       # MISP address, key, TLS
            "n",                                           # no single sign-on
            "", "5055", "n",                               # address, port, no proxy now
            "y", "n",                                      # analyser and collector, no misp-scraper
            "y"])                                          # go ahead
        settings = self.settings()
        for expected in ("MISP_WEBAPP_URL=https://misp.example.org", "MISP_WEBAPP_KEY=key1",
                         "MISP_WEBAPP_VERIFYCERT=True", "MISP_SESSION_REDIRECT_TO_LOGIN=False",
                         "JOB_REDIS_HOST=127.0.0.1", "MISP_SCRAPER_ENABLED=False"):
            self.assertIn(expected, settings)
        env = self.env()
        self.assertEqual(env["COMPOSE_FILE"], "docker-compose.yml:docker-compose.host.yml")
        self.assertEqual(env["COMPOSE_PROFILES"], "scheduled")
        self.assertEqual((env["ZSAZSA_BIND"], env["ZSAZSA_PORT"]), ("127.0.0.1", "5055"))
        self.assertEqual((self.root / "docker" / ".env").stat().st_mode & 0o777, 0o600)
        self.assertIn("Single sign-on     off", output)

        # The settings are what configure.py writes into the config.
        subprocess.run([sys.executable, "docker/configure.py", "-"], cwd=self.root, check=True, capture_output=True,
                       input="".join(s + "\0" for s in settings), text=True)
        namespace = {}
        exec((self.root / "config" / "__init__.py").read_text(), namespace)
        self.assertEqual((namespace["MISP_WEBAPP_KEY"], namespace["JOB_REDIS_PORT"]), ("key1", 6379))
        self.assertIs(namespace["MISP_WEBAPP_VERIFYCERT"], True)

    def test_an_existing_configuration_is_not_asked_again(self):
        self.existing_config(
            "MISP_WEBAPP_URL = 'https://misp.example.org'\nMISP_WEBAPP_KEY = 'k'\nMISP_SCRAPER_ENABLED = False\n"
            "MISP_SESSION_REDIRECT_TO_LOGIN = True\nMISP_SESSION_REDIS_HOST = '10.0.0.5'\n")
        (self.root / "docker" / ".env").write_text("ZSAZSA_BIND=0.0.0.0\nZSAZSA_PORT=5055\n")
        output = self.run_bash(QUESTIONS, [
            "y",                  # keep the configuration
            "2",                  # MISP on another host: no proxy to set up here
            "", "",               # address and port: the ones of the run before
            "n",                  # no analyser and collector
            "y"])
        for question in ("MISP URL", "MISP API key", "Redis host", "Use single sign-on", "Use misp-scraper"):
            self.assertNotIn(question, output)
        self.assertEqual(self.settings(), [])
        self.assertEqual((self.env()["COMPOSE_FILE"], self.env()["COMPOSE_PROFILES"]), ("docker-compose.yml", ""))
        self.assertEqual((self.env()["ZSAZSA_BIND"], self.env()["ZSAZSA_PORT"]), ("0.0.0.0", "5055"))
        self.assertIn("Single sign-on     on", output)

    def test_misp_docker_s_redis_puts_zsazsa_on_its_network(self):
        self.existing_config(
            "MISP_WEBAPP_URL = 'https://misp.example.org'\nMISP_WEBAPP_KEY = 'k'\nMISP_SCRAPER_ENABLED = False\n"
            "MISP_SESSION_REDIRECT_TO_LOGIN = True\nMISP_SESSION_REDIS_HOST = 'misp-docker-redis-1'\n")
        # docker inspect names the network the Redis container is on.
        self.fake("docker", 'if [ "$1" = inspect ]; then echo "misp-docker_default "; exit 0; fi\nexit 1')
        output = self.run_bash(QUESTIONS, ["y", "3", "", "", "n", "n", "y"])
        env = self.env()
        self.assertEqual(env["COMPOSE_FILE"], "docker-compose.yml:docker-compose.misp-docker.yml")
        self.assertEqual(env["MISP_NETWORK"], "misp-docker_default")
        self.assertIn("Set up the /zsazsa proxy now?", output)

    def test_each_use_of_redis_is_shown_with_its_own_host(self):
        self.existing_config(
            "MISP_WEBAPP_URL = 'https://misp.example.org'\nMISP_WEBAPP_KEY = 'k'\nMISP_SCRAPER_ENABLED = False\n"
            "MISP_SESSION_REDIS_HOST = '10.0.0.5'\nSCRAPER_REDIS_HOST = '10.0.0.6'\nJOB_REDIS_HOST = '10.0.0.7'\n"
            "MISP_SESSION_REDIRECT_TO_LOGIN = False\n")
        output = self.run_bash(QUESTIONS, ["y", "2", "", "", "n", "y"])
        for row in ("Redis, sign-on     10.0.0.5:6379", "Redis, scraper     10.0.0.6:6379",
                    "Redis, jobs        10.0.0.7:6379"):
            self.assertIn(row, output)

    def test_typed_keys_reach_the_container_on_standard_input_not_as_arguments(self):
        """Arguments of a running process can be read by every user of the host."""
        self.run_bash('source docker/setup.sh\ninit_answers\n'
                      'SETTINGS=("MISP_WEBAPP_KEY=typed-secret" "JOB_REDIS_PASSWORD=redis-secret" "MISP_URL=")\n'
                      'dc() { printf "%s\\n" "$@" > args.txt; cat > stdin.bin; }\nwrite_docker_config\n')
        arguments = (self.root / "args.txt").read_text()
        for secret in ("typed-secret", "redis-secret"):
            self.assertNotIn(secret, arguments)
        self.assertEqual((self.root / "stdin.bin").read_text().split("\0")[:-1],
                         ["MISP_WEBAPP_KEY=typed-secret", "JOB_REDIS_PASSWORD=redis-secret", "MISP_URL="])

    def test_an_import_this_user_cannot_read_is_read_through_docker_from_where_it_is(self):
        """It used to read the configuration in docker/volumes instead."""
        other = self.root / "elsewhere"
        other.mkdir()
        (other / "old.py").write_text("MISP_WEBAPP_URL = 'https://misp.example.org'\n")
        (other / "old.py").chmod(0)
        self.addCleanup((other / "old.py").chmod, 0o600)
        if os.access(other / "old.py", os.R_OK):
            self.skipTest("this user reads every file")
        self.run_bash('source docker/setup.sh\ninit_answers\n'
                      'copy_out() { printf "%s %s" "$1" "$2" > copied.txt; return 1; }\nask_config_source\n',
                      ["y", str(other / "old.py")])
        self.assertEqual((self.root / "copied.txt").read_text(), f"{other} old.py")

    def test_a_url_for_the_scraper_folder_is_asked_again(self):
        """git clone took the URL for the folder to clone into, and failed."""
        output = self.run_bash('source docker/setup.sh\ninit_answers\n'
                               'SCRAPER_USED=yes SCR_URL=https://misp.example.org SCR_KEY=k\n'
                               'ask_scraper\nprintf "%s %s" "$SCRAPER_DIR" "$SCRAPER_CLONE" > scraper.txt\n',
                               ["y", "https://github.com/cudeso/misp-scraper", "checkouts/misp-scraper", "y", ""])
        self.assertIn("That is a URL", output)
        # Relative to where the setup runs, which Compose would read from docker/.
        self.assertEqual((self.root / "scraper.txt").read_text(), f"{self.root}/checkouts/misp-scraper yes")

    def test_a_url_an_earlier_run_stored_is_not_offered_as_the_folder(self):
        (self.root / "docker" / ".env").write_text("SCRAPER_DIR=https://github.com/cudeso/misp-scraper\n")
        output = self.run_bash('source docker/setup.sh\ninit_answers\n'
                               'SCRAPER_USED=yes SCR_URL=https://misp.example.org SCR_KEY=k\n'
                               'ask_scraper\nprintf "%s" "$SCRAPER_DIR" > scraper.txt\n', ["y", "", "y", ""])
        self.assertNotIn("https://github.com/cudeso/misp-scraper]", output)
        self.assertEqual((self.root / "scraper.txt").read_text(), f"{Path(self.root).parent}/misp-scraper")

    def test_a_relative_import_path_is_made_absolute_for_docker(self):
        """docker run -v takes a relative path for the name of a volume."""
        (self.root / "old.py").write_text("MISP_WEBAPP_URL = 'https://misp.example.org'\n")
        self.run_bash('source docker/setup.sh\ninit_answers\nask_config_source\nprintf "%s" "$IMPORT" > import.txt\n',
                      ["y", "old.py"])
        self.assertEqual((self.root / "import.txt").read_text(), f"{self.root}/old.py")

    def test_the_scraper_check_passes_a_marker_with_a_space_as_one_value(self):
        self.run_bash('source docker/setup.sh\ninit_answers\n'
                      'zpy() { printf "starting\\nzsazsa:source=\\"misp scraper\\"\\nurls\\n"; }\n'
                      'dc() { printf "%s\\n" "$@" > dc-args.txt; echo True; }\n'
                      'check_scraper_config\nprintf "%s\\n" "${DONE[@]}" > done.txt\n')
        arguments = (self.root / "dc-args.txt").read_text().splitlines()
        self.assertEqual(arguments[-2:], ['zsazsa:source="misp scraper"', "urls"])
        self.assertIn("misp-scraper is configured", (self.root / "done.txt").read_text())

    def test_the_scraper_config_follows_the_tls_answer(self):
        scraper = self.root / "misp-scraper"
        scraper.mkdir()
        (scraper / "feedlist.json").write_text("[]")
        self.run_bash('source docker/setup.sh\ninit_answers\n'
                      f'SCRAPER_DIR={scraper}\nSCRAPER_MISP_URL=https://misp.example.org\n'
                      'SCRAPER_MISP_KEY=k\nSCRAPER_MISP_VERIFY=True\n'
                      'copy_scraper_files() { cp "$1/scraper.py" written.py; }\ncheck_scraper_config() { :; }\n'
                      'write_scraper_config\n')
        written = (self.root / "written.py").read_text().splitlines()
        for line in ('misp_url = "https://misp.example.org"', 'misp_key = "k"', "misp_verifycert = True"):
            self.assertIn(line, written)

    def write_scraper_config(self):
        scraper = self.root / "misp-scraper"
        scraper.mkdir(exist_ok=True)
        (scraper / "feedlist.json").write_text("[]")
        self.run_bash('source docker/setup.sh\ninit_answers\n'
                      f'SCRAPER_DIR={scraper}\nSCRAPER_MISP_URL=https://misp.example.org\n'
                      'SCRAPER_MISP_KEY=k\nSCRAPER_MISP_VERIFY=True\n'
                      'copy_scraper_files() { cp "$1/scraper.py" written.py; }\ncheck_scraper_config() { :; }\n'
                      'write_scraper_config\n')
        return (self.root / "written.py").read_text()

    def test_each_scraper_config_gets_a_flask_secret_key_of_its_own(self):
        # The template once had misp-scraper's example key, so every Docker
        # install shared one that is on GitHub for anyone to read.
        keys = []
        for _ in range(2):
            lines = [line for line in self.write_scraper_config().splitlines()
                     if line.startswith("flask_secret_key = ")]
            self.assertEqual(len(lines), 1)
            keys.append(lines[0].split('"')[1])
        self.assertNotEqual(keys[0], keys[1])
        for key in keys:
            self.assertRegex(key, r"^[0-9a-f]{64}$")


def _compose_available():
    try:
        return subprocess.run(["docker", "compose", "version"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@unittest.skipUnless(_compose_available(), "needs docker compose")
class ComposeFiles(unittest.TestCase):
    """Every combination the setup can write is a valid compose project."""

    def test_each_network_and_profile_combination_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker = Path(tmp) / "docker"
            shutil.copytree(ROOT / "docker", docker, ignore=shutil.ignore_patterns("volumes", ".env", "__pycache__"))
            for files in ("docker-compose.yml", "docker-compose.yml:docker-compose.host.yml",
                          "docker-compose.yml:docker-compose.misp-docker.yml"):
                for profiles in ("", "scheduled,scraper"):
                    with self.subTest(files=files, profiles=profiles):
                        (docker / ".env").write_text(f"COMPOSE_FILE={files}\nCOMPOSE_PROFILES={profiles}\n"
                                                     "MISP_NETWORK=misp-docker_default\nSCRAPER_DIR=/tmp\n")
                        result = subprocess.run(["docker", "compose", "config", "-q"], cwd=docker,
                                                capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
