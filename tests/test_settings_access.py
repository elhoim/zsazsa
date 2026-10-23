"""Only MISP site admins reach the settings pages (GHSA-v6rj-fh3w-rx8x).

The configuration and collection source pages hold every credential zsazsa
has and decide where identities are read from. Any MISP user could open them,
copy the keys and point the session Redis elsewhere to become anyone. These
pin the gate on both blueprints, with the user identified the way a real
request is, through the MISP session. The role itself is asked of MISP, since
the session keeps the one the user had when they logged in, and it is asked
with the user's own session: MISP_WEBAPP_KEY may not look up other users.

    python -m unittest tests.test_settings_access
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests
from flask import Flask, g
from pymisp import PyMISP

import config as _config
from webapp import collection_cache, create_app, misp_session, misp_store

USER_ROLE = {"name": "User", "perm_publish": True, "perm_site_admin": False}
ADMIN_ROLE = {"name": "Site Admin", "perm_publish": True, "perm_site_admin": True}
ANALYST = {"id": "7", "email": "analyst@example.org", "Role": USER_ROLE}
SITE_ADMIN = {"id": "1", "email": "admin@example.org", "Role": ADMIN_ROLE}

SETTINGS_BLUEPRINTS = ("config_page", "collection_sources", "setup_wizard")


class SettingsAccess(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patches = [
            mock.patch.object(_config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(_config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            # Single sign-on configured, without the redirect getting in first.
            mock.patch.object(_config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(_config, "MISP_SESSION_REDIRECT_TO_LOGIN", False, create=True),
            mock.patch.object(collection_cache, "start_worker"),
            # The session is a stand-in; asking MISP to refresh it would reach the real one.
            mock.patch.object(misp_session, "keep_misp_session_alive"),
            # The sources page lists the manual sources from MISP; nothing here reaches one.
            mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.app = create_app()
        self.client = self.app.test_client()
        self.client.set_cookie("MISP-test", "session-id")
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "token"

    def as_user(self, user, role_in_misp=None):
        """Sign in with ``user`` in the MISP session. ``role_in_misp`` is the role
        MISP has for them now, the one from the session when not given."""
        record = {"User": user, "Role": role_in_misp or (user or {}).get("Role")}
        self.view_own_record = mock.Mock(return_value=mock.Mock(
            status_code=200, url="https://misp.test/users/view/me.json", json=mock.Mock(return_value=record)))
        self.session = {"Config": {"countdown": 10}, "Auth": {"User": user}}
        for patcher in (mock.patch.object(misp_session, "get_misp_user", return_value=user),
                        mock.patch.object(misp_session, "_read_session", return_value=self.session),
                        mock.patch.object(misp_session, "_view_own_record", self.view_own_record)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def settings_requests(self):
        """One request per settings endpoint, so a route added later is covered too."""
        for rule in self.app.url_map.iter_rules():
            if rule.endpoint.split(".")[0] not in SETTINGS_BLUEPRINTS:
                continue
            if rule.endpoint == "config_page.serve_logo":
                continue
            path = rule.rule
            for arg in rule.arguments:
                path = path.replace(f"<string:{arg}>", "x").replace(f"<{arg}>", "x")
            method = "POST" if "POST" in rule.methods else "GET"
            yield rule.endpoint, method, path

    def test_every_settings_endpoint_refuses_a_user_who_is_not_a_site_admin(self):
        self.as_user(ANALYST)
        requests = list(self.settings_requests())
        self.assertGreater(len(requests), 30)
        for endpoint, method, path in requests:
            with self.subTest(endpoint=endpoint):
                resp = self.client.open(path, method=method, json={},
                                        headers={"X-CSRF-Token": "token"})
                self.assertEqual(resp.status_code, 403)

    def test_nobody_identified_is_refused_while_single_sign_on_is_configured(self):
        self.as_user(None)
        for path in ("/config", "/config/sources/"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 403)

    def test_with_the_login_redirect_on_nobody_identified_is_sent_to_misp(self):
        self.as_user(None)
        # The warning that explains the miss would otherwise ask this install's
        # session Redis where the sessions are.
        with mock.patch.object(_config, "MISP_SESSION_REDIRECT_TO_LOGIN", True), \
             mock.patch.object(misp_session, "_database_with_sessions", return_value=None):
            resp = self.client.get("/config")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/users/login", resp.headers["Location"])

    def test_without_single_sign_on_everyone_is_the_one_trusted_identity(self):
        """The documented mode for an install that does not use single sign-on:
        nobody is identified, and the whole app runs under one identity."""
        self.as_user(None)
        with mock.patch.object(_config, "MISP_SESSION_COOKIE_NAME", ""), \
             mock.patch.object(misp_session, "_session_cookie_name", return_value=""):
            self.assertEqual(self.client.get("/config/sources/").status_code, 200)

    def test_a_site_admin_gets_in(self):
        self.as_user(SITE_ADMIN)
        resp = self.client.get("/config/sources/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["Cache-Control"], "no-store")

    def test_the_role_is_asked_of_misp_with_the_users_own_session(self):
        self.as_user(SITE_ADMIN)
        self.client.get("/config/sources/")
        self.view_own_record.assert_called_once_with("MISP-test", "session-id")

    def test_a_site_admin_gets_in_when_the_zsazsa_key_cannot_look_up_users(self):
        """Issue #71: MISP shows another user's record only to a site admin, and
        MISP_WEBAPP_KEY need not be one. The check must not depend on it."""
        self.as_user(SITE_ADMIN)
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_user.return_value = {"errors": (404, {"message": "Invalid user or not authorised."})}
        with mock.patch.object(misp_store, "_misp", return_value=misp):
            self.assertEqual(self.client.get("/config/sources/").status_code, 200)

    def test_the_request_that_would_renew_the_session_id_is_not_sent(self):
        """With Session.autoRegenerate on, asking MISP could be the request that
        gives the session a new ID, which zsazsa would get instead of the browser."""
        self.as_user(SITE_ADMIN)
        self.session["Config"]["countdown"] = 1
        resp = self.client.get("/config/sources/")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Open any page in MISP first", resp.get_data(as_text=True))
        self.view_own_record.assert_not_called()

    def test_a_session_misp_has_ended_keeps_the_settings_closed(self):
        """MISP sends an ended session to its login page."""
        self.as_user(SITE_ADMIN)
        self.view_own_record.return_value.status_code = 302
        self.assertEqual(self.client.get("/config/sources/").status_code, 403)

    def test_a_user_made_site_admin_since_logging_in_gets_in(self):
        self.as_user(ANALYST, role_in_misp=ADMIN_ROLE)
        self.assertEqual(self.client.get("/config/sources/").status_code, 200)

    def test_a_site_admin_demoted_since_logging_in_is_refused(self):
        self.as_user(SITE_ADMIN, role_in_misp=USER_ROLE)
        self.assertEqual(self.client.get("/config/sources/").status_code, 403)

    def test_the_settings_stay_closed_when_misp_cannot_be_asked(self):
        self.as_user(SITE_ADMIN)
        self.view_own_record.side_effect = requests.ConnectionError("MISP is down")
        resp = self.client.get("/config/sources/")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Could not check your role in MISP", resp.get_data(as_text=True))

    def test_an_ajax_request_is_refused_as_json(self):
        self.as_user(ANALYST)
        resp = self.client.post("/config/test_misp_connection", json={"url": "https://x"},
                                headers={"X-CSRF-Token": "token"})
        self.assertEqual(resp.status_code, 403)
        self.assertFalse(resp.get_json()["ok"])

    def test_the_brand_logo_stays_reachable(self):
        self.as_user(ANALYST)
        resp = self.client.get("/config/logo")
        resp.close()
        self.assertNotEqual(resp.status_code, 403)


class SiteAdminFlag(unittest.TestCase):
    """What the Settings menu goes by. MISP stores a role permission as a PHP
    bool or as 1 / "1"; "0" is not true."""

    def is_admin(self, value):
        with Flask(__name__).test_request_context("/"):
            g.misp_user = {"Role": {"perm_site_admin": value}}
            return misp_session.current_user_is_admin()

    def test_what_counts_as_a_site_admin(self):
        for value, expected in ((True, True), (1, True), ("1", True),
                                (False, False), (0, False), ("0", False), (None, False)):
            with self.subTest(value=value):
                self.assertIs(self.is_admin(value), expected)


if __name__ == "__main__":
    unittest.main()
