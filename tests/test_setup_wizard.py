"""The setup wizard under Settings, and the saves it makes through /config.

It pins that every step renders for a site admin without a stored key,
password or webhook URL in the page, that a step saved through the Settings
form goes on to the next step and changes nothing it did not send, that a
refused save goes back to the step it came from, and that saving the AI
providers from the wizard leaves the per-feature AI settings alone. The logo
the organisation step uploads is held to the 2 MB the Settings page names. Which steps
count as set up decides where the wizard opens and whether the dashboard
points to it.

    python -m unittest tests.test_setup_wizard
"""

import io
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import render_template

import config as _config
from webapp import collection_cache, create_app, misp_session, misp_store
from webapp.routes import config_page, setup_wizard

SITE_ADMIN = {"id": "1", "email": "admin@example.org",
              "Role": {"name": "Site Admin", "perm_publish": True, "perm_site_admin": True}}

SECRETS = {
    "OPENAI_API_KEY": "sk-openai-secret",
    "LOCAL_LLM_API_KEY": "local-llm-secret",
    "SMTP_PASSWORD": "smtp-secret",
    "MISP_SERVERS": [{"id": "partner", "label": "Partner", "url": "https://misp.partner.example",
                      "api_key": "server-secret", "enabled": True}],
    "MISP_URL": "https://scraper.example.org",
    "MISP_KEY": "scraper-secret",
    "IMAP_SOURCES": [{"id": "inbox", "name": "Threat inbox", "host": "imap.example.org", "username": "cti",
                      "password": "imap-secret", "sources": [{"name": "Robot digest"}]}],
    "NOTIFICATION_CHANNELS": [{"id": "mm", "name": "Alerts", "type": "mattermost", "enabled": True,
                               "url": "https://chat.example.org/hooks/webhook-secret"}],
}
NOTHING_SET_UP = {
    "BRAND_COMPANY": "", "MISP_SERVERS": [], "IMAP_SOURCES": [], "NOTIFICATION_CHANNELS": [],
    "OPENAI_ENABLED": False, "LOCAL_LLM_ENABLED": False,
    "FOCUS_POINTS_GEOGRAPHIES": [], "FOCUS_POINTS_SECTORS": [], "FOCUS_POINTS_TECHNOLOGIES": [],
    "FOCUS_POINTS_THREAT_TYPES": [], "FOCUS_POINTS_THREAT_ACTORS": [],
}


def _keyvals(path):
    namespace = {}
    exec(compile(Path(path).read_text(), str(path), "exec"), namespace)
    return {k: v for k, v in namespace.items() if k.isupper()}


class SetupWizard(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.target = self.dir / "__init__.py"
        shutil.copy2("config/__init__.py.example", self.target)
        self.patch_all(
            mock.patch.object(_config, "DB_FILE", str(self.dir / "test.db"), create=True),
            mock.patch.object(_config, "LOG_FILE", str(self.dir / "test.log"), create=True),
            mock.patch.object(_config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(_config, "MISP_SESSION_REDIRECT_TO_LOGIN", False, create=True),
            mock.patch.object(collection_cache, "start_worker"),
            # The session is a stand-in; asking MISP to refresh it would reach the real one.
            mock.patch.object(misp_session, "keep_misp_session_alive"),
            mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
            mock.patch.object(misp_session, "get_misp_user", return_value=SITE_ADMIN),
            mock.patch.object(misp_store, "user_role", return_value=SITE_ADMIN["Role"]),
            mock.patch.object(misp_session, "derive_cookie_name", return_value=""),
            mock.patch.object(setup_wizard, "scraper_enabled", return_value=False),
            # Saves go to a copy of the config, and the running config is left as it is.
            mock.patch.object(config_page, "_CONFIG_FILE", self.target),
            mock.patch.object(config_page, "_BACKUP_FILE", self.dir / "backup.py"),
            mock.patch.object(config_page, "importlib"),
            mock.patch.object(config_page.audit, "record"),
        )
        self.app = create_app()
        self.client = self.app.test_client()
        self.client.set_cookie("MISP-test", "session-id")
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "token"

    def patch_all(self, *patchers):
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def configured(self, **values):
        self.patch_all(*(mock.patch.object(_config, k, v, create=True) for k, v in values.items()))

    def test_every_step_renders_without_a_stored_secret(self):
        self.configured(**SECRETS)
        setup_wizard.scraper_enabled.return_value = True
        for name in setup_wizard.STEP_NAMES:
            with self.subTest(step=name):
                resp = self.client.get(f"/config/setup/{name}")
                self.assertEqual(resp.status_code, 200)
                page = resp.get_data(as_text=True)
                for secret in ("sk-openai-secret", "local-llm-secret", "smtp-secret", "server-secret",
                               "scraper-secret", "imap-secret", "webhook-secret"):
                    self.assertNotIn(secret, page)

    def test_what_is_stored_is_shown_by_name(self):
        self.configured(**SECRETS)
        page = self.client.get("/config/setup/sources").get_data(as_text=True)
        for shown in ("https://misp.partner.example", "Threat inbox", "Robot digest"):
            self.assertIn(shown, page)
        page = self.client.get("/config/setup/ai").get_data(as_text=True)
        self.assertIn("Configured, leave blank to keep", page)
        self.assertIn("Alerts", self.client.get("/config/setup/notifications").get_data(as_text=True))

    def test_an_unknown_step_is_not_found(self):
        self.assertEqual(self.client.get("/config/setup/elsewhere").status_code, 404)

    def test_it_opens_on_the_first_step_not_set_up(self):
        self.configured(**dict(NOTHING_SET_UP, BRAND_COMPANY="Example Corp"))
        self.assertTrue(self.client.get("/config/setup/").headers["Location"].endswith("/config/setup/sources"))

    def test_sources_and_focus_points_are_what_setup_needs(self):
        self.configured(**NOTHING_SET_UP)
        self.assertTrue(setup_wizard.needs_setup())
        self.configured(MISP_SERVERS=SECRETS["MISP_SERVERS"])
        self.assertTrue(setup_wizard.needs_setup())
        self.configured(FOCUS_POINTS_SECTORS=["Energy"])
        self.assertFalse(setup_wizard.needs_setup())

    def test_a_channel_counts_once_it_has_somewhere_to_send_to(self):
        """The example config has a Mattermost channel without a URL."""
        empty = [{"id": "mattermost-main", "name": "Mattermost", "type": "mattermost", "url": "", "enabled": True}]
        self.configured(NOTIFICATION_CHANNELS=empty)
        self.assertFalse(setup_wizard.status()["notifications"])
        self.assertNotIn("Mattermost</span>", self.client.get("/config/setup/notifications").get_data(as_text=True))
        # A configuration from before the channels has only the one webhook.
        self.configured(NOTIFICATION_CHANNELS=[], MATTERMOST_WEBHOOK_URL="https://chat.example.org/hooks/x",
                        MATTERMOST_ENABLED=True)
        self.assertTrue(setup_wizard.status()["notifications"])

    def test_a_manual_source_added_from_the_wizard_goes_back_to_it(self):
        """The form posts to its own URL, and the wizard's link has wizard=1 in it."""
        self.assertIn("/config/sources/new?wizard=1", self.client.get("/config/setup/sources").get_data(as_text=True))
        form = self.client.get("/config/sources/new?wizard=1").get_data(as_text=True)
        self.assertIn('href="/config/setup/sources"', form)
        with mock.patch.object(misp_store, "create_collection_source", return_value="u" * 36) as create, \
             mock.patch.object(collection_cache, "trigger_refresh"):
            from_wizard = self.client.post("/config/sources/new?wizard=1", data={"csrf_token": "token", "name": "Portal"})
            from_sources = self.client.post("/config/sources/new", data={"csrf_token": "token", "name": "Portal"})
        self.assertEqual(create.call_count, 2)
        self.assertTrue(from_wizard.headers["Location"].endswith("/config/setup/sources"))
        self.assertTrue(from_sources.headers["Location"].endswith("/config/sources/"))

    def test_the_last_step_says_so_once_sources_and_focus_points_are_in(self):
        self.configured(**dict(NOTHING_SET_UP, MISP_SERVERS=SECRETS["MISP_SERVERS"]))
        self.assertNotIn("You're done", self.client.get("/config/setup/done").get_data(as_text=True))
        self.configured(FOCUS_POINTS_SECTORS=["Energy"])
        self.assertIn("You're done", self.client.get("/config/setup/done").get_data(as_text=True))
        self.assertNotIn("You're done", self.client.get("/config/setup/focus").get_data(as_text=True))

    def test_the_dashboard_sends_a_site_admin_to_the_wizard_until_setup_is_done(self):
        for setup_needed, admin, shown in ((True, True, True), (True, False, False), (False, True, False)):
            with self.subTest(setup_needed=setup_needed, admin=admin), self.app.test_request_context("/"), \
                 mock.patch.object(misp_session, "current_user_is_admin", return_value=admin):
                html = render_template("_dashboard_content.html", setup_needed=setup_needed,
                                       stakeholder_count=1, pir_count=1)
                self.assertEqual("/config/setup/" in html, shown)

    def test_openai_counts_in_a_config_from_before_its_switch(self):
        """The analyser uses OpenAI unless OPENAI_ENABLED says otherwise."""
        self.configured(**dict(NOTHING_SET_UP, OPENAI_API_KEY="sk-real"))
        with mock.patch.dict(_config.__dict__):
            del _config.__dict__["OPENAI_ENABLED"]
            self.assertTrue(setup_wizard.status()["ai"])
            page = self.client.get("/config/setup/ai").get_data(as_text=True)
        self.assertRegex(page, r'id="wz-openai-enabled"\s+checked')

    def test_the_placeholders_of_the_example_config_are_not_set_up(self):
        self.configured(**dict(NOTHING_SET_UP, OPENAI_ENABLED=True, OPENAI_API_KEY="sk-your-openai-key-here",
                               MISP_URL="https://your-misp-instance.example.com"))
        with mock.patch.object(setup_wizard, "scraper_enabled", return_value=True):
            self.assertEqual((setup_wizard.status()["ai"], setup_wizard.status()["sources"]), (False, False))

    def post_step(self, step, **fields):
        return self.client.post("/config", data=dict(fields, csrf_token="token", wizard_step=step))

    def test_a_saved_step_goes_on_and_changes_only_what_it_sent(self):
        self.client.post("/config", data={"csrf_token": "token"})
        unchanged = _keyvals(self.target)
        resp = self.post_step("organisation", BRAND_COMPANY="Example Corp", BRAND_DEPARTMENT="CTI")
        self.assertTrue(resp.headers["Location"].endswith("/config/setup/sources"))
        self.assertEqual(_keyvals(self.target), dict(unchanged, BRAND_COMPANY="Example Corp", BRAND_DEPARTMENT="CTI"))

    def test_the_last_step_with_a_form_ends_on_done(self):
        resp = self.post_step("notifications", SMTP_HOST="", SMTP_FROM="cti@example.org",
                              SMTP_SENDER_NAME="Threat Intelligence")
        self.assertTrue(resp.headers["Location"].endswith("/config/setup/done"))
        self.assertEqual(_keyvals(self.target)["SMTP_FROM"], "cti@example.org")
        self.assertEqual(_keyvals(self.target)["SMTP_SENDER_NAME"], "Threat Intelligence")

    def test_a_save_that_names_no_step_stays_on_the_settings_page(self):
        resp = self.post_step("https://elsewhere.example", FOCUS_POINTS_SECTORS="Energy\nFinance")
        self.assertTrue(resp.headers["Location"].endswith("/config?tab=tab-connections"))
        self.assertEqual(_keyvals(self.target)["FOCUS_POINTS_SECTORS"], ["Energy", "Finance"])

    def test_a_refused_save_goes_back_to_its_step(self):
        """A new mail server without its password is refused, as on the Settings page."""
        self.configured(SMTP_HOST="smtp.old.example", SMTP_PASSWORD="smtp-secret")
        before = self.target.read_text()
        resp = self.post_step("notifications", SMTP_HOST="smtp.new.example")
        self.assertTrue(resp.headers["Location"].endswith("/config/setup/notifications"))
        self.assertEqual(self.target.read_text(), before)

    def test_the_ai_providers_are_saved_without_touching_the_features(self):
        self.configured(LOCAL_LLM_URL="", LOCAL_LLM_API_KEY="")
        with mock.patch("core.ai_config.save") as save_features:
            resp = self.client.post("/config/save-ai-features", headers={"X-CSRF-Token": "token"}, json={
                "default_model": "gpt-4o-mini",
                "providers": {"openai": {"enabled": False},
                              "local": {"enabled": True, "url": "http://127.0.0.1:11434/v1", "model": "llama3.1:8b"},
                              "default": "local"}})
        self.assertEqual(resp.get_json(), {"ok": True})
        save_features.assert_not_called()
        saved = _keyvals(self.target)
        self.assertEqual((saved["LOCAL_LLM_ENABLED"], saved["LOCAL_LLM_URL"], saved["LLM_DEFAULT_PROVIDER"]),
                         (True, "http://127.0.0.1:11434/v1", "local"))

    def upload_logo(self, content, name="logo.png"):
        return self.client.post("/config/upload-logo", headers={"X-CSRF-Token": "token"},
                                data={"logo": (io.BytesIO(content), name)}, content_type="multipart/form-data")

    def test_a_logo_is_stored_and_its_upload_recorded(self):
        with mock.patch.object(config_page, "_UPLOADS_DIR", self.dir / "uploads"):
            resp = self.upload_logo(b"\x89PNG small")
        self.assertEqual(resp.get_json(), {"ok": True, "filename": "logo.png"})
        self.assertEqual((self.dir / "uploads" / "logo.png").read_bytes(), b"\x89PNG small")
        self.assertEqual(_keyvals(self.target)["BRAND_LOGO"], "logo.png")
        config_page.audit.record.assert_called_once_with("update", "config", details="logo uploaded")

    def test_a_logo_over_the_limit_is_refused_and_the_old_one_kept(self):
        """The Styling tab has always said 2 MB; nothing held an upload to it.
        A smaller limit stands in, since the test client leaves a large body's
        temporary file open."""
        self.assertEqual(config_page._LOGO_MAX_BYTES, 2 * 1024 * 1024)
        uploads = self.dir / "uploads"
        uploads.mkdir()
        (uploads / "logo.png").write_bytes(b"old")
        with mock.patch.object(config_page, "_UPLOADS_DIR", uploads), \
             mock.patch.object(config_page, "_LOGO_MAX_BYTES", 10):
            resp = self.upload_logo(b"x" * 11)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual((uploads / "logo.png").read_bytes(), b"old")

    def test_a_request_with_neither_features_nor_providers_is_refused(self):
        for body in ({"features": ["summary"]}, {}, {"providers": "local"}):
            with self.subTest(body=body):
                resp = self.client.post("/config/save-ai-features", headers={"X-CSRF-Token": "token"}, json=body)
                self.assertEqual(resp.status_code, 400)
        config_page.audit.record.assert_not_called()


if __name__ == "__main__":
    unittest.main()
