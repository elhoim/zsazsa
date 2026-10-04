"""The "Draft with AI" button on the threat actor profile form, and /api/draft-tap.

What the model returns goes into the form as it is, and the assessment
confidence lands in a select that only offers "low", "moderate" and "high". A
"High" or a "medium" selected nothing there while the page reported the field
as drafted. The model is patched out.

When MISP's galaxy cannot be read, the actor picker falls back to a tag input of
hidden fields, and the button sent no actors at all. There is no JavaScript test
runner here, so that is pinned on the template source.

    python -m unittest tests.test_tap_draft_api
"""

import unittest
from pathlib import Path
from unittest import mock

from flask import Flask

from webapp import rate_limit
from webapp.routes import api


class AssessmentConfidence(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(api.bp, url_prefix="/api")
        self.client = app.test_client()
        rate_limit._WINDOWS.clear()
        self.addCleanup(rate_limit._WINDOWS.clear)

    def draft(self, confidence):
        sections = {"summary": "An actor.", "assessment_confidence": confidence}
        with mock.patch("analyser.llm.draft_tap_sections", return_value=sections):
            reply = self.client.post("/api/draft-tap", json={"actors": ["APT29"]})
        return reply.get_json()["sections"]

    def test_it_is_brought_to_the_value_the_form_offers(self):
        self.assertEqual(self.draft(" High ")["assessment_confidence"], "high")

    def test_one_the_form_does_not_offer_is_left_out(self):
        self.assertEqual(self.draft("medium")["assessment_confidence"], "")

    def test_the_other_sections_are_untouched(self):
        self.assertEqual(self.draft("low")["summary"], "An actor.")


class TypedActors(unittest.TestCase):
    def test_the_draft_sends_actors_typed_into_the_fallback_picker(self):
        form = (Path(api.__file__).resolve().parent.parent / "templates"
                / "threat_actor_profile" / "form.html").read_text(encoding="utf-8")
        handler = form[form.index("var btn = document.getElementById('tap-draft-btn');"):]
        self.assertIn('input[type="hidden"][name="threat_actors"]', handler)


if __name__ == "__main__":
    unittest.main()
