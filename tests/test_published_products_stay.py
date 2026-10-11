"""A published alert, advisory or detection engineering request stays as sent.

Their pages hid Delete and Edit once published, but the delete routes took the
request anyway, and the detection engineering list still offered both. The
alert and advisory reject routes took a published one too, which made it
editable and deletable again. The threat actor profile and threat landscape
routes already refused. MISP is patched out.

    python -m unittest tests.test_published_products_stay
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask
from pymisp import MISPEvent

import config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import detection_eng, flash_intel, vea

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"

PRODUCTS = [
    (flash_intel, "/products/flash-intel", "fia"),
    (vea, "/products/vea", "vea"),
    (detection_eng, "/products/detection-eng", "der"),
]


class DeleteAndReject(unittest.TestCase):
    def done(self, routes, prefix, kind, action, state):
        """Whether the store was asked to delete or reject a record in this state."""
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(routes.bp)
        record = SimpleNamespace(review_state=state, fia_id="FIA-1", vea_id="VEA-1", der_id="DER-1")
        with mock.patch.object(misp_store, f"get_{kind}", return_value=record), \
             mock.patch.object(misp_store, f"{action}_{kind}") as write, \
             mock.patch.object(routes.audit, "record"):
            app.test_client().post(f"{prefix}/{UUID}/{action}")
        return write.called

    def test_a_published_product_is_refused(self):
        for routes, prefix, kind in PRODUCTS:
            for action in ("delete", "reject"):
                with self.subTest(product=prefix, action=action):
                    self.assertFalse(self.done(routes, prefix, kind, action, "approved"))

    def test_a_draft_still_goes(self):
        for routes, prefix, kind in PRODUCTS:
            for action in ("delete", "reject"):
                with self.subTest(product=prefix, action=action):
                    self.assertTrue(self.done(routes, prefix, kind, action, "draft"))


class DetectionEngineeringList(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
                        mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
                        mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
                        mock.patch.object(collection_cache, "start_worker")):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def request(self, uuid, der_id, state):
        """A request as the store reads it back from MISP."""
        event = MISPEvent()
        event.from_dict(uuid=uuid, id="42", info=der_id, date="2026-10-11")
        event.Object.append(misp_store._der_obj({"der_id": der_id, "title": der_id, "review_state": state}))
        return misp_store._der_ns(event)

    def test_a_published_request_offers_neither_edit_nor_delete(self):
        published = self.request("a" * 36, "DER-1", misp_store.DER_REVIEW_APPROVED)
        draft = self.request("b" * 36, "DER-2", "draft")
        with mock.patch.object(misp_store, "list_ders", return_value=[published, draft]):
            page = BeautifulSoup(self.client.get("/products/detection-eng/").data, "html.parser")
        for uuid, offered in (("a" * 36, False), ("b" * 36, True)):
            with self.subTest(uuid=uuid[:1]):
                self.assertEqual(page.select_one(f'a[href="/products/detection-eng/{uuid}/edit"]') is not None,
                                 offered)
                self.assertEqual(page.select_one(f'form[action="/products/detection-eng/{uuid}/delete"]')
                                 is not None, offered)


if __name__ == "__main__":
    unittest.main()
