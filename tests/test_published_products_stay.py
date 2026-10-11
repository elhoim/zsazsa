"""A published alert, advisory or detection engineering request stays as sent.

Their pages hid Delete and Edit once published, but the delete routes took the
request anyway, and the detection engineering list still offered both. The
threat actor profile and threat landscape routes already refused. MISP is
patched out.

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
    (flash_intel, "/products/flash-intel", "get_fia", "delete_fia", misp_store.FIA_REVIEW_APPROVED),
    (vea, "/products/vea", "get_vea", "delete_vea", misp_store.VEA_REVIEW_APPROVED),
    (detection_eng, "/products/detection-eng", "get_der", "delete_der", misp_store.DER_REVIEW_APPROVED),
]


class Delete(unittest.TestCase):
    def deleted(self, routes, prefix, getter, deleter, state):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(routes.bp)
        record = SimpleNamespace(review_state=state, fia_id="FIA-1", vea_id="VEA-1", der_id="DER-1")
        with mock.patch.object(misp_store, getter, return_value=record), \
             mock.patch.object(misp_store, deleter) as delete, \
             mock.patch.object(routes.audit, "record"):
            app.test_client().post(f"{prefix}/{UUID}/delete")
        return delete.called

    def test_a_published_product_is_refused(self):
        for routes, prefix, getter, deleter, approved in PRODUCTS:
            with self.subTest(product=prefix):
                self.assertFalse(self.deleted(routes, prefix, getter, deleter, approved))

    def test_a_draft_is_still_deleted(self):
        for routes, prefix, getter, deleter, _approved in PRODUCTS:
            with self.subTest(product=prefix):
                self.assertTrue(self.deleted(routes, prefix, getter, deleter, "draft"))


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
