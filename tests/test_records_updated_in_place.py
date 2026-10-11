"""Saving a record edits its stored MISP object rather than replacing it.

Daily briefings, flash intel alerts, vulnerability advisories, detection
engineering requests and collection sources were saved by deleting the object
and adding a new one. When the add failed, the record was left with no object
at all, and every save cluttered the event history. They now go through
_sync_object_attributes, as the other records do. MISP is a specced stand-in,
so a call PyMISP does not have fails here as it would against a server.

    python -m unittest tests.test_records_updated_in_place
"""

import unittest
from unittest import mock

from pymisp import MISPEvent, PyMISP

from webapp import misp_store

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"


class InPlace(unittest.TestCase):
    def store(self, stored):
        """A record event holding one stored object, served by a specced PyMISP."""
        event = MISPEvent()
        event.from_dict(uuid=UUID, id="42", info="record", date="2026-10-11")
        stored.id = 7  # as an object read back from MISP has
        event.Object.append(stored)
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = event
        for patcher in (mock.patch.object(misp_store, "_misp", return_value=misp),
                        mock.patch.object(misp_store.misp_session, "current_user_email",
                                          return_value="analyst@example.org")):
            patcher.start()
            self.addCleanup(patcher.stop)
        return misp

    def written(self, misp, stored):
        """The object MISP was asked to update, after checking nothing was replaced."""
        misp.delete_object.assert_not_called()
        misp.add_object.assert_not_called()
        obj = misp.update_object.call_args.args[0]
        self.assertEqual(obj.uuid, stored.uuid)
        return obj

    def test_a_daily_briefing(self):
        stored = misp_store._briefing_obj({"title": "Old", "date": "2026-10-11", "review_state": "draft"})
        misp = self.store(stored)
        misp_store.update_briefing(UUID, {"title": "New", "review_state": "draft", "stories": []})
        self.assertEqual(misp_store._obj_attr(self.written(misp, stored), "title"), "New")

    def test_publishing_a_daily_briefing(self):
        stored = misp_store._briefing_obj({"title": "Daily", "date": "2026-10-11", "review_state": "draft"})
        misp = self.store(stored)
        misp_store.publish_briefing(UUID)
        obj = self.written(misp, stored)
        self.assertEqual(misp_store._obj_attr(obj, "review-state"), misp_store.BRIEFING_REVIEW_PUBLISHED)
        self.assertEqual(misp_store._obj_attr(obj, "title"), "Daily")

    def test_a_flash_intel_alert(self):
        stored = misp_store._fia_obj({"fia_id": "FIA-0001", "title": "Old", "creator": "a@example.org"})
        misp = self.store(stored)
        misp_store.update_fia(UUID, {"title": "New", "tlp": "amber"})
        obj = self.written(misp, stored)
        self.assertEqual(misp_store._obj_attr(obj, "title"), "New")
        self.assertEqual(misp_store._obj_attr(obj, "creator"), "a@example.org")

    def test_a_vulnerability_advisory(self):
        stored = misp_store._vea_obj({"vea_id": "VEA-0001", "title": "Old", "cve_id": "CVE-2026-1"})
        misp = self.store(stored)
        misp_store.update_vea(UUID, {"title": "New", "cve_id": "CVE-2026-1"})
        self.assertEqual(misp_store._obj_attr(self.written(misp, stored), "title"), "New")

    def test_a_detection_engineering_request(self):
        stored = misp_store._der_obj({"der_id": "DER-0001", "title": "Old", "status": "pending"})
        misp = self.store(stored)
        misp_store.update_der(UUID, {"title": "New"})
        self.assertEqual(misp_store._obj_attr(self.written(misp, stored), "title"), "New")

    def test_an_approval_keeps_the_object_and_names_the_approver(self):
        stored = misp_store._fia_obj({"fia_id": "FIA-0001", "title": "Alert", "review_state": "draft"})
        misp = self.store(stored)
        misp_store.set_fia_review_state(UUID, misp_store.FIA_REVIEW_APPROVED)
        obj = self.written(misp, stored)
        self.assertEqual(misp_store._obj_attr(obj, "review-state"), misp_store.FIA_REVIEW_APPROVED)
        self.assertEqual(misp_store._obj_attr(obj, "approved-by"), "analyst@example.org")

    def test_a_collection_source(self):
        stored = misp_store._collection_source_obj({"name": "Old", "owner": "SOC"}, enabled=False)
        misp = self.store(stored)
        misp_store.update_collection_source(UUID, {"name": "New", "owner": "SOC"})
        obj = self.written(misp, stored)
        self.assertEqual(misp_store._obj_attr(obj, "name"), "New")
        self.assertEqual(misp_store._obj_attr(obj, "enabled"), "false", "a save keeps the source off")

    def test_switching_a_collection_source_off_keeps_its_fields(self):
        stored = misp_store._collection_source_obj({"name": "ISAC", "owner": "SOC", "description": "Mails",
                                                    "source_reliability": "B"})
        misp = self.store(stored)
        misp_store.toggle_collection_source(UUID, False)
        obj = self.written(misp, stored)
        self.assertEqual({a.object_relation: a.value for a in obj.attributes},
                         {"name": "ISAC", "owner": "SOC", "description": "Mails",
                          "source-reliability": "B", "enabled": "false"})

    def test_a_field_cleared_on_save_is_removed_from_the_stored_object(self):
        stored = misp_store._der_obj({"der_id": "DER-0001", "title": "Old", "hypothesis": "Was set"})
        for attr in stored.attributes:
            attr.uuid = f"{attr.object_relation}-uuid"
        misp = self.store(stored)
        misp_store.update_der(UUID, {"title": "Old"})
        self.written(misp, stored)
        deleted = [c.args[0] for c in misp.delete_attribute.call_args_list]
        self.assertIn("hypothesis-uuid", deleted)


if __name__ == "__main__":
    unittest.main()
