import json
import tempfile
import unittest
from pathlib import Path

from printerhmi_agent.service import SnapshotStore


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_snapshot_store_writes_complete_document(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state" / "status.json"
            store = SnapshotStore(path)
            await store.update("instance-one", {"connected": True})
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["schema_version"], 1)
            self.assertTrue(document["instances"]["instance-one"]["connected"])
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    async def test_snapshot_store_coalesces_rapid_updates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            store = SnapshotStore(path, minimum_write_interval=60.0)

            await store.update("instance-one", {"sequence": 1})
            await store.update("instance-one", {"sequence": 2})

            first_document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                first_document["instances"]["instance-one"]["sequence"],
                1,
            )

            await store.flush()
            final_document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                final_document["instances"]["instance-one"]["sequence"],
                2,
            )


if __name__ == "__main__":
    unittest.main()
