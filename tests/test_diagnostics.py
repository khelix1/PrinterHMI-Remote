import json
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from printerhmi_agent.diagnostics import (
    collect_diagnostics,
    sanitize_text,
    write_support_bundle,
)


class DiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    def test_sanitizer_removes_sensitive_values(self):
        source = (
            str(Path.home()) + "/printer_data/config/printer.cfg "
            "http://192.168.1.20:7125/path api_key=supersecret "
            "filename=customer-part.gcode"
        )
        cleaned = sanitize_text(source)
        self.assertNotIn(str(Path.home()), cleaned)
        self.assertNotIn("192.168.1.20", cleaned)
        self.assertNotIn("supersecret", cleaned)
        self.assertNotIn("customer-part.gcode", cleaned)
        self.assertIn("<URL>", cleaned)

        named = sanitize_text(
            "ERROR: Customer-Printer private-id failed",
            ("Customer-Printer", "private-id"),
        )
        self.assertNotIn("Customer-Printer", named)
        self.assertNotIn("private-id", named)

    async def test_report_excludes_identifying_and_raw_state(self):
        async def requester(_socket, method):
            if method == "health":
                result = {
                    "agent_version": "test",
                    "instance_count": 1,
                    "telemetry_ready_count": 1,
                    "connected_count": 1,
                }
            elif method == "catalog":
                result = {"instances": [{
                    "instance_id": "private-id",
                    "hostname": "Customer-Printer",
                    "socket_path": "/home/customer/printer_data/comms/moonraker.sock",
                    "reachable": True,
                    "moonraker_version": "v0.10.0",
                    "klippy_state": "ready",
                }]}
            else:
                result = {"instances": {"private-id": {
                    "connected": True,
                    "captured_at": "now",
                    "status": {
                        "print": {"state": "printing", "filename": "secret.gcode"},
                        "temperatures": {"extruder": {"temperature": 200}},
                        "fans": {"fan": {"speed": 1}},
                    },
                }}}
            return {"ok": True, "result": result}

        def command(_args):
            return 0, "ActiveState=active\nSubState=running\n"

        with tempfile.TemporaryDirectory() as directory:
            report = await collect_diagnostics(
                Path(directory) / "agent.sock",
                Path(directory) / "status.json",
                requester=requester,
                command=command,
            )
        encoded = json.dumps(report)
        for forbidden in (
            "private-id",
            "Customer-Printer",
            "moonraker.sock",
            "secret.gcode",
            "/home/customer",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(report["printers"][0]["alias"], "printer-1")
        self.assertEqual(report["printers"][0]["temperature_device_count"], 1)

    async def test_bundle_is_private_and_contains_only_safe_files(self):
        report = {"diagnostics_schema_version": 1, "privacy": {}}
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "support.zip"
            result = write_support_bundle(report, destination)
            self.assertEqual(stat.S_IMODE(os.stat(result).st_mode), 0o600)
            with zipfile.ZipFile(result) as archive:
                self.assertEqual(
                    set(archive.namelist()),
                    {"diagnostics.json", "README.txt"},
                )
                loaded = json.loads(archive.read("diagnostics.json"))
                self.assertEqual(loaded["diagnostics_schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
