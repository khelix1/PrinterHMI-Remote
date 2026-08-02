import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ServiceInstallationTests(unittest.TestCase):
    def test_system_unit_is_boot_persistent_and_local_only(self):
        unit = (
            ROOT / "packaging/systemd/printerhmi-remote.service.in"
        ).read_text(encoding="utf-8")
        for required in (
            "User=@SERVICE_USER@",
            "Group=@SERVICE_GROUP@",
            "PrivateNetwork=true",
            "ProtectSystem=strict",
            "RestrictAddressFamilies=AF_UNIX",
            "ReadWritePaths=@STATE_DIR@",
            "WantedBy=multi-user.target",
        ):
            self.assertIn(required, unit)
        self.assertNotIn("WantedBy=default.target", unit)

    def test_installer_creates_state_directory_before_start(self):
        installer = (ROOT / "install-service.sh").read_text(encoding="utf-8")
        create_at = installer.index("sudo install -d")
        start_at = installer.index('sudo systemctl enable --now')
        self.assertLess(create_at, start_at)
        self.assertIn('/etc/systemd/system/$service_name', installer)


if __name__ == "__main__":
    unittest.main()
