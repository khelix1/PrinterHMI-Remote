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
            "--api-socket @API_SOCKET@",
            "WantedBy=multi-user.target",
        ):
            self.assertIn(required, unit)
        self.assertNotIn("WantedBy=default.target", unit)

    def test_installer_uses_end_to_end_api_readiness_probe(self):
        installer = (ROOT / "install-service.sh").read_text(encoding="utf-8")
        self.assertIn('printerhmi-agent" api health', installer)
        self.assertIn("api_ready=true", installer)
        self.assertNotIn('[[ -S "$api_socket" ]]', installer)

    def test_installer_creates_state_directory_before_start(self):
        installer = (ROOT / "install-service.sh").read_text(encoding="utf-8")
        create_at = installer.index("sudo install -d")
        enable_at = installer.index('sudo systemctl enable "$service_name"')
        restart_at = installer.index('sudo systemctl restart "$service_name"')
        probe_at = installer.index('"$repo_dir/.venv/bin/printerhmi-agent" api health')
        self.assertLess(create_at, enable_at)
        self.assertLess(enable_at, restart_at)
        self.assertLess(restart_at, probe_at)
        self.assertIn('/etc/systemd/system/$service_name', installer)
        self.assertIn('@API_SOCKET@', installer)
        self.assertIn('sudo -u "$service_user"', installer)
        self.assertIn('api_ready=true', installer)
        self.assertNotIn('systemctl enable --now', installer)


if __name__ == "__main__":
    unittest.main()
