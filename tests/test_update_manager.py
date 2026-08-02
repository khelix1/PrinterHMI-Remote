import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class UpdateManagerTests(unittest.TestCase):
    def test_template_matches_moonraker_git_repo_contract(self):
        template = (
            ROOT / "packaging/moonraker/printerhmi-remote-update.conf.in"
        ).read_text(encoding="utf-8")
        for required in (
            "[update_manager printerhmi-remote]",
            "type: git_repo",
            "channel: dev",
            "path: @REPO_DIR@",
            "origin: https://github.com/khelix1/PrinterHMI-Remote.git",
            "primary_branch: main",
            "virtualenv: @VIRTUALENV@",
            "requirements: requirements.txt",
            "managed_services: printerhmi-remote",
        ):
            self.assertIn(required, template)

    def test_installer_is_idempotent_and_requires_pristine_main(self):
        installer = (ROOT / "install-update-manager.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('branch --show-current', installer)
        self.assertIn('status --porcelain', installer)
        self.assertIn('grep -Fxq "$include_line"', installer)
        self.assertIn('grep -Fxq "$service_name"', installer)
        self.assertIn('moonraker.asvc', installer)
        self.assertIn('systemctl restart "$moonraker_service"', installer)

    def test_installer_waits_for_valid_exact_updater_revision(self):
        installer = (ROOT / "install-update-manager.sh").read_text(
            encoding="utf-8"
        )
        for required in (
            'moonraker_socket="$data_dir/comms/moonraker.sock"',
            '"machine.update.status"',
            'updater.get("is_valid") is True',
            'updater.get("branch") == "main"',
            'updater.get("is_dirty") is False',
            'updater.get("current_hash") == sys.argv[2]',
            "Moonraker Update Manager did not become ready",
        ):
            self.assertIn(required, installer)

    def test_multiple_instances_require_explicit_primary(self):
        installer = (ROOT / "install-update-manager.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("multiple Moonraker configurations found", installer)
        self.assertIn("--moonraker-config PATH", installer)

    def test_requirements_file_is_tracked_for_future_dependencies(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("cryptography>=42,<47", requirements)


if __name__ == "__main__":
    unittest.main()
