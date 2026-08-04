import asyncio
import json
import os
import ssl
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from printerhmi_agent.enrollment import EnrollmentStore
from printerhmi_agent.relay_configuration import (
    CA_NAME,
    CA_KEY_NAME,
    CERT_NAME,
    CONFIG_NAME,
    KEY_NAME,
    STATE_NAME,
    RelayConfigurationError,
    RelayConfigurationManager,
)
from printerhmi_agent.relay_receiver import RelayReceiverConfig


class RelayConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.directory = self.root / "relay"
        self.manager = RelayConfigurationManager(self.directory)

    def tearDown(self):
        self.temporary.cleanup()

    def initialize(self):
        return self.manager.initialize("relay-test", "relay-operator", 9443)

    def enroll_device(self):
        self.initialize()
        agent = EnrollmentStore(self.root / "agent")
        offer = agent.create_pairing(300)
        offer_path = self.root / "pairing-offer.json"
        offer_path.write_text(json.dumps(offer), encoding="utf-8")
        request_path = self.root / "enrollment-request.json"
        original_parent_mode = stat.S_IMODE(self.root.stat().st_mode)
        request_summary = self.manager.create_enrollment_request(
            offer_path, request_path
        )
        self.assertEqual(
            stat.S_IMODE(self.root.stat().st_mode), original_parent_mode
        )
        request = json.loads(request_path.read_text(encoding="utf-8"))
        receipt = agent.complete_relay_enrollment(request)
        receipt_path = self.root / "receipt.json"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        result = self.manager.add_receipt(receipt_path)
        return agent, offer, request_summary, receipt_path, result

    def test_init_generates_private_disabled_loopback_configuration(self):
        status = self.initialize()
        self.assertFalse(status["enabled"])
        self.assertEqual(status["device_count"], 0)
        self.assertEqual(status["listen_host"], "127.0.0.1")
        self.assertEqual(status["listen_port"], 9443)

        config = RelayReceiverConfig.load(self.directory / CONFIG_NAME)
        self.assertFalse(config.enabled)
        self.assertEqual(config.devices, {})
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        for name in (STATE_NAME, CONFIG_NAME, CA_KEY_NAME, KEY_NAME):
            self.assertEqual(
                stat.S_IMODE((self.directory / name).stat().st_mode), 0o600
            )
        for name in (CA_NAME, CERT_NAME):
            self.assertEqual(
                stat.S_IMODE((self.directory / name).stat().st_mode), 0o644
            )

        certificate = x509.load_pem_x509_certificate(
            (self.directory / CERT_NAME).read_bytes()
        )
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        self.assertIn("localhost", san.get_values_for_type(x509.DNSName))
        usage = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, usage)

    def test_generated_certificate_completes_verified_tls_handshake(self):
        async def exercise():
            self.initialize()
            config = RelayReceiverConfig.load(self.directory / CONFIG_NAME)

            async def handle(_reader, writer):
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(
                handle,
                "127.0.0.1",
                0,
                ssl=config.tls_context(),
            )
            try:
                port = server.sockets[0].getsockname()[1]
                context = ssl.create_default_context(
                    cafile=str(self.directory / CA_NAME)
                )
                _reader, writer = await asyncio.open_connection(
                    "127.0.0.1",
                    port,
                    ssl=context,
                    server_hostname="localhost",
                )
                self.assertIsNotNone(writer.get_extra_info("ssl_object"))
                writer.close()
                await writer.wait_closed()
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(exercise())

    def test_signed_receipt_builds_allowlist_and_explicit_enable(self):
        agent, offer, summary, request_path, result = self.enroll_device()
        del agent, request_path
        self.assertEqual(summary["device_id"], offer["device_id"])
        self.assertEqual(result["device_id"], offer["device_id"])
        self.assertEqual(result["device_count"], 1)
        self.assertFalse(result["already_enrolled"])
        self.assertEqual(
            stat.S_IMODE((self.root / "enrollment-request.json").stat().st_mode),
            0o600,
        )

        with self.assertRaisesRegex(RelayConfigurationError, "confirmation"):
            self.manager.set_enabled(True)
        enabled = self.manager.set_enabled(True, confirmed=True)
        self.assertTrue(enabled["enabled"])
        parsed = RelayReceiverConfig.load(self.directory / CONFIG_NAME)
        self.assertEqual(
            parsed.devices[offer["device_id"]], offer["device_public_key"]
        )

    def test_receipt_must_match_pending_challenge_and_local_peer(self):
        _agent, _offer, _summary, receipt_path, _result = self.enroll_device()
        with self.assertRaisesRegex(RelayConfigurationError, "pending challenge"):
            self.manager.add_receipt(receipt_path)

        document = json.loads(receipt_path.read_text(encoding="utf-8"))
        document["relay_id"] = "other-relay"
        receipt_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(RelayConfigurationError, "invalid enrollment"):
            self.manager.add_receipt(receipt_path)

    def test_enable_requires_device_and_final_removal_requires_disable(self):
        self.initialize()
        with self.assertRaisesRegex(RelayConfigurationError, "without enrolled"):
            self.manager.set_enabled(True, confirmed=True)

        _agent, offer, _summary, _receipt, _result = self._enroll_after_init()
        self.manager.set_enabled(True, confirmed=True)
        with self.assertRaisesRegex(RelayConfigurationError, "disable"):
            self.manager.remove_device(offer["device_id"], confirmed=True)
        self.manager.set_enabled(False)
        status = self.manager.remove_device(
            offer["device_id"], confirmed=True
        )
        self.assertEqual(status["device_count"], 0)

    def _enroll_after_init(self):
        agent = EnrollmentStore(self.root / "agent-two")
        offer = agent.create_pairing(300)
        offer_path = self.root / "offer-two.json"
        offer_path.write_text(json.dumps(offer), encoding="utf-8")
        request_path = self.root / "request-two.json"
        summary = self.manager.create_enrollment_request(offer_path, request_path)
        receipt = agent.complete_relay_enrollment(
            json.loads(request_path.read_text(encoding="utf-8"))
        )
        receipt_path = self.root / "receipt-two.json"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        result = self.manager.add_receipt(receipt_path)
        return agent, offer, summary, receipt_path, result

    def test_initializer_refuses_overwrite_and_status_hides_private_key(self):
        self.initialize()
        with self.assertRaisesRegex(RelayConfigurationError, "non-empty"):
            self.manager.initialize("relay-test")
        serialized = json.dumps(self.manager.status())
        state = json.loads((self.directory / STATE_NAME).read_text())
        self.assertNotIn(state["peer_private_key"], serialized)
        self.assertNotIn("peer_private_key", serialized)

    def test_request_refuses_expired_or_overwritten_pairing_material(self):
        self.initialize()
        agent = EnrollmentStore(self.root / "agent-expired")
        offer = agent.create_pairing(300)
        offer["expires_at"] = "2000-01-01T00:00:00Z"
        offer_path = self.root / "expired.json"
        offer_path.write_text(json.dumps(offer), encoding="utf-8")
        output = self.root / "request.json"
        with self.assertRaisesRegex(RelayConfigurationError, "expired"):
            self.manager.create_enrollment_request(offer_path, output)
        offer["expires_at"] = "not-a-timestamp"
        offer_path.write_text(json.dumps(offer), encoding="utf-8")
        with self.assertRaisesRegex(RelayConfigurationError, "expiry"):
            self.manager.create_enrollment_request(offer_path, output)
        output.write_text("preserve", encoding="utf-8")
        offer = agent.create_pairing(300)
        offer_path.write_text(json.dumps(offer), encoding="utf-8")
        with self.assertRaisesRegex(RelayConfigurationError, "overwrite"):
            self.manager.create_enrollment_request(offer_path, output)
        self.assertEqual(output.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
