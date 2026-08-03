import asyncio
import json
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from printerhmi_agent.enrollment import EnrollmentStore
from printerhmi_agent.relay_simulator import RelaySimulator
from printerhmi_agent.relay_transport import (
    BoundedSnapshotQueue,
    RelayConfig,
    RelayConnector,
    RelayTransportError,
    create_agent_hello,
    create_session_challenge,
    retry_delays,
    sanitize_snapshot,
    sign_session_challenge,
    validate_agent_hello,
    verify_session_auth,
)


def make_certificates(directory: Path, prefix: str = "relay"):
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "{}-ca.pem".format(prefix)
    cert_path = directory / "{}-cert.pem".format(prefix)
    key_path = directory / "{}-key.pem".format(prefix)
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


def snapshot_document():
    return {
        "schema_version": 1,
        "generated_at": "2026-08-03T00:00:00Z",
        "instances": {
            "printer-one": {
                "instance_id": "printer-one",
                "socket_path": "/home/operator/printer_data/comms/moonraker.sock",
                "connected": True,
                "captured_at": "2026-08-03T00:00:00Z",
                "error": None,
                "status": {
                    "print": {
                        "state": "printing",
                        "filename": "private-customer-job.gcode",
                        "message": "private message",
                        "progress": 0.5,
                    },
                    "temperatures": {"extruder": {"temperature": 210.0}},
                    "metadata": {"url": "https://private.invalid/job/1"},
                },
            }
        },
    }


class RelayTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def config(self, ca_path, port, relay_id="local-relay", server_name="localhost"):
        path = self.directory / "relay.json"
        path.write_text(
            json.dumps({
                "schema_version": 1,
                "enabled": True,
                "relay_id": relay_id,
                "host": "127.0.0.1",
                "port": port,
                "server_name": server_name,
                "ca_file": str(ca_path),
                "queue_capacity": 8,
                "connect_timeout": 2.0,
            }),
            encoding="utf-8",
        )
        return RelayConfig.load(path)

    def test_bounded_queue_keeps_latest_snapshots(self):
        async def exercise():
            queue = BoundedSnapshotQueue(2)
            queue.put_latest({"sequence": 1})
            queue.put_latest({"sequence": 2})
            queue.put_latest({"sequence": 3})
            self.assertEqual(queue.qsize(), 2)
            self.assertEqual(queue.dropped_count, 1)
            self.assertEqual((await queue.get())["sequence"], 2)
            self.assertEqual((await queue.get())["sequence"], 3)
        asyncio.run(exercise())

    def test_privacy_filter_removes_local_paths_and_job_identity(self):
        filtered = sanitize_snapshot(snapshot_document())
        serialized = json.dumps(filtered)
        self.assertNotIn("socket_path", serialized)
        self.assertNotIn("private-customer-job", serialized)
        self.assertNotIn("private message", serialized)
        self.assertNotIn("private.invalid", serialized)
        self.assertEqual(
            filtered["instances"]["printer-one"]["status"]["print"]["progress"],
            0.5,
        )

    def test_retry_policy_is_bounded(self):
        self.assertEqual(retry_delays(7), [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0])

    def test_agent_hello_is_strict_and_bound_to_enrolled_identity(self):
        store = EnrollmentStore(self.directory / "enrollment")
        hello = create_agent_hello(store)
        device_id = store.identity()["device_id"]
        self.assertEqual(validate_agent_hello(hello, device_id), device_id)

        extra = dict(hello)
        extra["hostname"] = "private-host"
        with self.assertRaisesRegex(RelayTransportError, "invalid agent hello"):
            validate_agent_hello(extra, device_id)

        other = EnrollmentStore(self.directory / "other-enrollment")
        with self.assertRaisesRegex(RelayTransportError, "not enrolled"):
            validate_agent_hello(hello, other.identity()["device_id"])

    def test_session_authentication_rejects_transcript_tampering(self):
        store = EnrollmentStore(self.directory / "enrollment")
        challenge = create_session_challenge(
            store.identity()["device_id"], "local-relay"
        )
        response = sign_session_challenge(store, challenge, "local-relay")
        verified = verify_session_auth(response, challenge)
        self.assertEqual(verified["device_id"], store.identity()["device_id"])
        response["signed_at"] = "2026-08-03T00:00:00Z"
        with self.assertRaises(RelayTransportError):
            verify_session_auth(response, challenge)

    def test_expired_session_challenge_is_rejected(self):
        store = EnrollmentStore(self.directory / "enrollment", clock=lambda: 1000.0)
        challenge = create_session_challenge(
            store.identity()["device_id"],
            "local-relay",
            lifetime=10,
            clock=lambda: 1000.0,
        )
        with self.assertRaisesRegex(RelayTransportError, "expired"):
            sign_session_challenge(
                store,
                challenge,
                "local-relay",
                clock=lambda: 1011.0,
            )

    def test_disabled_configuration_cannot_create_connector(self):
        ca_path, _cert_path, _key_path = make_certificates(self.directory)
        enabled = self.config(ca_path, 8443)
        disabled = RelayConfig(
            enabled=False,
            relay_id=enabled.relay_id,
            host=enabled.host,
            port=enabled.port,
            server_name=enabled.server_name,
            ca_file=enabled.ca_file,
        )
        with self.assertRaisesRegex(RelayTransportError, "disabled"):
            RelayConnector(disabled)

    def test_authenticated_tls_session_delivers_sanitized_snapshot(self):
        async def exercise():
            ca_path, cert_path, key_path = make_certificates(self.directory)
            store = EnrollmentStore(self.directory / "enrollment")
            simulator = RelaySimulator(
                cert_path, key_path, store.identity()["device_id"]
            )
            await simulator.start()
            try:
                _host, port = simulator.address
                result = await RelayConnector(
                    self.config(ca_path, port), store
                ).send_snapshot(snapshot_document())
                await asyncio.sleep(0)
                self.assertEqual(result["relay_id"], "local-relay")
                self.assertEqual(len(simulator.received), 1)
                received = json.dumps(simulator.received[0])
                self.assertNotIn("socket_path", received)
                self.assertNotIn("filename", received)
                self.assertEqual(simulator.errors, [])
            finally:
                await simulator.close()
        asyncio.run(exercise())

    def test_simulator_rejects_unenrolled_agent_before_challenge(self):
        async def exercise():
            ca_path, cert_path, key_path = make_certificates(self.directory)
            enrolled = EnrollmentStore(self.directory / "enrolled")
            unknown = EnrollmentStore(self.directory / "unknown")
            simulator = RelaySimulator(
                cert_path, key_path, enrolled.identity()["device_id"]
            )
            await simulator.start()
            try:
                _host, port = simulator.address
                with self.assertRaises(RelayTransportError):
                    await RelayConnector(
                        self.config(ca_path, port), unknown
                    ).send_snapshot(snapshot_document())
                await asyncio.sleep(0)
                self.assertTrue(
                    any("not enrolled" in error for error in simulator.errors)
                )
                self.assertEqual(simulator.received, [])
            finally:
                await simulator.close()
        asyncio.run(exercise())

    def test_untrusted_certificate_is_rejected(self):
        async def exercise():
            _ca_path, cert_path, key_path = make_certificates(self.directory, "real")
            wrong_ca, _wrong_cert, _wrong_key = make_certificates(
                self.directory, "wrong"
            )
            store = EnrollmentStore(self.directory / "enrollment")
            simulator = RelaySimulator(
                cert_path, key_path, store.identity()["device_id"]
            )
            await simulator.start()
            try:
                _host, port = simulator.address
                with self.assertRaisesRegex(RelayTransportError, "secure relay"):
                    await RelayConnector(
                        self.config(wrong_ca, port), store
                    ).send_snapshot(snapshot_document())
            finally:
                await simulator.close()
        asyncio.run(exercise())

    def test_hostname_and_configured_relay_identity_are_enforced(self):
        async def exercise():
            ca_path, cert_path, key_path = make_certificates(self.directory)
            store = EnrollmentStore(self.directory / "enrollment")
            simulator = RelaySimulator(
                cert_path, key_path, store.identity()["device_id"], "relay-a"
            )
            await simulator.start()
            try:
                _host, port = simulator.address
                with self.assertRaises(RelayTransportError):
                    await RelayConnector(
                        self.config(ca_path, port, "relay-a", "wrong.example"), store
                    ).send_snapshot(snapshot_document())
                with self.assertRaisesRegex(RelayTransportError, "identity"):
                    await RelayConnector(
                        self.config(ca_path, port, "relay-b"), store
                    ).send_snapshot(snapshot_document())
            finally:
                await simulator.close()
        asyncio.run(exercise())

    def test_session_schema_and_example_default_are_safe(self):
        root = Path(__file__).resolve().parents[1]
        schema = json.loads(
            (root / "protocol/relay-session-v1.schema.json").read_text()
        )
        self.assertEqual(schema["$defs"]["hello"]["additionalProperties"], False)
        example = json.loads((root / "config/relay.example.json").read_text())
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(example["enabled"])
        unit = (root / "packaging/systemd/printerhmi-remote.service.in").read_text()
        self.assertIn("PrivateNetwork=true", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", unit)
        project = (root / "pyproject.toml").read_text()
        self.assertIn(
            'printerhmi-relay-sim = "printerhmi_agent.relay_simulator:main"',
            project,
        )


if __name__ == "__main__":
    unittest.main()
