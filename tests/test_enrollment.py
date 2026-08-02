import json
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from printerhmi_agent.enrollment import EnrollmentError, EnrollmentStore, verify_signature


def peer_key():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    import base64
    encoded = base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii")
    return private, encoded


class MutableClock:
    def __init__(self, value=1_800_000_000.0):
        self.value = value

    def __call__(self):
        return self.value


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.clock = MutableClock()
        self.directory = Path(self.temporary.name) / "enrollment"
        self.store = EnrollmentStore(self.directory, self.clock)

    def tearDown(self):
        self.temporary.cleanup()

    def test_identity_is_stable_private_and_signs(self):
        first = self.store.identity()
        second = self.store.identity()
        self.assertEqual(first, second)
        self.assertEqual(first["algorithm"], "Ed25519")
        self.assertNotIn("private_key", first)
        self.assertEqual(
            stat.S_IMODE(self.store.identity_path.stat().st_mode), 0o600
        )
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        payload = b"printerhmi-enrollment-challenge"
        verify_signature(first["public_key"], payload, self.store.sign(payload))

    def test_pairing_is_one_time_and_enrolls_peer(self):
        offer = self.store.create_pairing(120)
        _, public_key = peer_key()
        peer = self.store.consume_pairing(
            offer["pairing_id"], offer["code"], "browser-one", public_key
        )
        self.assertEqual(peer["peer_id"], "browser-one")
        self.assertIsNone(peer["revoked_at"])
        with self.assertRaises(EnrollmentError):
            self.store.consume_pairing(
                offer["pairing_id"], offer["code"], "browser-two", public_key
            )

    def test_pairing_expires(self):
        offer = self.store.create_pairing(60)
        self.clock.value += 61
        _, public_key = peer_key()
        with self.assertRaisesRegex(EnrollmentError, "invalid or expired"):
            self.store.consume_pairing(
                offer["pairing_id"], offer["code"], "late-peer", public_key
            )

    def test_failed_attempts_exhaust_pairing_without_audit_secrets(self):
        offer = self.store.create_pairing(120)
        _, public_key = peer_key()
        for _ in range(5):
            with self.assertRaisesRegex(EnrollmentError, "invalid or expired"):
                self.store.consume_pairing(
                    offer["pairing_id"], "22222-22222", "peer", public_key
                )
        with self.assertRaises(EnrollmentError):
            self.store.consume_pairing(
                offer["pairing_id"], offer["code"], "peer", public_key
            )
        audit = self.store.audit_path.read_text(encoding="utf-8")
        self.assertNotIn(offer["code"], audit)
        identity_document = self.store.identity_path.read_text(encoding="utf-8")
        private_key = json.loads(identity_document)["private_key"]
        self.assertNotIn(private_key, audit)

    def test_revocation_and_rotation(self):
        identity = self.store.identity()
        offer = self.store.create_pairing(120)
        _, public_key = peer_key()
        self.store.consume_pairing(
            offer["pairing_id"], offer["code"], "phone", public_key
        )
        revoked = self.store.revoke_peer("phone")
        self.assertIsNotNone(revoked["revoked_at"])
        with self.assertRaises(EnrollmentError):
            self.store.rotate_identity()
        rotated = self.store.rotate_identity(confirmed=True)
        self.assertNotEqual(identity["device_id"], rotated["device_id"])
        self.assertEqual(rotated["generation"], 2)
        self.assertEqual(self.store.list_peers(), [])


if __name__ == "__main__":
    unittest.main()
