import json
import stat
import tempfile
import unittest
import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from printerhmi_agent.enrollment import (
    EnrollmentError,
    EnrollmentStore,
    create_relay_challenge,
    peer_proof_payload,
    verify_challenge_response,
    verify_enrollment_receipt,
    verify_signature,
)


def peer_key():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    encoded = base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii")
    return private, encoded


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


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

    def test_signed_relay_challenge_is_bound_to_device_and_transcript(self):
        identity = self.store.identity()
        challenge = create_relay_challenge(
            identity["device_id"], "relay-test", 120, self.clock
        )
        response = self.store.sign_relay_challenge(challenge)
        verified = verify_challenge_response(response, self.clock)
        self.assertEqual(verified, challenge)

        tampered = json.loads(json.dumps(response))
        tampered["challenge"]["relay_id"] = "relay-attacker"
        with self.assertRaisesRegex(EnrollmentError, "signature"):
            verify_challenge_response(tampered, self.clock)

    def test_expired_and_wrong_audience_challenges_are_rejected(self):
        identity = self.store.identity()
        challenge = create_relay_challenge(
            identity["device_id"], "relay-test", 60, self.clock
        )
        wrong = dict(challenge)
        wrong["audience"] = "phm_aaaaaaaaaaaaaaaaaaaaaaaaaa"
        with self.assertRaisesRegex(EnrollmentError, "wrong audience"):
            self.store.sign_relay_challenge(wrong)

        self.clock.value += 61
        with self.assertRaisesRegex(EnrollmentError, "expired"):
            self.store.sign_relay_challenge(challenge)

    def test_relay_enrollment_proves_peer_key_and_rejects_replay(self):
        identity = self.store.identity()
        offer = self.store.create_pairing(120)
        private_key, public_key = peer_key()
        challenge = create_relay_challenge(
            identity["device_id"], "relay-test", 120, self.clock
        )
        proof = peer_proof_payload(
            challenge,
            offer["pairing_id"],
            "browser-client",
            identity["device_id"],
        )
        request = {
            "schema_version": 1,
            "type": "relay.enrollment-request",
            "challenge": challenge,
            "pairing_id": offer["pairing_id"],
            "code": offer["code"],
            "peer_id": "browser-client",
            "peer_public_key": public_key,
            "peer_signature": encoded(private_key.sign(proof)),
        }
        receipt = self.store.complete_relay_enrollment(request)
        verified = verify_enrollment_receipt(receipt)
        self.assertEqual(verified["peer_id"], "browser-client")
        self.assertEqual(verified["challenge_id"], challenge["challenge_id"])

        with self.assertRaisesRegex(EnrollmentError, "already been used"):
            self.store.complete_relay_enrollment(request)

    def test_bad_peer_proof_does_not_consume_pairing(self):
        identity = self.store.identity()
        offer = self.store.create_pairing(120)
        private_key, public_key = peer_key()
        challenge = create_relay_challenge(
            identity["device_id"], "relay-test", 120, self.clock
        )
        proof = peer_proof_payload(
            challenge,
            offer["pairing_id"],
            "browser-client",
            identity["device_id"],
        )
        request = {
            "schema_version": 1,
            "type": "relay.enrollment-request",
            "challenge": challenge,
            "pairing_id": offer["pairing_id"],
            "code": offer["code"],
            "peer_id": "browser-client",
            "peer_public_key": public_key,
            "peer_signature": encoded(b"x" * 64),
        }
        with self.assertRaisesRegex(EnrollmentError, "peer enrollment proof"):
            self.store.complete_relay_enrollment(request)

        request["peer_signature"] = encoded(private_key.sign(proof))
        receipt = self.store.complete_relay_enrollment(request)
        self.assertEqual(receipt["peer_id"], "browser-client")


if __name__ == "__main__":
    unittest.main()
