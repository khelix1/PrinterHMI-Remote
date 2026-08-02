import base64
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterator, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SCHEMA_VERSION = 1
PAIRING_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
PAIRING_CODE_LENGTH = 10
DEFAULT_PAIRING_TTL = 600
MIN_PAIRING_TTL = 60
MAX_PAIRING_TTL = 1800
PAIRING_ATTEMPTS = 5
PEER_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
RELAY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_CHALLENGE_LIFETIME = 300
CHALLENGE_CLOCK_SKEW = 30
CHALLENGE_SIGNATURE_DOMAIN = b"PrinterHMI Remote relay challenge response v1\x00"
PEER_PROOF_DOMAIN = b"PrinterHMI Remote peer enrollment proof v1\x00"
ENROLLMENT_RECEIPT_DOMAIN = b"PrinterHMI Remote enrollment receipt v1\x00"


class EnrollmentError(RuntimeError):
    pass


def default_enrollment_dir() -> Path:
    configured = os.environ.get("PRINTERHMI_ENROLLMENT_DIR")
    if configured:
        return Path(configured).expanduser()
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local/state"
    return base / "printerhmi-remote/enrollment"


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise EnrollmentError("invalid encoded value")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            (value + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise EnrollmentError("invalid encoded value") from exc


def _timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> float:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EnrollmentError("invalid relay challenge timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EnrollmentError("invalid relay challenge timestamp") from exc
    return parsed.timestamp()


def _canonical(document: dict) -> bytes:
    return json.dumps(
        document,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    ).encode("utf-8")


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _private_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _device_id(public_key: bytes) -> str:
    digest = hashlib.sha256(public_key).digest()
    token = base64.b32encode(digest).decode("ascii").rstrip("=").lower()
    return "phm_{}".format(token[:26])


def _fingerprint(public_key: bytes) -> str:
    digest = hashlib.sha256(public_key).hexdigest()
    return ":".join(digest[index:index + 2] for index in range(0, 32, 2))


def _code_digest(code: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        code.encode("ascii"),
        salt,
        250_000,
        dklen=32,
    )


def _normalize_code(code: str) -> str:
    if not isinstance(code, str):
        raise EnrollmentError("invalid or expired pairing code")
    normalized = code.replace("-", "").replace(" ", "").upper()
    if len(normalized) != PAIRING_CODE_LENGTH:
        raise EnrollmentError("invalid or expired pairing code")
    if any(character not in PAIRING_ALPHABET for character in normalized):
        raise EnrollmentError("invalid or expired pairing code")
    return normalized


def _validate_relay_challenge(
    challenge: dict,
    device_id: str,
    now: float,
) -> dict:
    expected_fields = {
        "schema_version",
        "type",
        "challenge_id",
        "relay_id",
        "nonce",
        "audience",
        "issued_at",
        "expires_at",
    }
    if not isinstance(challenge, dict) or set(challenge) != expected_fields:
        raise EnrollmentError("invalid relay challenge")
    if challenge.get("schema_version") != SCHEMA_VERSION:
        raise EnrollmentError("unsupported relay challenge version")
    if challenge.get("type") != "relay.challenge":
        raise EnrollmentError("invalid relay challenge type")
    challenge_id = challenge.get("challenge_id")
    try:
        parsed_challenge_id = uuid.UUID(challenge_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise EnrollmentError("invalid relay challenge identifier") from exc
    if str(parsed_challenge_id) != challenge_id:
        raise EnrollmentError("invalid relay challenge identifier")
    relay_id = challenge.get("relay_id")
    if not isinstance(relay_id, str) or not RELAY_ID_PATTERN.fullmatch(relay_id):
        raise EnrollmentError("invalid relay identifier")
    nonce = _b64decode(challenge.get("nonce", ""))
    if len(nonce) != 32:
        raise EnrollmentError("invalid relay challenge nonce")
    if challenge.get("audience") != device_id:
        raise EnrollmentError("relay challenge has the wrong audience")

    issued = _parse_timestamp(challenge["issued_at"])
    expires = _parse_timestamp(challenge["expires_at"])
    if expires <= issued or expires - issued > MAX_CHALLENGE_LIFETIME:
        raise EnrollmentError("invalid relay challenge lifetime")
    if issued > now + CHALLENGE_CLOCK_SKEW:
        raise EnrollmentError("relay challenge is not yet valid")
    if expires <= now:
        raise EnrollmentError("relay challenge has expired")
    return json.loads(json.dumps(challenge))


def peer_proof_payload(
    challenge: dict,
    pairing_id: str,
    peer_id: str,
    device_id: str,
) -> bytes:
    proof = {
        "schema_version": SCHEMA_VERSION,
        "type": "peer.enrollment-proof",
        "pairing_id": pairing_id,
        "peer_id": peer_id,
        "device_id": device_id,
        "challenge_id": challenge["challenge_id"],
        "relay_id": challenge["relay_id"],
        "nonce": challenge["nonce"],
    }
    return PEER_PROOF_DOMAIN + _canonical(proof)


def create_relay_challenge(
    device_id: str,
    relay_id: str,
    ttl_seconds: int = 120,
    clock: Callable[[], float] = time.time,
) -> dict:
    if not isinstance(device_id, str) or not device_id.startswith("phm_") or len(device_id) != 30:
        raise EnrollmentError("invalid challenge audience")
    if not isinstance(relay_id, str) or not RELAY_ID_PATTERN.fullmatch(relay_id):
        raise EnrollmentError("invalid relay identifier")
    if not 1 <= ttl_seconds <= MAX_CHALLENGE_LIFETIME:
        raise EnrollmentError("invalid relay challenge lifetime")
    now = clock()
    return {
        "schema_version": SCHEMA_VERSION,
        "type": "relay.challenge",
        "challenge_id": str(uuid.uuid4()),
        "relay_id": relay_id,
        "nonce": _b64encode(secrets.token_bytes(32)),
        "audience": device_id,
        "issued_at": _timestamp(now),
        "expires_at": _timestamp(now + ttl_seconds),
    }


class EnrollmentStore:
    def __init__(
        self,
        directory: Optional[Path] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.directory = directory or default_enrollment_dir()
        self.clock = clock
        self.identity_path = self.directory / "identity.json"
        self.state_path = self.directory / "state.json"
        self.audit_path = self.directory / "audit.jsonl"
        self.lock_path = self.directory / ".lock"

    def identity(self) -> dict:
        with self._locked():
            identity, _ = self._ensure_identity_locked()
            return self._public_identity(identity)

    def sign(self, payload: bytes) -> bytes:
        with self._locked():
            identity, private_key = self._ensure_identity_locked()
            del identity
            return private_key.sign(payload)

    def create_pairing(self, ttl_seconds: int = DEFAULT_PAIRING_TTL) -> dict:
        if not MIN_PAIRING_TTL <= ttl_seconds <= MAX_PAIRING_TTL:
            raise EnrollmentError(
                "pairing TTL must be between {} and {} seconds".format(
                    MIN_PAIRING_TTL, MAX_PAIRING_TTL
                )
            )
        with self._locked():
            identity, _ = self._ensure_identity_locked()
            state = self._load_state_locked()
            now = self.clock()
            self._prune_expired_locked(state, now)
            pairing_id = str(uuid.uuid4())
            code = "".join(
                secrets.choice(PAIRING_ALPHABET)
                for _ in range(PAIRING_CODE_LENGTH)
            )
            salt = secrets.token_bytes(16)
            expires = now + ttl_seconds
            state["pairings"][pairing_id] = {
                "created_at": _timestamp(now),
                "expires_at": _timestamp(expires),
                "expires_epoch": expires,
                "salt": _b64encode(salt),
                "code_digest": _b64encode(_code_digest(code, salt)),
                "attempts_remaining": PAIRING_ATTEMPTS,
            }
            self._write_json(self.state_path, state)
            self._audit_locked(
                "pairing.created",
                "success",
                pairing_id=pairing_id,
                expires_at=_timestamp(expires),
            )
            display_code = "{}-{}".format(code[:5], code[5:])
            public = self._public_identity(identity)
            return {
                "schema_version": SCHEMA_VERSION,
                "pairing_id": pairing_id,
                "device_id": public["device_id"],
                "device_public_key": public["public_key"],
                "code": display_code,
                "expires_at": _timestamp(expires),
            }

    def consume_pairing(
        self,
        pairing_id: str,
        code: str,
        peer_id: str,
        peer_public_key: str,
    ) -> dict:
        try:
            parsed_pairing_id = uuid.UUID(pairing_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise EnrollmentError("invalid or expired pairing code") from exc
        if str(parsed_pairing_id) != pairing_id:
            raise EnrollmentError("invalid or expired pairing code")
        if not isinstance(peer_id, str) or not PEER_ID_PATTERN.fullmatch(peer_id):
            raise EnrollmentError("invalid peer identifier")
        peer_key_bytes = _b64decode(peer_public_key)
        if len(peer_key_bytes) != 32:
            raise EnrollmentError("invalid peer public key")
        try:
            Ed25519PublicKey.from_public_bytes(peer_key_bytes)
        except ValueError as exc:
            raise EnrollmentError("invalid peer public key") from exc

        try:
            normalized_code = _normalize_code(code)
        except EnrollmentError:
            normalized_code = ""

        with self._locked():
            self._ensure_identity_locked()
            state = self._load_state_locked()
            peer = self._consume_pairing_locked(
                state,
                pairing_id,
                normalized_code,
                peer_id,
                peer_key_bytes,
                self.clock(),
            )
            return self._public_peer(peer)

    def sign_relay_challenge(self, challenge: dict) -> dict:
        with self._locked():
            identity, private_key = self._ensure_identity_locked()
            now = self.clock()
            normalized = _validate_relay_challenge(
                challenge, identity["device_id"], now
            )
            response = {
                "schema_version": SCHEMA_VERSION,
                "type": "agent.challenge-response",
                "challenge": normalized,
                "device_id": identity["device_id"],
                "device_public_key": identity["public_key"],
                "signed_at": _timestamp(now),
            }
            response["signature"] = _b64encode(
                private_key.sign(
                    CHALLENGE_SIGNATURE_DOMAIN + _canonical(response)
                )
            )
            self._audit_locked(
                "relay.challenge.signed",
                "success",
                challenge_id=normalized["challenge_id"],
                relay_id=normalized["relay_id"],
            )
            return response

    def complete_relay_enrollment(self, request_document: dict) -> dict:
        required_fields = {
            "schema_version",
            "type",
            "challenge",
            "pairing_id",
            "code",
            "peer_id",
            "peer_public_key",
            "peer_signature",
        }
        if (
            not isinstance(request_document, dict)
            or set(request_document) != required_fields
            or request_document.get("schema_version") != SCHEMA_VERSION
            or request_document.get("type") != "relay.enrollment-request"
        ):
            raise EnrollmentError("invalid relay enrollment request")

        pairing_id = request_document["pairing_id"]
        try:
            parsed_pairing_id = uuid.UUID(pairing_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise EnrollmentError("invalid relay enrollment request") from exc
        if str(parsed_pairing_id) != pairing_id:
            raise EnrollmentError("invalid relay enrollment request")
        peer_id = request_document["peer_id"]
        if not isinstance(peer_id, str) or not PEER_ID_PATTERN.fullmatch(peer_id):
            raise EnrollmentError("invalid peer identifier")
        try:
            normalized_code = _normalize_code(request_document["code"])
        except EnrollmentError:
            normalized_code = ""
        peer_key_bytes = _b64decode(request_document["peer_public_key"])
        peer_signature = _b64decode(request_document["peer_signature"])
        if len(peer_key_bytes) != 32 or len(peer_signature) != 64:
            raise EnrollmentError("invalid peer enrollment proof")
        try:
            peer_key = Ed25519PublicKey.from_public_bytes(peer_key_bytes)
        except ValueError as exc:
            raise EnrollmentError("invalid peer enrollment proof") from exc

        with self._locked():
            identity, private_key = self._ensure_identity_locked()
            now = self.clock()
            challenge = _validate_relay_challenge(
                request_document["challenge"], identity["device_id"], now
            )
            state = self._load_state_locked()
            self._prune_used_challenges_locked(state, now)
            challenge_id = challenge["challenge_id"]
            if challenge_id in state["used_challenges"]:
                raise EnrollmentError("relay challenge has already been used")

            proof_payload = peer_proof_payload(
                challenge, pairing_id, peer_id, identity["device_id"]
            )
            try:
                peer_key.verify(peer_signature, proof_payload)
            except InvalidSignature as exc:
                self._audit_locked(
                    "relay.enrollment.completed",
                    "rejected",
                    challenge_id=challenge_id,
                    relay_id=challenge["relay_id"],
                    peer_id=peer_id,
                )
                raise EnrollmentError("invalid peer enrollment proof") from exc

            peer = self._consume_pairing_locked(
                state,
                pairing_id,
                normalized_code,
                peer_id,
                peer_key_bytes,
                now,
                persist_success=False,
            )
            state["used_challenges"][challenge_id] = {
                "relay_id": challenge["relay_id"],
                "expires_epoch": _parse_timestamp(challenge["expires_at"]),
                "used_at": _timestamp(now),
            }
            self._write_json(self.state_path, state)
            self._audit_locked(
                "pairing.consumed",
                "success",
                pairing_id=pairing_id,
                peer_id=peer_id,
                peer_fingerprint=peer["fingerprint"],
            )

            receipt = {
                "schema_version": SCHEMA_VERSION,
                "type": "agent.enrollment-receipt",
                "challenge_id": challenge_id,
                "relay_id": challenge["relay_id"],
                "pairing_id": pairing_id,
                "device_id": identity["device_id"],
                "device_public_key": identity["public_key"],
                "peer_id": peer_id,
                "peer_public_key": peer["public_key"],
                "enrolled_at": _timestamp(now),
            }
            receipt["signature"] = _b64encode(
                private_key.sign(
                    ENROLLMENT_RECEIPT_DOMAIN + _canonical(receipt)
                )
            )
            self._audit_locked(
                "relay.enrollment.completed",
                "success",
                challenge_id=challenge_id,
                relay_id=challenge["relay_id"],
                pairing_id=pairing_id,
                peer_id=peer_id,
                peer_fingerprint=peer["fingerprint"],
            )
            return receipt

    def list_peers(self) -> list:
        with self._locked():
            self._ensure_identity_locked()
            state = self._load_state_locked()
            return [
                self._public_peer(peer)
                for _, peer in sorted(state["peers"].items())
            ]

    def revoke_peer(self, peer_id: str) -> dict:
        with self._locked():
            self._ensure_identity_locked()
            state = self._load_state_locked()
            peer = state["peers"].get(peer_id)
            if peer is None or peer.get("revoked_at") is not None:
                raise EnrollmentError("active peer not found")
            peer["revoked_at"] = _timestamp(self.clock())
            self._write_json(self.state_path, state)
            self._audit_locked(
                "peer.revoked", "success", peer_id=peer_id,
                peer_fingerprint=peer["fingerprint"]
            )
            return self._public_peer(peer)

    def rotate_identity(self, confirmed: bool = False) -> dict:
        if not confirmed:
            raise EnrollmentError("identity rotation requires explicit confirmation")
        with self._locked():
            old_identity, _ = self._ensure_identity_locked()
            state = self._load_state_locked()
            previous_device_id = old_identity["device_id"]
            identity, _ = self._generate_identity_locked(
                generation=int(old_identity.get("generation", 1)) + 1
            )
            state["pairings"] = {}
            state["peers"] = {}
            state["used_challenges"] = {}
            self._write_json(self.state_path, state)
            self._audit_locked(
                "identity.rotated",
                "success",
                previous_device_id=previous_device_id,
                device_id=identity["device_id"],
            )
            return self._public_identity(identity)

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.chmod(self.lock_path, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _ensure_identity_locked(self):
        if not self.identity_path.exists():
            return self._generate_identity_locked(generation=1)
        identity = json.loads(self.identity_path.read_text(encoding="utf-8"))
        private_bytes = _b64decode(identity["private_key"])
        if len(private_bytes) != 32:
            raise EnrollmentError("stored device key is invalid")
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        public_bytes = _public_bytes(private_key.public_key())
        if _b64encode(public_bytes) != identity.get("public_key"):
            raise EnrollmentError("stored device identity does not match its key")
        if _device_id(public_bytes) != identity.get("device_id"):
            raise EnrollmentError("stored device identifier is invalid")
        os.chmod(self.identity_path, 0o600)
        return identity, private_key

    def _generate_identity_locked(self, generation: int):
        private_key = Ed25519PrivateKey.generate()
        public_bytes = _public_bytes(private_key.public_key())
        identity = {
            "schema_version": SCHEMA_VERSION,
            "device_id": _device_id(public_bytes),
            "public_key": _b64encode(public_bytes),
            "private_key": _b64encode(_private_bytes(private_key)),
            "fingerprint": _fingerprint(public_bytes),
            "algorithm": "Ed25519",
            "generation": generation,
            "created_at": _timestamp(self.clock()),
        }
        self._write_json(self.identity_path, identity)
        self._audit_locked(
            "identity.created",
            "success",
            device_id=identity["device_id"],
            generation=generation,
        )
        return identity, private_key

    def _load_state_locked(self) -> dict:
        if not self.state_path.exists():
            return {
                "schema_version": SCHEMA_VERSION,
                "pairings": {},
                "peers": {},
                "used_challenges": {},
            }
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        if state.get("schema_version") != SCHEMA_VERSION:
            raise EnrollmentError("unsupported enrollment state version")
        state.setdefault("pairings", {})
        state.setdefault("peers", {})
        state.setdefault("used_challenges", {})
        os.chmod(self.state_path, 0o600)
        return state

    def _prune_expired_locked(self, state: dict, now: float) -> None:
        expired = [
            pairing_id
            for pairing_id, pairing in state["pairings"].items()
            if pairing["expires_epoch"] <= now
        ]
        for pairing_id in expired:
            state["pairings"].pop(pairing_id, None)

    def _prune_used_challenges_locked(self, state: dict, now: float) -> None:
        expired = [
            challenge_id
            for challenge_id, challenge in state["used_challenges"].items()
            if challenge["expires_epoch"] <= now
        ]
        for challenge_id in expired:
            state["used_challenges"].pop(challenge_id, None)

    def _consume_pairing_locked(
        self,
        state: dict,
        pairing_id: str,
        normalized_code: str,
        peer_id: str,
        peer_key_bytes: bytes,
        now: float,
        persist_success: bool = True,
    ) -> dict:
        pairing = state["pairings"].get(pairing_id)
        if pairing is None or pairing["expires_epoch"] <= now:
            state["pairings"].pop(pairing_id, None)
            self._write_json(self.state_path, state)
            self._audit_locked(
                "pairing.consumed", "rejected", pairing_id=pairing_id
            )
            raise EnrollmentError("invalid or expired pairing code")

        salt = _b64decode(pairing["salt"])
        candidate = (
            _code_digest(normalized_code, salt)
            if normalized_code
            else secrets.token_bytes(32)
        )
        expected = _b64decode(pairing["code_digest"])
        if not hmac.compare_digest(candidate, expected):
            pairing["attempts_remaining"] -= 1
            if pairing["attempts_remaining"] <= 0:
                state["pairings"].pop(pairing_id, None)
            self._write_json(self.state_path, state)
            self._audit_locked(
                "pairing.consumed", "rejected", pairing_id=pairing_id
            )
            raise EnrollmentError("invalid or expired pairing code")

        existing = state["peers"].get(peer_id)
        if existing is not None and existing.get("revoked_at") is None:
            state["pairings"].pop(pairing_id, None)
            self._write_json(self.state_path, state)
            self._audit_locked(
                "pairing.consumed",
                "rejected",
                pairing_id=pairing_id,
                peer_id=peer_id,
            )
            raise EnrollmentError("peer is already enrolled")

        state["pairings"].pop(pairing_id, None)
        peer = {
            "peer_id": peer_id,
            "public_key": _b64encode(peer_key_bytes),
            "fingerprint": _fingerprint(peer_key_bytes),
            "paired_at": _timestamp(now),
            "revoked_at": None,
        }
        state["peers"][peer_id] = peer
        if persist_success:
            self._write_json(self.state_path, state)
            self._audit_locked(
                "pairing.consumed",
                "success",
                pairing_id=pairing_id,
                peer_id=peer_id,
                peer_fingerprint=peer["fingerprint"],
            )
        return peer

    def _audit_locked(self, event: str, outcome: str, **details) -> None:
        record = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": _timestamp(self.clock()),
            "event": event,
            "outcome": outcome,
            "details": details,
        }
        descriptor = os.open(
            self.audit_path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        try:
            os.chmod(self.audit_path, 0o600)
            os.write(
                descriptor,
                (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"),
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _public_identity(identity: dict) -> dict:
        return {
            key: identity[key]
            for key in (
                "schema_version", "device_id", "public_key", "fingerprint",
                "algorithm", "generation", "created_at"
            )
        }

    @staticmethod
    def _public_peer(peer: dict) -> dict:
        return {
            key: peer[key]
            for key in (
                "peer_id", "public_key", "fingerprint", "paired_at", "revoked_at"
            )
        }

    @staticmethod
    def _write_json(path: Path, document: Dict) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            )
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)


def verify_signature(public_key: str, payload: bytes, signature: bytes) -> None:
    key_bytes = _b64decode(public_key)
    if len(key_bytes) != 32:
        raise EnrollmentError("invalid public key")
    Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature, payload)


def verify_challenge_response(
    response: dict,
    clock: Callable[[], float] = time.time,
) -> dict:
    expected_fields = {
        "schema_version",
        "type",
        "challenge",
        "device_id",
        "device_public_key",
        "signed_at",
        "signature",
    }
    if (
        not isinstance(response, dict)
        or set(response) != expected_fields
        or response.get("schema_version") != SCHEMA_VERSION
        or response.get("type") != "agent.challenge-response"
    ):
        raise EnrollmentError("invalid agent challenge response")
    public_bytes = _b64decode(response["device_public_key"])
    if len(public_bytes) != 32 or _device_id(public_bytes) != response["device_id"]:
        raise EnrollmentError("invalid agent challenge identity")
    now = clock()
    challenge = _validate_relay_challenge(
        response["challenge"], response["device_id"], now
    )
    signed_at = _parse_timestamp(response["signed_at"])
    if not (
        _parse_timestamp(challenge["issued_at"]) - CHALLENGE_CLOCK_SKEW
        <= signed_at
        < _parse_timestamp(challenge["expires_at"])
    ):
        raise EnrollmentError("invalid agent challenge response time")
    signature = _b64decode(response["signature"])
    if len(signature) != 64:
        raise EnrollmentError("invalid agent challenge signature")
    signed = dict(response)
    signed.pop("signature")
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature,
            CHALLENGE_SIGNATURE_DOMAIN + _canonical(signed),
        )
    except InvalidSignature as exc:
        raise EnrollmentError("invalid agent challenge signature") from exc
    return challenge


def verify_enrollment_receipt(receipt: dict) -> dict:
    expected_fields = {
        "schema_version",
        "type",
        "challenge_id",
        "relay_id",
        "pairing_id",
        "device_id",
        "device_public_key",
        "peer_id",
        "peer_public_key",
        "enrolled_at",
        "signature",
    }
    if (
        not isinstance(receipt, dict)
        or set(receipt) != expected_fields
        or receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("type") != "agent.enrollment-receipt"
    ):
        raise EnrollmentError("invalid enrollment receipt")
    public_bytes = _b64decode(receipt["device_public_key"])
    if len(public_bytes) != 32 or _device_id(public_bytes) != receipt["device_id"]:
        raise EnrollmentError("invalid enrollment receipt identity")
    signature = _b64decode(receipt["signature"])
    if len(signature) != 64:
        raise EnrollmentError("invalid enrollment receipt signature")
    signed = dict(receipt)
    signed.pop("signature")
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature,
            ENROLLMENT_RECEIPT_DOMAIN + _canonical(signed),
        )
    except InvalidSignature as exc:
        raise EnrollmentError("invalid enrollment receipt signature") from exc
    return signed
