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
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise EnrollmentError("invalid encoded key") from exc


def _timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


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
    normalized = code.replace("-", "").replace(" ", "").upper()
    if len(normalized) != PAIRING_CODE_LENGTH:
        raise EnrollmentError("invalid or expired pairing code")
    if any(character not in PAIRING_ALPHABET for character in normalized):
        raise EnrollmentError("invalid or expired pairing code")
    return normalized


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
        if not PEER_ID_PATTERN.fullmatch(peer_id):
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
            now = self.clock()
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
            self._write_json(self.state_path, state)
            self._audit_locked(
                "pairing.consumed",
                "success",
                pairing_id=pairing_id,
                peer_id=peer_id,
                peer_fingerprint=peer["fingerprint"],
            )
            return self._public_peer(peer)

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
            return {"schema_version": SCHEMA_VERSION, "pairings": {}, "peers": {}}
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        if state.get("schema_version") != SCHEMA_VERSION:
            raise EnrollmentError("unsupported enrollment state version")
        state.setdefault("pairings", {})
        state.setdefault("peers", {})
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
