import argparse
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .enrollment import (
    EnrollmentError,
    create_relay_challenge,
    peer_proof_payload,
    verify_enrollment_receipt,
)
from .relay_receiver import RelayReceiverConfig, RelayReceiverError


SCHEMA_VERSION = 1
STATE_NAME = "relay-enrollment.json"
CONFIG_NAME = "relay-receiver.json"
CA_NAME = "relay-ca.pem"
CA_KEY_NAME = "relay-ca-key.pem"
CERT_NAME = "relay-cert.pem"
KEY_NAME = "relay-key.pem"
DEVICE_ID_PATTERN = re.compile(r"^phm_[a-z2-7]{26}$")
PUBLIC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
PAIRING_CODE_PATTERN = re.compile(
    r"^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{5}-"
    r"[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{5}$"
)
RELAY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
PEER_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class RelayConfigurationError(RuntimeError):
    pass


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise RelayConfigurationError("invalid encoded key")
    try:
        return base64.b64decode(
            (value + "=" * (-len(value) % 4)).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise RelayConfigurationError("invalid encoded key") from exc


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _device_id(public_key: bytes) -> str:
    token = base64.b32encode(hashlib.sha256(public_key).digest()).decode(
        "ascii"
    ).rstrip("=").lower()
    return "phm_{}".format(token[:26])


def _read_json(path: Path, label: str) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RelayConfigurationError("{} could not be read".format(label)) from exc
    if not isinstance(document, dict):
        raise RelayConfigurationError("invalid {}".format(label))
    return document


def _write_private_json(
    path: Path,
    document: dict,
    overwrite=True,
    secure_parent=True,
) -> None:
    if secure_parent:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
    elif not path.parent.is_dir():
        raise RelayConfigurationError(
            "output parent directory was not found: {}".format(path.parent)
        )
    if path.exists() and not overwrite:
        raise RelayConfigurationError("refusing to overwrite {}".format(path))
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _write_file(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    os.chmod(path, mode)


class RelayConfigurationManager:
    def __init__(self, directory: Path):
        self.directory = directory.expanduser().resolve()
        self.state_path = self.directory / STATE_NAME
        self.config_path = self.directory / CONFIG_NAME
        self.lock_path = self.directory / ".configuration.lock"

    def initialize(
        self,
        relay_id: str,
        peer_id: str = "printerhmi-relay",
        listen_port: int = 8443,
    ) -> dict:
        if not isinstance(relay_id, str) or not RELAY_ID_PATTERN.fullmatch(relay_id):
            raise RelayConfigurationError("invalid relay identifier")
        if not isinstance(peer_id, str) or not PEER_ID_PATTERN.fullmatch(peer_id):
            raise RelayConfigurationError("invalid relay peer identifier")
        if (
            not isinstance(listen_port, int)
            or isinstance(listen_port, bool)
            or not 1 <= listen_port <= 65535
        ):
            raise RelayConfigurationError("invalid relay listener port")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)

        with self._locked():
            unexpected = [
                item for item in self.directory.iterdir()
                if item != self.lock_path
            ]
            if unexpected:
                raise RelayConfigurationError(
                    "refusing to initialize a non-empty directory"
                )
            return self._initialize_locked(relay_id, peer_id, listen_port)

    def _initialize_locked(
        self,
        relay_id: str,
        peer_id: str,
        listen_port: int,
    ) -> dict:

        peer_private = Ed25519PrivateKey.generate()
        peer_private_bytes = peer_private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        peer_public_bytes = peer_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        now = datetime.now(timezone.utc)
        state = {
            "schema_version": SCHEMA_VERSION,
            "relay_id": relay_id,
            "peer_id": peer_id,
            "peer_public_key": _encode(peer_public_bytes),
            "peer_private_key": _encode(peer_private_bytes),
            "created_at": _timestamp(now),
            "pending_challenges": {},
        }

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        ca_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "PrinterHMI Remote Local CA")]
        )
        server_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
        )
        ca_certificate = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=None,
                    decipher_only=None,
                ),
                True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_key.public_key()
                ),
                False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        server_certificate = (
            x509.CertificateBuilder()
            .subject_name(server_name)
            .issuer_name(ca_name)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=397))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
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
                True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                        x509.IPAddress(ipaddress.ip_address("::1")),
                    ]
                ),
                False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
                False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_key.public_key()
                ),
                False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        ca_path = self.directory / CA_NAME
        ca_key_path = self.directory / CA_KEY_NAME
        cert_path = self.directory / CERT_NAME
        key_path = self.directory / KEY_NAME
        _write_file(
            ca_path,
            ca_certificate.public_bytes(serialization.Encoding.PEM),
            0o644,
        )
        _write_file(
            ca_key_path,
            ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            0o600,
        )
        _write_file(
            cert_path,
            server_certificate.public_bytes(serialization.Encoding.PEM),
            0o644,
        )
        _write_file(
            key_path,
            server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            0o600,
        )
        _write_private_json(self.state_path, state, overwrite=False)
        config = {
            "schema_version": SCHEMA_VERSION,
            "enabled": False,
            "relay_id": relay_id,
            "listen_host": "127.0.0.1",
            "listen_port": listen_port,
            "api_socket": "runtime/receiver.sock",
            "state_file": "runtime/latest.json",
            "cert_file": CERT_NAME,
            "key_file": KEY_NAME,
            "stale_after": 30,
            "devices": [],
        }
        _write_private_json(self.config_path, config, overwrite=False)
        return self._status_unlocked()

    def create_enrollment_request(self, offer_path: Path, output: Path) -> dict:
        with self._locked():
            return self._create_enrollment_request_locked(offer_path, output)

    def _create_enrollment_request_locked(
        self, offer_path: Path, output: Path
    ) -> dict:
        state = self._load_state()
        offer = _read_json(offer_path, "pairing offer")
        expected = {
            "schema_version",
            "pairing_id",
            "device_id",
            "device_public_key",
            "code",
            "expires_at",
        }
        if set(offer) != expected or offer.get("schema_version") != 1:
            raise RelayConfigurationError("invalid pairing offer")
        try:
            pairing_id = str(uuid.UUID(offer["pairing_id"]))
        except (ValueError, TypeError, AttributeError) as exc:
            raise RelayConfigurationError("invalid pairing offer") from exc
        if pairing_id != offer["pairing_id"]:
            raise RelayConfigurationError("invalid pairing offer")
        device_id = offer.get("device_id")
        public_key = offer.get("device_public_key")
        key_bytes = _decode(public_key)
        if (
            not isinstance(device_id, str)
            or not DEVICE_ID_PATTERN.fullmatch(device_id)
            or not isinstance(public_key, str)
            or not PUBLIC_KEY_PATTERN.fullmatch(public_key)
            or len(key_bytes) != 32
            or _device_id(key_bytes) != device_id
            or not isinstance(offer.get("code"), str)
            or not PAIRING_CODE_PATTERN.fullmatch(offer["code"])
        ):
            raise RelayConfigurationError("invalid pairing offer")
        expires_at = offer.get("expires_at")
        if not isinstance(expires_at, str) or not expires_at.endswith("Z"):
            raise RelayConfigurationError("invalid pairing offer expiry")
        try:
            expires = datetime.fromisoformat(
                expires_at[:-1] + "+00:00"
            )
        except (ValueError, TypeError, AttributeError) as exc:
            raise RelayConfigurationError("invalid pairing offer expiry") from exc
        if expires <= datetime.now(timezone.utc):
            raise RelayConfigurationError("pairing offer has expired")

        challenge = create_relay_challenge(device_id, state["relay_id"], 300)
        proof = peer_proof_payload(
            challenge,
            pairing_id,
            state["peer_id"],
            device_id,
        )
        private_key = Ed25519PrivateKey.from_private_bytes(
            _decode(state["peer_private_key"])
        )
        request = {
            "schema_version": 1,
            "type": "relay.enrollment-request",
            "challenge": challenge,
            "pairing_id": pairing_id,
            "code": offer["code"],
            "peer_id": state["peer_id"],
            "peer_public_key": state["peer_public_key"],
            "peer_signature": _encode(private_key.sign(proof)),
        }
        output = output.expanduser().resolve()
        _write_private_json(
            output,
            request,
            overwrite=False,
            secure_parent=False,
        )
        state["pending_challenges"][challenge["challenge_id"]] = {
            "device_id": device_id,
            "device_public_key": public_key,
            "expires_at": challenge["expires_at"],
        }
        _write_private_json(self.state_path, state)
        return {
            "request": str(output),
            "challenge_id": challenge["challenge_id"],
            "device_id": device_id,
            "expires_at": challenge["expires_at"],
        }

    def add_receipt(self, receipt_path: Path) -> dict:
        with self._locked():
            return self._add_receipt_locked(receipt_path)

    def _add_receipt_locked(self, receipt_path: Path) -> dict:
        state = self._load_state()
        config = self._load_config()
        receipt = _read_json(receipt_path, "enrollment receipt")
        try:
            verified = verify_enrollment_receipt(receipt)
        except EnrollmentError as exc:
            raise RelayConfigurationError("invalid enrollment receipt") from exc
        if (
            verified["relay_id"] != state["relay_id"]
            or verified["peer_id"] != state["peer_id"]
            or verified["peer_public_key"] != state["peer_public_key"]
        ):
            raise RelayConfigurationError(
                "enrollment receipt is not addressed to this relay"
            )
        pending = state["pending_challenges"].get(verified["challenge_id"])
        if (
            pending is None
            or pending["device_id"] != verified["device_id"]
            or pending["device_public_key"] != verified["device_public_key"]
        ):
            raise RelayConfigurationError(
                "enrollment receipt does not match a pending challenge"
            )
        device = {
            "device_id": verified["device_id"],
            "public_key": verified["device_public_key"],
        }
        existing = {
            item["device_id"]: item for item in config["devices"]
        }.get(device["device_id"])
        if existing is not None and existing != device:
            raise RelayConfigurationError("enrolled device key conflict")
        if existing is None:
            config["devices"].append(device)
            config["devices"].sort(key=lambda item: item["device_id"])
            self._save_config(config)
        state["pending_challenges"].pop(verified["challenge_id"], None)
        _write_private_json(self.state_path, state)
        self._validate_config(allow_disabled=True)
        return {
            "device_id": device["device_id"],
            "device_count": len(config["devices"]),
            "already_enrolled": existing is not None,
        }

    def set_enabled(self, enabled: bool, confirmed=False) -> dict:
        with self._locked():
            return self._set_enabled_locked(enabled, confirmed)

    def _set_enabled_locked(self, enabled: bool, confirmed=False) -> dict:
        if enabled and not confirmed:
            raise RelayConfigurationError("enabling requires explicit confirmation")
        config = self._load_config()
        if enabled and not config["devices"]:
            raise RelayConfigurationError("cannot enable without enrolled devices")
        config["enabled"] = enabled
        self._save_config(config)
        return self._status_unlocked()

    def remove_device(self, device_id: str, confirmed=False) -> dict:
        with self._locked():
            return self._remove_device_locked(device_id, confirmed)

    def _remove_device_locked(self, device_id: str, confirmed=False) -> dict:
        if not confirmed:
            raise RelayConfigurationError("device removal requires confirmation")
        config = self._load_config()
        retained = [
            item for item in config["devices"] if item["device_id"] != device_id
        ]
        if len(retained) == len(config["devices"]):
            raise RelayConfigurationError("enrolled device was not found")
        if config["enabled"] and not retained:
            raise RelayConfigurationError(
                "disable the receiver before removing its final device"
            )
        config["devices"] = retained
        self._save_config(config)
        return self._status_unlocked()

    def status(self) -> dict:
        with self._locked():
            return self._status_unlocked()

    def _status_unlocked(self) -> dict:
        state = self._load_state()
        config = self._load_config()
        return {
            "schema_version": 1,
            "relay_id": state["relay_id"],
            "peer_id": state["peer_id"],
            "peer_public_key": state["peer_public_key"],
            "enabled": config["enabled"],
            "listen_host": config["listen_host"],
            "listen_port": config["listen_port"],
            "device_count": len(config["devices"]),
            "devices": [item["device_id"] for item in config["devices"]],
            "pending_challenge_count": len(state["pending_challenges"]),
            "config": str(self.config_path),
            "ca_certificate": str(self.directory / CA_NAME),
        }

    def _load_state(self) -> dict:
        state = _read_json(self.state_path, "relay enrollment state")
        expected = {
            "schema_version",
            "relay_id",
            "peer_id",
            "peer_public_key",
            "peer_private_key",
            "created_at",
            "pending_challenges",
        }
        if set(state) != expected or state.get("schema_version") != 1:
            raise RelayConfigurationError("invalid relay enrollment state")
        if (
            not isinstance(state.get("relay_id"), str)
            or not RELAY_ID_PATTERN.fullmatch(state["relay_id"])
            or not isinstance(state.get("peer_id"), str)
            or not PEER_ID_PATTERN.fullmatch(state["peer_id"])
            or not isinstance(state.get("pending_challenges"), dict)
        ):
            raise RelayConfigurationError("invalid relay enrollment state")
        private_bytes = _decode(state["peer_private_key"])
        public_bytes = _decode(state["peer_public_key"])
        if len(private_bytes) != 32 or len(public_bytes) != 32:
            raise RelayConfigurationError("invalid relay enrollment identity")
        try:
            derived = Ed25519PrivateKey.from_private_bytes(
                private_bytes
            ).public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        except ValueError as exc:
            raise RelayConfigurationError("invalid relay enrollment identity") from exc
        if derived != public_bytes:
            raise RelayConfigurationError("relay enrollment identity does not match")
        os.chmod(self.state_path, 0o600)
        return state

    def _load_config(self) -> dict:
        config = _read_json(self.config_path, "relay receiver configuration")
        try:
            parsed = RelayReceiverConfig.load(self.config_path)
        except RelayReceiverError as exc:
            raise RelayConfigurationError(str(exc)) from exc
        state = self._load_state()
        if parsed.relay_id != state["relay_id"]:
            raise RelayConfigurationError(
                "receiver and enrollment relay identifiers do not match"
            )
        os.chmod(self.config_path, 0o600)
        return config

    def _validate_config(self, allow_disabled=False) -> RelayReceiverConfig:
        try:
            config = RelayReceiverConfig.load(self.config_path)
        except RelayReceiverError as exc:
            raise RelayConfigurationError(str(exc)) from exc
        if not allow_disabled and not config.enabled:
            raise RelayConfigurationError("relay receiver is disabled")
        return config

    def _save_config(self, document: dict) -> None:
        candidate = self.config_path.with_name(self.config_path.name + ".candidate")
        try:
            _write_private_json(candidate, document)
            try:
                parsed = RelayReceiverConfig.load(candidate)
            except RelayReceiverError as exc:
                raise RelayConfigurationError(str(exc)) from exc
            state = self._load_state()
            if parsed.relay_id != state["relay_id"]:
                raise RelayConfigurationError(
                    "receiver and enrollment relay identifiers do not match"
                )
            os.replace(candidate, self.config_path)
            os.chmod(self.config_path, 0o600)
        finally:
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass

    @contextlib.contextmanager
    def _locked(self):
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


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="printerhmi-relay-config")
    parser.add_argument(
        "action",
        choices=("init", "request", "add-receipt", "enable", "disable", "remove", "status"),
    )
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--relay-id")
    parser.add_argument("--peer-id", default="printerhmi-relay")
    parser.add_argument("--listen-port", type=int, default=8443)
    parser.add_argument("--offer", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--device-id")
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args(argv)
    manager = RelayConfigurationManager(args.directory)
    try:
        if args.action == "init":
            if args.relay_id is None:
                parser.error("init requires --relay-id")
            result = manager.initialize(
                args.relay_id, args.peer_id, args.listen_port
            )
        elif args.action == "request":
            if args.offer is None or args.output is None:
                parser.error("request requires --offer and --output")
            result = manager.create_enrollment_request(args.offer, args.output)
        elif args.action == "add-receipt":
            if args.receipt is None:
                parser.error("add-receipt requires --receipt")
            result = manager.add_receipt(args.receipt)
        elif args.action == "enable":
            result = manager.set_enabled(True, args.confirm)
        elif args.action == "disable":
            result = manager.set_enabled(False)
        elif args.action == "remove":
            if args.device_id is None:
                parser.error("remove requires --device-id")
            result = manager.remove_device(args.device_id, args.confirm)
        else:
            result = manager.status()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, EnrollmentError, RelayConfigurationError) as exc:
        print("ERROR: relay configuration: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
