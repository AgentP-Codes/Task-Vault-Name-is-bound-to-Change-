"""Encryption with customer-held keys.

Everything the vault stores (cached records, secret values behind placeholders)
is encrypted with AES-256-GCM under a data key that the *customer* controls:

  * LocalKeyProvider - a key file on the customer's own machine or volume
  * KMSKeyProvider   - envelope encryption: the data key is wrapped by the
                       customer's cloud KMS key and only unwrapped in memory

Deleting or revoking the customer key makes every stored ciphertext unreadable
("crypto-shredding"). The vault never needs to see a key it isn't given.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import TaskvaultError


class KeyUnavailable(TaskvaultError):
    """Raised when a key is missing, revoked or wrong, or data was tampered with."""


KeyError_ = KeyUnavailable   # backwards-compatible name


class KeyProvider(Protocol):
    key_id: str

    def data_key(self) -> bytes: ...


class LocalKeyProvider:
    """A 256-bit key stored in a file only the customer controls (created 0600)."""

    def __init__(self, path: str | Path, create: bool = True):
        self.path = Path(path)
        if not self.path.exists():
            if not create:
                raise KeyError_(f"key file {self.path} not found")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(base64.b64encode(AESGCM.generate_key(bit_length=256)))
        self.key_id = "local:" + hashlib.sha256(str(self.path.resolve()).encode()).hexdigest()[:12]

    def data_key(self) -> bytes:
        if not self.path.exists():
            raise KeyError_("key has been destroyed; stored data is unreadable")
        return base64.b64decode(self.path.read_bytes())

    def shred(self) -> None:
        """Destroy the key. Everything encrypted under it becomes unreadable."""
        if self.path.exists():
            size = self.path.stat().st_size
            with self.path.open("r+b") as f:
                f.write(os.urandom(size))
            self.path.unlink()


class KMSKeyProvider:
    """Envelope encryption with a cloud KMS key the customer owns.

    `client` needs `encrypt(plaintext) -> bytes` and `decrypt(ciphertext) -> bytes`
    that call the customer's KMS (e.g. AWS KMS Encrypt/Decrypt with their key ARN).
    See `aws_kms_client()` for a ready-made AWS adapter.
    """

    def __init__(self, client: Any, wrapped_key_path: str | Path, key_id: str):
        self.client, self.key_id = client, f"kms:{key_id}"
        self.path = Path(wrapped_key_path)
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(client.encrypt(AESGCM.generate_key(bit_length=256)))
        self._cached: bytes | None = None

    def data_key(self) -> bytes:
        if self._cached is None:
            try:
                self._cached = self.client.decrypt(self.path.read_bytes())
            except Exception as e:  # noqa: BLE001 - KMS clients raise many types
                raise KeyError_(f"KMS refused to unwrap the data key: {e}") from e
        return self._cached

    def forget(self) -> None:
        """Drop the unwrapped key from memory (e.g. after the customer revokes access)."""
        self._cached = None


def aws_kms_client(key_arn: str, region: str | None = None):  # pragma: no cover - needs AWS
    import boto3  # optional dependency: pip install "taskvault[aws]"

    kms = boto3.client("kms", region_name=region)

    class _Client:
        def encrypt(self, plaintext: bytes) -> bytes:
            return kms.encrypt(KeyId=key_arn, Plaintext=plaintext)["CiphertextBlob"]

        def decrypt(self, ciphertext: bytes) -> bytes:
            return kms.decrypt(KeyId=key_arn, CiphertextBlob=ciphertext)["Plaintext"]

    return _Client()


class Cipher:
    """AES-256-GCM. Each message gets a fresh 96-bit nonce; `aad` binds context."""

    VERSION = b"\x01"

    def __init__(self, keys: KeyProvider):
        self.keys = keys

    def encrypt(self, value: Any, aad: str = "") -> bytes:
        nonce = os.urandom(12)
        body = json.dumps(value).encode()
        return self.VERSION + nonce + AESGCM(self.keys.data_key()).encrypt(nonce, body, aad.encode())

    def decrypt(self, blob: bytes, aad: str = "") -> Any:
        if blob[:1] != self.VERSION:
            raise KeyError_("unknown ciphertext version")
        try:
            body = AESGCM(self.keys.data_key()).decrypt(blob[1:13], blob[13:], aad.encode())
        except KeyError_:
            raise
        except Exception as e:  # InvalidTag: wrong key, wrong aad or tampering
            raise KeyError_("could not decrypt: wrong key, revoked key or tampered data") from e
        return json.loads(body)

    def fingerprint(self, value: Any) -> str:
        """Keyed fingerprint, so logs can correlate values without being brute-forceable."""
        mac = hmac.new(self.keys.data_key(), b"fp:" + str(value).encode(), hashlib.sha256)
        return mac.hexdigest()[:16]
