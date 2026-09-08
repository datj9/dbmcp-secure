"""Secret backends: OS keyring with encrypted-file fallback."""

import getpass
import json
import os
import sys
from pathlib import Path
from typing import Protocol

import click
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dbmcp.errors import BackendUnavailable, ConfigError
from dbmcp.profiles import config_dir


class SecretBackend(Protocol):
    def set_secret(self, profile_name: str, secret: str) -> None: ...
    def get_secret(self, profile_name: str) -> str | None: ...
    def delete_secret(self, profile_name: str) -> None: ...


class KeyringBackend:
    def __init__(self) -> None:
        self._kr = self._get_allowed_keyring()

    def set_secret(self, profile_name: str, secret: str) -> None:
        import keyring

        try:
            self._kr.set_password(f"dbmcp:{profile_name}", getpass.getuser(), secret)
        except (keyring.errors.KeyringLocked, keyring.errors.InitError) as exc:
            raise self._unavailable(exc) from exc

    def get_secret(self, profile_name: str) -> str | None:
        import keyring

        try:
            return self._kr.get_password(f"dbmcp:{profile_name}", getpass.getuser())
        except (keyring.errors.KeyringLocked, keyring.errors.InitError) as exc:
            raise self._unavailable(exc) from exc

    def delete_secret(self, profile_name: str) -> None:
        import keyring

        try:
            self._kr.delete_password(f"dbmcp:{profile_name}", getpass.getuser())
        except keyring.errors.PasswordDeleteError:
            return
        except (keyring.errors.KeyringLocked, keyring.errors.InitError) as exc:
            raise self._unavailable(exc) from exc

    @staticmethod
    def _unavailable(exc: BaseException) -> BackendUnavailable:
        # Static message: exception text is backend-owned and not scrubbed.
        return BackendUnavailable(
            f"keyring unavailable ({type(exc).__name__}); use --backend encrypted-file"
        )

    def _get_allowed_keyring(self):
        import keyring
        import keyring.backends.chainer
        import keyring.backends.fail
        import keyring.backends.kwallet
        import keyring.backends.macOS
        import keyring.backends.SecretService

        allowed = {
            keyring.backends.macOS.Keyring,
            keyring.backends.SecretService.Keyring,
            keyring.backends.kwallet.DBusKeyring,
        }

        kr = keyring.get_keyring()

        # Explicitly reject fail.Keyring and plaintext/encrypted file backends.
        if isinstance(kr, keyring.backends.fail.Keyring):
            raise BackendUnavailable(
                "keyring backend is fail.Keyring; use --backend encrypted-file"
            )
        try:
            import keyrings.alt.file  # type: ignore[import]
        except ImportError:
            pass
        else:
            plaintext = (keyrings.alt.file.PlaintextKeyring, keyrings.alt.file.EncryptedKeyring)
            if isinstance(kr, plaintext):
                raise BackendUnavailable(
                    "keyring backend is plaintext/encrypted file; use --backend encrypted-file"
                )

        if isinstance(kr, keyring.backends.chainer.ChainerBackend):
            if not all(type(member) in allowed for member in kr.backends):
                raise BackendUnavailable(
                    "keyring chainer contains disallowed backend; use --backend encrypted-file"
                )
            return kr

        if type(kr) not in allowed:
            raise BackendUnavailable(
                f"keyring backend {type(kr).__name__} not allowed; use --backend encrypted-file"
            )
        return kr


class EncryptedFileBackend:
    _MAGIC = b"DBMCP1"

    def __init__(self, path: Path | None = None) -> None:
        if path is None:
            cfg = config_dir()
            cfg.mkdir(parents=True, mode=0o700, exist_ok=True)
            path = cfg / "secrets.enc"
        self._path = path

    def set_secret(self, profile_name: str, secret: str) -> None:
        data = self._load_plaintext()
        data[profile_name] = secret
        self._save(data)

    def get_secret(self, profile_name: str) -> str | None:
        data = self._load_plaintext()
        return data.get(profile_name)

    def delete_secret(self, profile_name: str) -> None:
        data = self._load_plaintext()
        if profile_name in data:
            del data[profile_name]
            self._save(data)

    def _load_plaintext(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        passphrase = self._get_passphrase()
        blob = self._path.read_bytes()
        plaintext = self._decrypt(blob, passphrase)
        return json.loads(plaintext)

    def _save(self, data: dict[str, str]) -> None:
        passphrase = self._get_passphrase()
        blob = self._encrypt(json.dumps(data, sort_keys=True).encode("utf-8"), passphrase)
        self._path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._path)

    def _get_passphrase(self) -> str:
        if "DBMCP_PASSPHRASE" in os.environ:
            return os.environ["DBMCP_PASSPHRASE"]
        if not sys.stdin.isatty():
            raise BackendUnavailable("passphrase required; set DBMCP_PASSPHRASE or run in a tty")
        return click.prompt("Passphrase", hide_input=True)

    @classmethod
    def _derive_key(cls, passphrase: str, salt: bytes) -> bytes:
        import hashlib

        return hashlib.scrypt(
            passphrase.encode("utf-8"),
            salt=salt,
            n=2**17,
            r=8,
            p=1,
            dklen=32,
            # n=2**17 with r=8 needs ~128 MiB; OpenSSL's default maxmem is 32 MiB.
            maxmem=512 * 1024 * 1024,
        )

    @classmethod
    def _encrypt(cls, plaintext: bytes, passphrase: str) -> bytes:
        import secrets

        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        key = cls._derive_key(passphrase, salt)
        aad = cls._MAGIC + salt + nonce
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return aad + ciphertext

    @classmethod
    def _decrypt(cls, blob: bytes, passphrase: str) -> bytes:
        if len(blob) < 6 + 16 + 12:
            raise ConfigError("wrong passphrase or corrupt secrets.enc")
        magic = blob[:6]
        if magic != cls._MAGIC:
            raise ConfigError("wrong passphrase or corrupt secrets.enc")
        salt = blob[6:22]
        nonce = blob[22:34]
        ciphertext = blob[34:]
        key = cls._derive_key(passphrase, salt)
        aad = cls._MAGIC + salt + nonce
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise ConfigError("wrong passphrase or corrupt secrets.enc") from exc


def get_backend(name: str) -> SecretBackend:
    if name == "keyring":
        return KeyringBackend()
    if name == "encrypted-file":
        return EncryptedFileBackend()
    raise ConfigError(f"unknown backend: {name}")
