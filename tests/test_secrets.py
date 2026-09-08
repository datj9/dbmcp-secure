"""Tests for dbmcp.secrets: encrypted-file round-trip, wrong passphrase
(InvalidTag -> ConfigError), and the keyring backend allowlist.
"""

from pathlib import Path

import keyring
import pytest

from dbmcp.errors import BackendUnavailable, ConfigError
from dbmcp.secrets import EncryptedFileBackend, KeyringBackend, get_backend


def test_encrypted_file_round_trip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBMCP_PASSPHRASE", "hunter2")
    path = tmp_path / "secrets.enc"
    backend = EncryptedFileBackend(path)
    backend.set_secret("prod-pg", "s[)|,*")
    assert backend.get_secret("prod-pg") == "s[)|,*"


def test_encrypted_file_wrong_passphrase(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBMCP_PASSPHRASE", "hunter2")
    path = tmp_path / "secrets.enc"
    backend = EncryptedFileBackend(path)
    backend.set_secret("prod-pg", "secret")
    monkeypatch.setenv("DBMCP_PASSPHRASE", "wrong")
    with pytest.raises(ConfigError, match="wrong passphrase or corrupt secrets.enc"):
        backend.get_secret("prod-pg")


def test_encrypted_file_delete(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBMCP_PASSPHRASE", "hunter2")
    path = tmp_path / "secrets.enc"
    backend = EncryptedFileBackend(path)
    backend.set_secret("a", "1")
    backend.set_secret("b", "2")
    backend.delete_secret("a")
    assert backend.get_secret("a") is None
    assert backend.get_secret("b") == "2"


def test_encrypted_file_missing_passphrase_non_tty(tmp_path: Path, monkeypatch) -> None:
    import sys

    class NotATty:
        def isatty(self) -> bool:
            return False

    monkeypatch.delenv("DBMCP_PASSPHRASE", raising=False)
    monkeypatch.setattr(sys, "stdin", NotATty())
    path = tmp_path / "secrets.enc"
    with pytest.raises(BackendUnavailable, match="DBMCP_PASSPHRASE"):
        EncryptedFileBackend(path).set_secret("a", "1")


def test_encrypted_file_corrupt_header(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBMCP_PASSPHRASE", "hunter2")
    path = tmp_path / "secrets.enc"
    path.write_bytes(b"garbage-not-dbmcp")
    with pytest.raises(ConfigError, match="corrupt secrets.enc"):
        EncryptedFileBackend(path).get_secret("a")


def test_keyring_allowlist_rejects_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(keyring, "get_keyring", lambda: keyring.backends.fail.Keyring())
    with pytest.raises(BackendUnavailable, match="encrypted-file"):
        KeyringBackend()


class _PlaintextLikeKeyring:
    """Stands in for keyrings.alt.file.PlaintextKeyring in the allowlist check."""

    def set_password(self, *a, **k) -> None:
        pass

    def get_password(self, *a, **k) -> str | None:
        return None

    def delete_password(self, *a, **k) -> None:
        pass


def test_keyring_allowlist_rejects_plaintext(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(keyring, "get_keyring", lambda: _PlaintextLikeKeyring())
    with pytest.raises(BackendUnavailable, match="encrypted-file"):
        KeyringBackend()


def test_keyring_allowlist_rejects_unknown_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    class UnknownBackend:
        pass

    monkeypatch.setattr(keyring, "get_keyring", UnknownBackend)
    with pytest.raises(BackendUnavailable):
        KeyringBackend()


def test_keyring_backend_roundtrip_with_allowed_keyring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store: dict[tuple[str, str], str] = {}
    kr = keyring.backends.macOS.Keyring()
    kr.set_password = lambda service, user, pw: store.__setitem__((service, user), pw)
    kr.get_password = lambda service, user: store.get((service, user))
    kr.delete_password = lambda service, user: store.pop((service, user), None)
    monkeypatch.setattr(keyring, "get_keyring", lambda: kr)

    backend = KeyringBackend()
    backend.set_secret("prod-pg", "s[)|,*")
    assert backend.get_secret("prod-pg") == "s[)|,*"
    backend.delete_secret("prod-pg")
    assert backend.get_secret("prod-pg") is None


def test_keyring_locked_maps_to_backend_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def locked(*a, **k) -> None:
        raise keyring.errors.KeyringLocked("locked")

    kr = keyring.backends.macOS.Keyring()
    kr.set_password = locked
    monkeypatch.setattr(keyring, "get_keyring", lambda: kr)

    backend = KeyringBackend()
    with pytest.raises(BackendUnavailable, match="keyring unavailable"):
        backend.set_secret("p", "pw")


def test_keyring_delete_missing_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_password(*a, **k) -> None:
        raise keyring.errors.PasswordDeleteError("missing")

    kr = keyring.backends.macOS.Keyring()
    kr.delete_password = no_password
    monkeypatch.setattr(keyring, "get_keyring", lambda: kr)

    KeyringBackend().delete_secret("absent")


def test_get_backend_unknown_name() -> None:
    with pytest.raises(ConfigError):
        get_backend("bogus")


def test_get_backend_known_names(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBMCP_PASSPHRASE", "hunter2")
    assert isinstance(get_backend("keyring"), KeyringBackend)
    assert isinstance(get_backend("encrypted-file"), EncryptedFileBackend)
