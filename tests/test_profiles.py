"""Tests for dbmcp.profiles."""

from pathlib import Path

import pytest

from dbmcp.errors import ConfigError, ProfileNotFound
from dbmcp.profiles import (
    Profile,
    delete_profile,
    get_profile,
    load_profiles,
    save_profile,
    validate_profile,
)


def test_validate_profile_rejects_bad_port() -> None:
    p = Profile(
        name="test",
        db_type="postgres",
        host="localhost",
        port=70000,
        user="dbo",
        dbname="appdb",
        sslmode=None,
        mechanism="direct",
        backend="keyring",
        tls=False,
    )
    with pytest.raises(ConfigError):
        validate_profile(p)


def test_validate_profile_rejects_bad_sslmode() -> None:
    p = Profile(
        name="test",
        db_type="postgres",
        host="localhost",
        port=5432,
        user="dbo",
        dbname="appdb",
        sslmode="bad",
        mechanism="direct",
        backend="keyring",
        tls=False,
    )
    with pytest.raises(ConfigError):
        validate_profile(p)


def test_validate_profile_rejects_sqlite_with_host() -> None:
    p = Profile(
        name="test",
        db_type="sqlite",
        host="localhost",
        port=None,
        user=None,
        dbname="/tmp/app.db",
        sslmode=None,
        mechanism="direct",
        backend="keyring",
        tls=False,
    )
    with pytest.raises(ConfigError):
        validate_profile(p)


def test_validate_profile_requires_host_and_user() -> None:
    p = Profile(
        name="test",
        db_type="postgres",
        host=None,
        port=5432,
        user="dbo",
        dbname="appdb",
        sslmode=None,
        mechanism="direct",
        backend="keyring",
        tls=False,
    )
    with pytest.raises(ConfigError):
        validate_profile(p)


def test_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "profiles.toml"
    p = Profile(
        name="local",
        db_type="postgres",
        host="localhost",
        port=5432,
        user="dbo",
        dbname="appdb",
        sslmode=None,
        mechanism="direct",
        backend="keyring",
        tls=False,
    )
    save_profile(p, path)
    loaded = get_profile("local", path)
    assert loaded == p


def test_delete_profile(tmp_path: Path) -> None:
    path = tmp_path / "profiles.toml"
    p = Profile(
        name="x",
        db_type="sqlite",
        host=None,
        port=None,
        user=None,
        dbname="/tmp/x.db",
        sslmode=None,
        mechanism="direct",
        backend="keyring",
        tls=False,
    )
    save_profile(p, path)
    delete_profile("x", path)
    with pytest.raises(ProfileNotFound):
        get_profile("x", path)


def test_load_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "does_not_exist.toml"
    assert load_profiles(path) == {}


def test_unknown_key_rejected(tmp_path: Path) -> None:
    path = tmp_path / "profiles.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[profiles.x]\ndb_type = 'postgres'\nfoo = 'bar'\n")
    with pytest.raises(ConfigError):
        load_profiles(path)
