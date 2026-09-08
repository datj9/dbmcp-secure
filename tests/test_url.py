"""Tests for dbmcp.url."""

from urllib.parse import urlsplit

import pytest

from dbmcp.errors import UrlError
from dbmcp.profiles import Profile
from dbmcp.url import build_url, redact


def _profile(db_type="postgres", **kwargs) -> Profile:
    defaults = {
        "name": "test",
        "db_type": db_type,
        "host": "localhost",
        "port": 5432,
        "user": "dbo",
        "dbname": "appdb",
        "sslmode": None,
        "mechanism": "direct",
        "backend": "keyring",
        "tls": False,
    }
    if db_type == "sqlite":
        defaults.update(host=None, port=None, user=None, dbname="/tmp/app.db")
    elif db_type == "redis":
        defaults.update(dbname=None)
    defaults.update(kwargs)
    return Profile(**defaults)


def test_postgres_build_url_percent_encodes_password() -> None:
    profile = _profile(db_type="postgres")
    pw = "p[)|,*"
    url = build_url(profile, pw)
    assert url == "postgresql://dbo:p%5B%29%7C%2C%2A@localhost:5432/appdb"
    # urlsplit must not raise
    parts = urlsplit(url)
    assert parts.scheme == "postgresql"
    assert parts.hostname == "localhost"
    assert parts.port == 5432
    assert parts.path == "/appdb"


def test_postgres_build_url_sslmode() -> None:
    profile = _profile(sslmode="require")
    url = build_url(profile, "secret")
    assert url == "postgresql://dbo:secret@localhost:5432/appdb?sslmode=require"


def test_postgres_build_url_missing_field() -> None:
    profile = _profile(host=None)
    with pytest.raises(UrlError):
        build_url(profile, "secret")


def test_redis_build_url() -> None:
    profile = _profile(db_type="redis", dbname="2")
    assert build_url(profile, "secret") == "redis://dbo:secret@localhost:5432/2"


def test_redis_tls() -> None:
    profile = _profile(db_type="redis", tls=True)
    assert build_url(profile, "secret") == "rediss://dbo:secret@localhost:5432/0"


def test_redis_no_dbname_defaults_to_zero() -> None:
    profile = _profile(db_type="redis", dbname=None)
    assert build_url(profile, "secret") == "redis://dbo:secret@localhost:5432/0"


def test_sqlite_build_url() -> None:
    profile = _profile(
        db_type="sqlite",
        host=None,
        port=None,
        user=None,
        dbname="/tmp/app.db",
    )
    url = build_url(profile, None)
    assert url.startswith("sqlite:///")
    assert "/tmp/app.db" in url


def test_mysql_raises_url_error() -> None:
    profile = _profile(db_type="mysql")
    with pytest.raises(UrlError):
        build_url(profile, "secret")


def test_ipv6_host_wrapped() -> None:
    profile = _profile(host="2001:db8::1")
    url = build_url(profile, "secret")
    assert "@[2001:db8::1]:5432" in url


def test_redact_raw_and_encoded_and_url() -> None:
    pw = "p[)|,*"
    encoded = "p%5B%29%7C%2C%2A"
    text = f"error: {pw} and {encoded} and postgresql://dbo:{encoded}@h:5432/db"
    result = redact(text, pw)
    assert "p[" not in result
    assert encoded not in result
    assert "postgresql://" not in result
    assert result.count("***") == 3


def test_redact_returns_text_when_password_none() -> None:
    text = "something secret"
    assert redact(text, None) == text
