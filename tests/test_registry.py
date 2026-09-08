"""Tests for dbmcp.registry."""

from dbmcp.profiles import Profile
from dbmcp.registry import DB_TYPES, get_spec


def _profile(db_type: str, **kwargs) -> Profile:
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
        defaults.update(dbname="0")
    defaults.update(kwargs)
    return Profile(**defaults)


def test_all_db_types_registered() -> None:
    assert set(DB_TYPES.keys()) == {"postgres", "mysql", "sqlite", "redis"}


def test_postgres_env_and_argv() -> None:
    spec = get_spec("postgres")
    env = spec.build_env(_profile("postgres"), "secret")
    assert "DATABASE_URI" in env
    assert "postgresql://" in env["DATABASE_URI"]
    argv = spec.launch_argv(_profile("postgres"))
    assert argv[0] == "uvx"
    assert "postgres-mcp" in argv
    assert spec.probe == ("list_schemas", {})


def test_mysql_env_and_argv() -> None:
    spec = get_spec("mysql")
    env = spec.build_env(_profile("mysql"), "secret")
    assert env["MYSQL_HOST"] == "localhost"
    assert env["MYSQL_PORT"] == "5432"
    assert env["MYSQL_USER"] == "dbo"
    assert env["MYSQL_PASSWORD"] == "secret"
    assert env["MYSQL_DATABASE"] == "appdb"
    argv = spec.launch_argv(_profile("mysql"))
    assert argv == ["uvx", "--from", "mysql-mcp-server", "mysql_mcp_server"]
    assert spec.probe == ("execute_sql", {"query": "SELECT 1"})


def test_sqlite_env_and_argv() -> None:
    spec = get_spec("sqlite")
    env = spec.build_env(_profile("sqlite"), None)
    assert env == {}
    argv = spec.launch_argv(_profile("sqlite"))
    assert argv[0] == "uvx"
    assert "mcp-server-sqlite" in argv
    assert spec.needs_secret is False


def test_redis_env_and_argv() -> None:
    spec = get_spec("redis")
    env = spec.build_env(_profile("redis", dbname="2"), "secret")
    assert "REDIS_URL" in env
    assert "redis://" in env["REDIS_URL"]
    argv = spec.launch_argv(_profile("redis"))
    assert argv == ["uvx", "redis-mcp-server"]
    assert spec.probe == ("info", {})
