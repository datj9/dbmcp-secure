"""Database type registry."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from dbmcp.errors import UnknownDbType
from dbmcp.url import build_url

if TYPE_CHECKING:
    from dbmcp.profiles import Profile


@dataclass(frozen=True)
class DbTypeSpec:
    db_type: str
    scheme: str
    needs_secret: bool
    default_port: int | None
    build_env: Callable[["Profile", str | None], dict[str, str]]
    launch_argv: Callable[["Profile"], list[str]]
    probe: tuple[str, dict]


def _postgres_env(profile: "Profile", password: str | None) -> dict[str, str]:
    return {"DATABASE_URI": build_url(profile, password)}


def _mysql_env(profile: "Profile", password: str | None) -> dict[str, str]:
    env = {
        "MYSQL_HOST": profile.host or "",
        "MYSQL_PORT": str(profile.port) if profile.port is not None else "",
        "MYSQL_USER": profile.user or "",
    }
    if password is not None:
        env["MYSQL_PASSWORD"] = password
    if profile.dbname is not None:
        env["MYSQL_DATABASE"] = profile.dbname
    return env


def _sqlite_env(_profile: "Profile", _password: str | None) -> dict[str, str]:
    return {}


def _redis_env(profile: "Profile", password: str | None) -> dict[str, str]:
    return {"REDIS_URL": build_url(profile, password)}


def _postgres_argv(profile: "Profile") -> list[str]:
    if profile.mcp_server_argv is not None:
        return profile.mcp_server_argv
    return [
        "uvx",
        "--from",
        "postgres-mcp",
        "--with",
        "mcp<2",
        "postgres-mcp",
        "--access-mode",
        "restricted",
        "--transport",
        "stdio",
    ]


def _mysql_argv(profile: "Profile") -> list[str]:
    if profile.mcp_server_argv is not None:
        return profile.mcp_server_argv
    return ["uvx", "--from", "mysql-mcp-server", "mysql_mcp_server"]


def _sqlite_argv(profile: "Profile") -> list[str]:
    if profile.mcp_server_argv is not None:
        return profile.mcp_server_argv
    db_path = str(Path(profile.dbname or "").resolve())
    return ["uvx", "mcp-server-sqlite", "--db-path", db_path]


def _redis_argv(profile: "Profile") -> list[str]:
    if profile.mcp_server_argv is not None:
        return profile.mcp_server_argv
    return ["uvx", "redis-mcp-server"]


DB_TYPES: dict[str, DbTypeSpec] = {
    "postgres": DbTypeSpec(
        db_type="postgres",
        scheme="postgresql",
        needs_secret=True,
        default_port=5432,
        build_env=_postgres_env,
        launch_argv=_postgres_argv,
        probe=("list_schemas", {}),
    ),
    "mysql": DbTypeSpec(
        db_type="mysql",
        scheme="mysql",
        needs_secret=True,
        default_port=3306,
        build_env=_mysql_env,
        launch_argv=_mysql_argv,
        probe=("execute_sql", {"query": "SELECT 1"}),
    ),
    "sqlite": DbTypeSpec(
        db_type="sqlite",
        scheme="sqlite",
        needs_secret=False,
        default_port=None,
        build_env=_sqlite_env,
        launch_argv=_sqlite_argv,
        probe=("list_tables", {}),
    ),
    "redis": DbTypeSpec(
        db_type="redis",
        scheme="redis",
        needs_secret=True,
        default_port=6379,
        build_env=_redis_env,
        launch_argv=_redis_argv,
        probe=("info", {}),
    ),
}


def get_spec(db_type: str) -> DbTypeSpec:
    if db_type not in DB_TYPES:
        raise UnknownDbType(f"unknown db_type: {db_type}")
    return DB_TYPES[db_type]
