"""Profile model, validation, and TOML persistence."""

import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

from dbmcp.errors import ConfigError, ProfileNotFound


@dataclass(frozen=True)
class Profile:
    name: str
    db_type: str
    host: str | None
    port: int | None
    user: str | None
    dbname: str | None
    sslmode: str | None
    mechanism: str
    backend: str
    tls: bool
    mcp_server_argv: list[str] | None = None


_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_USER_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SSLMODES = {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}


def config_dir() -> Path:
    """Return the dbmcp config directory (respects XDG_CONFIG_HOME)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "dbmcp"


def _config_path(path: Path | None = None) -> Path:
    if path is not None:
        return path
    cfg = config_dir()
    cfg.mkdir(parents=True, mode=0o700, exist_ok=True)
    return cfg / "profiles.toml"


def load_profiles(path: Path | None = None) -> dict[str, Profile]:
    file_path = _config_path(path)
    if not file_path.exists():
        return {}
    try:
        data = file_path.read_text(encoding="utf-8")
        parsed = tomllib.loads(data)
    except Exception as exc:  # noqa: BLE001
        raise ConfigError(f"failed to parse profiles: {exc}") from exc

    profiles: dict[str, Profile] = {}
    for raw_name, raw in parsed.get("profiles", {}).items():
        if not isinstance(raw, dict):
            raise ConfigError(f"profile '{raw_name}' is not a table")
        profiles[raw_name] = _from_dict(raw_name, raw)
    return profiles


def get_profile(name: str, path: Path | None = None) -> Profile:
    profiles = load_profiles(path)
    if name not in profiles:
        raise ProfileNotFound(f"profile not found: {name}")
    return profiles[name]


def save_profile(profile: Profile, path: Path | None = None) -> None:
    file_path = _config_path(path)
    validate_profile(profile)
    existing = load_profiles(file_path)
    existing[profile.name] = profile
    _write(existing, file_path)


def delete_profile(name: str, path: Path | None = None) -> None:
    profiles = load_profiles(path)
    if name not in profiles:
        raise ProfileNotFound(f"profile not found: {name}")
    del profiles[name]
    _write(profiles, _config_path(path))


def validate_profile(p: Profile) -> None:
    from dbmcp.registry import DB_TYPES  # lazy import avoids circular dependency

    if p.db_type not in DB_TYPES:
        raise ConfigError(f"unknown db_type: {p.db_type}")
    if p.mechanism not in {"direct", "tunnel"}:
        raise ConfigError(f"invalid mechanism: {p.mechanism}")
    if p.backend not in {"keyring", "encrypted-file"}:
        raise ConfigError(f"invalid backend: {p.backend}")
    if not _NAME_RE.match(p.name):
        raise ConfigError(f"invalid profile name: {p.name}")
    if p.user is not None and not _USER_RE.match(p.user):
        raise ConfigError(f"invalid user: {p.user}")

    if p.db_type == "sqlite":
        if p.host is not None or p.user is not None or p.port is not None:
            raise ConfigError("sqlite profile must not set host/user/port")
        if not p.dbname:
            raise ConfigError("sqlite profile requires dbname")
    else:
        if not p.host or not p.user or p.port is None:
            raise ConfigError(f"{p.db_type} requires host, user, and port")
        if not (1 <= p.port <= 65535):
            raise ConfigError(f"invalid port: {p.port}")
        if p.db_type == "postgres" and p.sslmode is not None and p.sslmode not in _SSLMODES:
            raise ConfigError(f"invalid sslmode: {p.sslmode}")
        if p.db_type == "redis" and p.dbname is not None and not re.fullmatch(r"\d+", p.dbname):
            raise ConfigError(f"invalid redis dbname: {p.dbname}")


def _from_dict(name: str, data: dict) -> Profile:
    known = {
        "db_type",
        "host",
        "port",
        "user",
        "dbname",
        "sslmode",
        "mechanism",
        "backend",
        "tls",
        "mcp_server_argv",
    }
    unknown = set(data.keys()) - known
    if unknown:
        raise ConfigError(f"unknown keys in profile '{name}': {sorted(unknown)}")

    port = data.get("port")
    if isinstance(port, str):
        port = int(port)

    db_type = data.get("db_type")
    if db_type is None:
        raise ConfigError(f"profile '{name}' is missing db_type")

    profile = Profile(
        name=name,
        db_type=db_type,
        host=data.get("host"),
        port=port,
        user=data.get("user"),
        dbname=data.get("dbname"),
        sslmode=data.get("sslmode"),
        mechanism=data.get("mechanism", "direct"),
        backend=data.get("backend", "keyring"),
        tls=data.get("tls", False),
        mcp_server_argv=data.get("mcp_server_argv"),
    )
    validate_profile(profile)
    return profile


def _to_dict(p: Profile) -> dict:
    d = asdict(p)
    d.pop("name")
    return {k: v for k, v in d.items() if v is not None}


def _write(profiles: dict[str, Profile], path: Path) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    lines: list[str] = []
    for name, p in profiles.items():
        lines.append(f"[profiles.{name}]")
        for key, value in _to_dict(p).items():
            if isinstance(value, list):
                rendered = "[" + ", ".join(_fmt(v) for v in value) + "]"
                lines.append(f"{key} = {rendered}")
            else:
                lines.append(f"{key} = {_fmt(value)}")
        lines.append("")
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(lines), encoding="utf-8")
    tmp.replace(path)


def _fmt(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return repr(value).replace("'", '"')
    raise TypeError(f"unsupported TOML value: {value!r}")
