"""Launch the underlying MCP server for a profile."""

import os
import shutil
import socket
import sys
from pathlib import Path
from typing import NoReturn

from dbmcp.errors import DbmcpError
from dbmcp.profiles import Profile
from dbmcp.registry import get_spec
from dbmcp.secrets import get_backend


def resolve_tool(name: str) -> str:
    path = shutil.which(name)
    if path:
        return path
    for candidate_dir in (
        Path.home() / ".local" / "bin",
        Path.home() / ".cargo" / "bin",
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
    ):
        candidate = candidate_dir / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise DbmcpError(f"{name} not found")


def warn_if_tunnel(profile: Profile) -> None:
    """Warn (to stderr) when a tunnel profile's local port is not listening."""
    if profile.mechanism != "tunnel" or profile.port is None:
        return
    try:
        with socket.create_connection(("127.0.0.1", profile.port), timeout=0.2):
            return
    except OSError:
        sys.stderr.write(
            f"warning: tunnel expected but local port {profile.port} is not listening\n"
        )


def launch(profile: Profile) -> NoReturn:
    spec = get_spec(profile.db_type)
    warn_if_tunnel(profile)
    password: str | None = None
    if spec.needs_secret:
        backend = get_backend(profile.backend)
        password = backend.get_secret(profile.name)
        if password is None:
            sys.stderr.write(f"secret missing for '{profile.name}'; re-run add\n")
            sys.exit(1)

    env = spec.build_env(profile, password)
    argv = spec.launch_argv(profile)
    argv[0] = resolve_tool(argv[0])

    os.environ.update(env)
    os.execv(argv[0], argv)
