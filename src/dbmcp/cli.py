"""dbmcp CLI entrypoint."""

import json
import shutil
import sys

import click

from dbmcp import __version__
from dbmcp.errors import DbmcpError
from dbmcp.handshake import HandshakeResult, mcp_initialize
from dbmcp.launcher import launch, resolve_tool, warn_if_tunnel
from dbmcp.profiles import (
    Profile,
    config_dir,
    delete_profile,
    get_profile,
    load_profiles,
    save_profile,
    validate_profile,
)
from dbmcp.registry import get_spec
from dbmcp.secrets import get_backend


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """Configure and launch database MCP servers."""


@cli.command()
@click.argument("name")
@click.option("--type", "db_type", required=True, help="Database type")
@click.option("--host", default=None, help="Host")
@click.option("--port", default=None, type=int, help="Port")
@click.option("--user", default=None, help="User")
@click.option("--dbname", default=None, help="Database name/path/index")
@click.option("--sslmode", default=None, help="Postgres SSL mode")
@click.option("--mechanism", default="direct", help="direct or tunnel")
@click.option("--backend", default="keyring", help="keyring or encrypted-file")
@click.option("--tls", is_flag=True, help="Use rediss:// for redis")
@click.option("--server-argv", default=None, help="Override MCP server argv as a JSON list string")
@click.option("--password-stdin", is_flag=True, help="Read password from stdin")
@click.option("--force", is_flag=True, help="Overwrite existing profile")
def add(
    name: str,
    db_type: str,
    host: str | None,
    port: int | None,
    user: str | None,
    dbname: str | None,
    sslmode: str | None,
    mechanism: str,
    backend: str,
    tls: bool,
    server_argv: str | None,
    password_stdin: bool,
    force: bool,
) -> None:
    """Add a new profile."""
    spec = get_spec(db_type)
    mcp_server_argv = None
    if server_argv is not None:
        mcp_server_argv = json.loads(server_argv)

    profile = Profile(
        name=name,
        db_type=db_type,
        host=host,
        port=port,
        user=user,
        dbname=dbname,
        sslmode=sslmode,
        mechanism=mechanism,
        backend=backend,
        tls=tls,
        mcp_server_argv=mcp_server_argv,
    )
    validate_profile(profile)

    existing = load_profiles()
    if name in existing and not force:
        if not click.confirm(f"Profile '{name}' exists; overwrite?"):
            return

    if spec.needs_secret:
        password = _read_secret(password_stdin)
    else:
        password = None

    if password is not None:
        get_backend(backend).set_secret(name, password)

    save_profile(profile)
    if password is not None:
        click.echo(
            f"stored secret for '{name}' ({backend}); profile written to "
            f"{config_dir() / 'profiles.toml'}"
        )
    else:
        click.echo(f"profile written to {config_dir() / 'profiles.toml'}")


@cli.command(name="list")
def list_profiles() -> None:
    """List profiles."""
    profiles = load_profiles()
    if not profiles:
        click.echo("no profiles")
        return
    click.echo(f"{'NAME':<8} {'TYPE':<8} {'TARGET':<20} {'MECH':<8} {'BACKEND'}")
    for p in profiles.values():
        click.echo(f"{p.name:<8} {p.db_type:<8} {_target(p):<20} {p.mechanism:<8} {p.backend}")


@cli.command()
@click.argument("name")
def show(name: str) -> None:
    """Show a profile."""
    p = get_profile(name)
    spec = get_spec(p.db_type)
    click.echo(f"name: {p.name}")
    click.echo(f"type: {p.db_type}")
    click.echo(f"target: {_target(p)}")
    click.echo(f"mechanism: {p.mechanism}")
    click.echo(f"backend: {p.backend}")
    if p.sslmode:
        click.echo(f"sslmode: {p.sslmode}")
    if p.tls:
        click.echo("tls: true")
    argv = spec.launch_argv(p)
    click.echo(f"launch argv: {' '.join(argv)}")


@cli.command()
@click.argument("name")
def test(name: str) -> None:
    """Test a profile via MCP handshake."""
    p = get_profile(name)
    spec = get_spec(p.db_type)
    warn_if_tunnel(p)
    password: str | None = None
    if spec.needs_secret:
        backend = get_backend(p.backend)
        password = backend.get_secret(name)
        if password is None:
            click.echo(f"secret missing for '{name}'; re-run add", err=True)
            sys.exit(1)

    env = spec.build_env(p, password)
    argv = spec.launch_argv(p)
    argv[0] = resolve_tool(argv[0])
    result = mcp_initialize(argv, env, spec.probe, password)
    _print_handshake(result)


@cli.command()
@click.argument("name")
def launch_cmd(name: str) -> None:
    """Launch the MCP server for a profile."""
    p = get_profile(name)
    launch(p)


@cli.command()
@click.argument("name")
@click.option("--client", default="claude-code", help="claude-code or claude-desktop")
def emit(name: str, client: str) -> None:
    """Emit an MCP client JSON block."""
    p = get_profile(name)
    dbmcp_path = shutil.which("dbmcp")
    if dbmcp_path is None:
        click.echo("dbmcp not found in PATH", err=True)
        sys.exit(1)

    env: dict[str, str] = {}
    if p.backend == "encrypted-file":
        env["DBMCP_PASSPHRASE"] = "<fill-in>"
        click.echo("# Note: DBMCP_PASSPHRASE will live in the client config", err=True)

    server: dict = {
        "command": dbmcp_path,
        "args": ["launch", name],
        "env": env,
    }
    if client == "claude-code":
        server["type"] = "stdio"

    block = {"mcpServers": {name: server}}
    click.echo(json.dumps(block, indent=2))


@cli.command()
@click.argument("name")
def remove(name: str) -> None:
    """Remove a profile and its secret."""
    p = get_profile(name)
    try:
        backend = get_backend(p.backend)
        backend.delete_secret(name)
    except DbmcpError as exc:
        click.echo(f"warning: secret not removed ({exc.message}); profile removed", err=True)
    delete_profile(name)
    click.echo(f"removed profile '{name}'")


def main() -> None:
    try:
        cli()
    except DbmcpError as exc:
        click.echo(exc.message, err=True)
        sys.exit(1)


# --- helpers ---


def _read_secret(password_stdin: bool) -> str | None:
    if password_stdin:
        return sys.stdin.readline().rstrip("\n")
    if not sys.stdin.isatty():
        raise DbmcpError("secret needed but stdin is not a tty; use --password-stdin")
    return click.prompt("Password", hide_input=True)


def _target(p: Profile) -> str:
    if p.db_type == "sqlite":
        return p.dbname or ""
    host = p.host or ""
    port = p.port or ""
    dbname = p.dbname or ""
    return f"{host}:{port}/{dbname}"


def _print_handshake(result: HandshakeResult) -> None:
    if result.status == "OK":
        click.echo(f"OK {result.elapsed_seconds:.1f}s")
    elif result.status == "SLOW":
        click.echo(f"SLOW {result.elapsed_seconds:.1f}s (>10s)")
    else:
        click.echo(f"FAIL {result.error}")
        sys.exit(1)
