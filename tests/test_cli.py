"""Tests for the dbmcp CLI.

Every test here avoids touching a real keychain or database: secrets go through
the encrypted-file backend with DBMCP_PASSPHRASE set, and the MCP server is
mocked at the handshake/exec boundary.

Happy paths run through click's CliRunner; error paths run through the real
`main()` entrypoint (the console-script target) to assert the exit-1 +
redacted-message-on-stderr contract.
"""

import contextlib
import io
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote

import pytest
from click.testing import CliRunner

from dbmcp.cli import cli, main
from dbmcp.errors import BackendUnavailable, DbmcpError
from dbmcp.handshake import HandshakeResult
from dbmcp.profiles import Profile, get_profile, save_profile
from dbmcp.secrets import EncryptedFileBackend

PASSWORD = "s[)|,*z"
ENCODED = quote(PASSWORD, safe="")
PASSPHRASE = "test-passphrase"
CONFIG_REL = Path("dbmcp") / "profiles.toml"
SECRETS_REL = Path("dbmcp") / "secrets.enc"

PG = {
    "name": "prod-pg",
    "db_type": "postgres",
    "host": "10.0.0.5",
    "port": 5432,
    "user": "dbo",
    "dbname": "appdb",
    "sslmode": "require",
    "mechanism": "direct",
    "backend": "encrypted-file",
    "tls": False,
}


def _env(tmp_path: Path, **extra) -> dict[str, str]:
    return {
        "XDG_CONFIG_HOME": str(tmp_path),
        "DBMCP_PASSPHRASE": PASSPHRASE,
        **extra,
    }


def _invoke(tmp_path: Path, args: list[str], input: str | None = None, env=None):
    runner = CliRunner()
    return runner.invoke(cli, args, input=input, env=_env(tmp_path, **(env or {})))


class _MainResult:
    def __init__(self, exit_code: int, stdout: str, stderr: str) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


def _run(tmp_path: Path, args: list[str], input: str | None = None, env=None) -> _MainResult:
    """Invoke the real main() entrypoint exactly as the console script does."""
    merged = _env(tmp_path, **(env or {}))
    old_argv, old_stdin, old_env = sys.argv, sys.stdin, dict(os.environ)
    sys.argv = ["dbmcp-secure", *args]
    if input is not None:
        sys.stdin = io.StringIO(input)
    os.environ.clear()
    os.environ.update(merged)
    out, err = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                main()
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
            except BaseException as exc:  # pragma: no cover - regression fails
                code = 1
                err.write(f"{type(exc).__name__}: {exc}\n")
    finally:
        sys.argv, sys.stdin = old_argv, old_stdin
        os.environ.clear()
        os.environ.update(old_env)
    return _MainResult(code, out.getvalue(), err.getvalue())


def _add_pg(tmp_path: Path, extra_args: list[str] | None = None):
    return _invoke(
        tmp_path,
        [
            "add",
            "prod-pg",
            "--type",
            "postgres",
            "--host",
            "10.0.0.5",
            "--port",
            "5432",
            "--user",
            "dbo",
            "--dbname",
            "appdb",
            "--sslmode",
            "require",
            "--backend",
            "encrypted-file",
            "--password-stdin",
            *(extra_args or []),
        ],
        input=PASSWORD + "\n",
    )


def _save_pg(tmp_path: Path) -> None:
    profile = Profile(
        name="prod-pg",
        db_type="postgres",
        host="10.0.0.5",
        port=5432,
        user="dbo",
        dbname="appdb",
        sslmode="require",
        mechanism="direct",
        backend="encrypted-file",
        tls=False,
    )
    save_profile(profile, Path(tmp_path) / CONFIG_REL)


def _config(tmp_path: Path) -> Path:
    return Path(tmp_path) / CONFIG_REL


def _secrets(tmp_path: Path) -> Path:
    return Path(tmp_path) / SECRETS_REL


# --- add ---


def test_add_stores_secret_and_profile(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBMCP_PASSPHRASE", PASSPHRASE)
    result = _add_pg(tmp_path)
    assert result.exit_code == 0, result.output
    assert "stored secret for 'prod-pg'" in result.output
    assert PASSWORD not in result.output
    assert ENCODED not in result.output
    backend = EncryptedFileBackend(_secrets(tmp_path))
    assert backend.get_secret("prod-pg") == PASSWORD
    profile = get_profile("prod-pg", _config(tmp_path))
    assert profile.host == "10.0.0.5"
    assert profile.port == 5432


def test_add_duplicate_without_force_prompts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBMCP_PASSPHRASE", PASSPHRASE)
    _add_pg(tmp_path)
    result = _invoke(
        tmp_path,
        [
            "add",
            "prod-pg",
            "--type",
            "postgres",
            "--host",
            "10.0.0.5",
            "--port",
            "5432",
            "--user",
            "dbo",
            "--dbname",
            "appdb",
            "--backend",
            "encrypted-file",
            "--password-stdin",
        ],
        input=PASSWORD + "\n\n",  # first line: password, second line: confirm -> default N
    )
    assert result.exit_code == 0, result.output
    backend = EncryptedFileBackend(_secrets(tmp_path))
    assert backend.get_secret("prod-pg") == PASSWORD  # unchanged


def test_add_duplicate_force_overwrites(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBMCP_PASSPHRASE", PASSPHRASE)
    _add_pg(tmp_path)
    result = _invoke(
        tmp_path,
        [
            "add",
            "prod-pg",
            "--type",
            "postgres",
            "--host",
            "10.0.0.5",
            "--port",
            "5432",
            "--user",
            "dbo",
            "--dbname",
            "appdb",
            "--backend",
            "encrypted-file",
            "--password-stdin",
            "--force",
        ],
        input="rotated-secret\n",
    )
    assert result.exit_code == 0, result.output
    backend = EncryptedFileBackend(_secrets(tmp_path))
    assert backend.get_secret("prod-pg") == "rotated-secret"


def test_add_sqlite_needs_no_password(tmp_path: Path) -> None:
    result = _invoke(
        tmp_path,
        ["add", "local-sqlite", "--type", "sqlite", "--dbname", "/tmp/dbmcp-test.db"],
    )
    assert result.exit_code == 0, result.output
    profile = get_profile("local-sqlite", _config(tmp_path))
    assert profile.db_type == "sqlite"


def test_add_non_tty_requires_password_stdin(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        [
            "add",
            "prod-pg",
            "--type",
            "postgres",
            "--host",
            "h",
            "--port",
            "5432",
            "--user",
            "u",
            "--dbname",
            "d",
            "--backend",
            "encrypted-file",
        ],
    )
    assert result.exit_code == 1
    assert "not a tty" in result.stderr
    assert result.stdout == ""


def test_add_invalid_port_rejected(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        [
            "add",
            "bad",
            "--type",
            "postgres",
            "--host",
            "h",
            "--port",
            "99999",
            "--user",
            "u",
            "--dbname",
            "d",
        ],
    )
    assert result.exit_code == 1
    with pytest.raises(Exception):
        get_profile("bad", _config(tmp_path))


def test_add_unknown_db_type_rejected(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        [
            "add",
            "x",
            "--type",
            "oracle",
            "--host",
            "h",
            "--port",
            "1521",
            "--user",
            "u",
            "--dbname",
            "d",
        ],
    )
    assert result.exit_code == 1
    assert "unknown db_type" in result.stderr
    assert "Traceback" not in result.output
    assert "Traceback" not in result.stderr


def test_add_server_argv_malformed_json_clean_error(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        ["add", "x", "--type", "sqlite", "--dbname", "/tmp/a.db", "--server-argv", "not json"],
    )
    assert result.exit_code == 1
    assert "Traceback" not in result.stderr
    assert "--server-argv is not valid JSON" in result.stderr


@pytest.mark.parametrize("bad", ['"x"', "{}", "5"])
def test_add_server_argv_not_a_list(tmp_path: Path, bad: str) -> None:
    result = _run(
        tmp_path,
        ["add", "x", "--type", "sqlite", "--dbname", "/tmp/a.db", "--server-argv", bad],
    )
    assert result.exit_code == 1
    assert "Traceback" not in result.stderr
    assert "--server-argv must be a JSON array of strings" in result.stderr


def test_add_server_argv_empty_list(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        ["add", "x", "--type", "sqlite", "--dbname", "/tmp/a.db", "--server-argv", "[]"],
    )
    assert result.exit_code == 1
    assert "Traceback" not in result.stderr
    assert "--server-argv must not be empty" in result.stderr


def test_add_server_argv_non_string_element(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        ["add", "x", "--type", "sqlite", "--dbname", "/tmp/a.db", "--server-argv", '["uvx", 5]'],
    )
    assert result.exit_code == 1
    assert "Traceback" not in result.stderr
    assert "--server-argv must contain only strings" in result.stderr


def test_add_server_argv_valid_persists(tmp_path: Path) -> None:
    result = _invoke(
        tmp_path,
        [
            "add",
            "pin",
            "--type",
            "sqlite",
            "--dbname",
            "/tmp/a.db",
            "--server-argv",
            '["uvx","mcp-server-sqlite","--db-path","/tmp/a.db"]',
        ],
    )
    assert result.exit_code == 0, result.output
    profile = get_profile("pin", _config(tmp_path))
    assert profile.mcp_server_argv == ["uvx", "mcp-server-sqlite", "--db-path", "/tmp/a.db"]


# --- list / show ---


def test_list_empty_prints_no_profiles(tmp_path: Path) -> None:
    result = _invoke(tmp_path, ["list"])
    assert result.exit_code == 0
    assert "no profiles" in result.output


def test_list_shows_target_without_secret(tmp_path: Path) -> None:
    _add_pg(tmp_path)
    result = _invoke(tmp_path, ["list"])
    assert result.exit_code == 0
    assert "prod-pg" in result.output
    assert "10.0.0.5:5432/appdb" in result.output
    assert "direct" in result.output
    assert PASSWORD not in result.output
    assert ENCODED not in result.output


def test_show_prints_profile_and_argv_without_secret(tmp_path: Path) -> None:
    _add_pg(tmp_path)
    result = _invoke(tmp_path, ["show", "prod-pg"])
    assert result.exit_code == 0
    assert "type: postgres" in result.output
    assert "launch argv:" in result.output
    assert "postgres-mcp" in result.output
    assert PASSWORD not in result.output
    assert ENCODED not in result.output


def test_show_missing_profile_fails(tmp_path: Path) -> None:
    result = _run(tmp_path, ["show", "nope"])
    assert result.exit_code == 1
    assert "profile not found" in result.stderr


# --- emit ---


def test_emit_claude_code_format(tmp_path: Path, monkeypatch) -> None:
    # keyring-backed profile -> empty env block
    save_profile(
        Profile(
            name="prod-pg",
            db_type="postgres",
            host="10.0.0.5",
            port=5432,
            user="dbo",
            dbname="appdb",
            sslmode="require",
            mechanism="direct",
            backend="keyring",
            tls=False,
        ),
        _config(tmp_path),
    )
    monkeypatch.setattr("dbmcp.cli.shutil.which", lambda name: "/abs/path/dbmcp-secure")
    result = _invoke(tmp_path, ["emit", "prod-pg", "--client", "claude-code"])
    assert result.exit_code == 0, result.output
    block = json.loads(result.stdout)
    server = block["mcpServers"]["prod-pg"]
    assert server["type"] == "stdio"
    assert server["args"] == ["launch", "prod-pg"]
    assert server["command"] == "/abs/path/dbmcp-secure"
    assert server["env"] == {}
    assert PASSWORD not in result.output


def test_emit_claude_desktop_no_type_key(tmp_path: Path, monkeypatch) -> None:
    _add_pg(tmp_path)
    monkeypatch.setattr("dbmcp.cli.shutil.which", lambda name: "/abs/path/dbmcp-secure")
    result = _invoke(tmp_path, ["emit", "prod-pg", "--client", "claude-desktop"])
    assert result.exit_code == 0, result.output
    server = json.loads(result.stdout)["mcpServers"]["prod-pg"]
    assert "type" not in server


def test_emit_encrypted_file_notes_passphrase_env(tmp_path: Path, monkeypatch) -> None:
    _add_pg(tmp_path)
    monkeypatch.setattr("dbmcp.cli.shutil.which", lambda name: "/abs/path/dbmcp-secure")
    result = _invoke(tmp_path, ["emit", "prod-pg"])
    assert result.exit_code == 0, result.output
    server = json.loads(result.stdout)["mcpServers"]["prod-pg"]
    assert server["env"] == {"DBMCP_PASSPHRASE": "<fill-in>"}
    assert "DBMCP_PASSPHRASE" in result.stderr


def test_emit_missing_dbmcp_secure_in_path_fails(tmp_path: Path, monkeypatch) -> None:
    _add_pg(tmp_path)
    monkeypatch.setattr("dbmcp.cli.shutil.which", lambda name: None)
    result = _run(tmp_path, ["emit", "prod-pg"])
    assert result.exit_code == 1
    assert "dbmcp-secure not found" in result.stderr


# --- test ---


def test_test_reports_ok(tmp_path: Path, monkeypatch) -> None:
    _add_pg(tmp_path)
    monkeypatch.setattr(
        "dbmcp.cli.mcp_initialize",
        lambda *a, **k: HandshakeResult(status="OK", elapsed_seconds=3.4, error=None),
    )
    monkeypatch.setattr("dbmcp.cli.resolve_tool", lambda name: "/bin/true")
    result = _invoke(tmp_path, ["test", "prod-pg"])
    assert result.exit_code == 0
    assert "OK 3.4s" in result.output


def test_test_reports_slow(tmp_path: Path, monkeypatch) -> None:
    _add_pg(tmp_path)
    monkeypatch.setattr(
        "dbmcp.cli.mcp_initialize",
        lambda *a, **k: HandshakeResult(status="SLOW", elapsed_seconds=11.0, error=None),
    )
    monkeypatch.setattr("dbmcp.cli.resolve_tool", lambda name: "/bin/true")
    result = _invoke(tmp_path, ["test", "prod-pg"])
    assert result.exit_code == 0
    assert "SLOW 11.0s (>10s)" in result.output


def test_test_reports_fail_and_exits_nonzero(tmp_path: Path, monkeypatch) -> None:
    _add_pg(tmp_path)
    monkeypatch.setattr(
        "dbmcp.cli.mcp_initialize",
        lambda *a, **k: HandshakeResult(
            status="FAIL", elapsed_seconds=1.0, error="probe failed: auth"
        ),
    )
    monkeypatch.setattr("dbmcp.cli.resolve_tool", lambda name: "/bin/true")
    result = _invoke(tmp_path, ["test", "prod-pg"])
    assert result.exit_code == 1
    assert "FAIL probe failed: auth" in result.output


def test_test_missing_secret_exits(tmp_path: Path) -> None:
    _save_pg(tmp_path)  # profile without a stored secret
    result = _run(tmp_path, ["test", "prod-pg"])
    assert result.exit_code == 1
    assert "secret missing for 'prod-pg'" in result.stderr
    assert PASSWORD not in result.output


def test_test_unknown_profile(tmp_path: Path) -> None:
    result = _run(tmp_path, ["test", "nope"])
    assert result.exit_code == 1
    assert "profile not found" in result.stderr


# --- launch (zero-stdout invariant) ---


def test_launch_writes_zero_bytes_to_stdout(tmp_path: Path, monkeypatch) -> None:
    _add_pg(tmp_path)
    captured: dict = {}

    def fake_execv(path: str, argv: list[str]) -> None:
        captured["path"] = path
        captured["argv"] = argv
        captured["env"] = {k: v for k, v in os.environ.items() if k.startswith("DATABASE_URI")}

    monkeypatch.setattr("dbmcp.launcher.os.execv", fake_execv)
    monkeypatch.setattr("dbmcp.launcher.resolve_tool", lambda name: "/fake/uvx")
    result = _invoke(tmp_path, ["launch", "prod-pg"])
    assert result.exit_code == 0, result.output
    assert result.stdout == ""  # zero bytes on the MCP protocol channel
    assert captured["path"] == "/fake/uvx"
    assert captured["argv"][0] == "/fake/uvx"
    assert captured["env"]["DATABASE_URI"].startswith("postgresql://dbo:")
    assert PASSWORD not in captured["env"]["DATABASE_URI"]  # percent-encoded
    assert ENCODED in captured["env"]["DATABASE_URI"]


def test_launch_missing_secret_exits_without_stdout(tmp_path: Path, monkeypatch) -> None:
    _save_pg(tmp_path)
    monkeypatch.setattr("dbmcp.launcher.os.execv", lambda *a: None)
    monkeypatch.setattr("dbmcp.launcher.resolve_tool", lambda name: "/fake/uvx")
    result = _run(tmp_path, ["launch", "prod-pg"])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "secret missing for 'prod-pg'" in result.stderr


def test_launch_tunnel_warns_on_stderr_still_launches(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBMCP_PASSPHRASE", PASSPHRASE)
    profile = Profile(
        name="tunnel-pg",
        db_type="postgres",
        host="10.0.0.5",
        port=59999,  # closed port, no listener
        user="dbo",
        dbname="appdb",
        sslmode=None,
        mechanism="tunnel",
        backend="encrypted-file",
        tls=False,
    )
    save_profile(profile, _config(tmp_path))
    EncryptedFileBackend(_secrets(tmp_path)).set_secret("tunnel-pg", PASSWORD)
    monkeypatch.setattr("dbmcp.launcher.os.execv", lambda *a: None)
    monkeypatch.setattr("dbmcp.launcher.resolve_tool", lambda name: "/fake/uvx")
    result = _invoke(tmp_path, ["launch", "tunnel-pg"])
    assert result.exit_code == 0
    assert result.stdout == ""
    assert "tunnel expected but local port 59999 is not listening" in result.stderr


def test_launch_tunnel_no_warning_when_port_listening(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBMCP_PASSPHRASE", PASSPHRASE)
    # Bind an ephemeral port and claim it's the tunnel endpoint.
    import socket

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen(1)
    try:
        profile = Profile(
            name="tunnel-pg",
            db_type="postgres",
            host="10.0.0.5",
            port=port,
            user="dbo",
            dbname="appdb",
            sslmode=None,
            mechanism="tunnel",
            backend="encrypted-file",
            tls=False,
        )
        save_profile(profile, _config(tmp_path))
        EncryptedFileBackend(_secrets(tmp_path)).set_secret("tunnel-pg", PASSWORD)
        monkeypatch.setattr("dbmcp.launcher.os.execv", lambda *a: None)
        monkeypatch.setattr("dbmcp.launcher.resolve_tool", lambda name: "/fake/uvx")
        result = _invoke(tmp_path, ["launch", "tunnel-pg"])
        assert result.exit_code == 0
        assert "not listening" not in result.stderr
    finally:
        listener.close()


def test_launch_unknown_tool_fails(tmp_path: Path, monkeypatch) -> None:
    _add_pg(tmp_path)

    def raise_not_found(name: str) -> str:
        raise DbmcpError(f"{name} not found")

    monkeypatch.setattr("dbmcp.launcher.resolve_tool", raise_not_found)
    result = _run(tmp_path, ["launch", "prod-pg"])
    assert result.exit_code == 1
    assert "not found" in result.stderr
    assert result.stdout == ""


# --- remove ---


def test_remove_deletes_profile_and_secret(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBMCP_PASSPHRASE", PASSPHRASE)
    _add_pg(tmp_path)
    result = _invoke(tmp_path, ["remove", "prod-pg"])
    assert result.exit_code == 0, result.output
    assert "removed profile 'prod-pg'" in result.output
    backend = EncryptedFileBackend(_secrets(tmp_path))
    assert backend.get_secret("prod-pg") is None
    assert "no profiles" in _invoke(tmp_path, ["list"]).output


def test_remove_warns_when_backend_unavailable(tmp_path: Path, monkeypatch) -> None:
    _add_pg(tmp_path)

    def boom(name: str):
        raise BackendUnavailable("keyring backend is fail.Keyring; use --backend encrypted-file")

    monkeypatch.setattr("dbmcp.cli.get_backend", boom)
    result = _invoke(tmp_path, ["remove", "prod-pg"])
    assert result.exit_code == 0, result.output
    assert "warning: secret not removed" in result.stderr
    assert "removed profile 'prod-pg'" in result.output


def test_remove_unknown_profile(tmp_path: Path) -> None:
    result = _run(tmp_path, ["remove", "nope"])
    assert result.exit_code == 1
    assert "profile not found" in result.stderr


# --- version / misc ---


def test_cli_has_version() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "version" in result.output


# --- resolve_tool (launcher) ---


def test_resolve_tool_finds_on_path(tmp_path: Path, monkeypatch) -> None:
    import dbmcp.launcher

    bindir = tmp_path / "bin"
    bindir.mkdir()
    tool = bindir / "fake-tool"
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    assert dbmcp.launcher.resolve_tool("fake-tool") == str(tool)


def test_resolve_tool_searches_extra_dirs(tmp_path: Path, monkeypatch) -> None:
    from pathlib import Path as _Path

    import dbmcp.launcher

    local_bin = tmp_path / ".local" / "bin"
    local_bin.mkdir(parents=True)
    tool = local_bin / "uravtool"
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)
    monkeypatch.setattr(_Path, "home", classmethod(lambda cls: tmp_path))
    assert dbmcp.launcher.resolve_tool("uravtool") == str(tool)


def test_resolve_tool_missing_raises() -> None:
    import dbmcp.launcher

    with pytest.raises(DbmcpError, match="not found"):
        dbmcp.launcher.resolve_tool("definitely-not-a-real-tool-xyzzy")
