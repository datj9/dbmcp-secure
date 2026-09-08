# dbmcp-secure

Configure, securely store credentials for, test, and launch **database MCP servers**.

`dbmcp` does not implement a database driver or an MCP server itself. It stores
connection profiles (non-secret) plus one secret per profile, then `exec`s the
appropriate existing OSS MCP server for each database type with the credential
injected via **environment variables** — never argv, stdout, or logs.

- Language: Python 3.10+
- License: MIT
- Supported DB types (v1): **postgres, mysql, sqlite, redis**
- Secret backends (v1): **OS keyring** (macOS Keychain / Linux Secret Service)
  with an **encrypted-file fallback** for headless Linux with no D-Bus.

## Install

```sh
uv tool install .        # or: pip install -e . / pipx install .
dbmcp-secure --help
```

The pip distribution is named **`dbmcp-secure`**; the Python import package
stays `dbmcp` (mirroring how scikit-learn installs as `scikit-learn` but
imports as `sklearn`).

## Quickstart

```sh
# Store a postgres profile + secret in the OS keyring
dbmcp-secure add prod-pg --type postgres --host 10.0.0.5 --port 5432 \
    --user dbo --dbname appdb --sslmode require

dbmcp-secure list                 # table: name, type, host:port/db, mechanism, backend
dbmcp-secure show prod-pg         # profile + resolved launch argv (no secret)
dbmcp-secure test prod-pg         # MCP initialize + probe: "OK 3.4s" | "SLOW ..." | "FAIL ..."
dbmcp-secure emit prod-pg --client claude-code
dbmcp-secure remove prod-pg       # deletes profile + secret

# sqlite needs no password:
dbmcp-secure add local-sqlite --type sqlite --dbname /path/to/app.db
```

Non-interactive use (MCP clients, scripts) reads the secret from stdin:

```sh
printf '%s\n' "$PGPASSWORD" | dbmcp-secure add prod-pg --type postgres \
    --host ... --user ... --dbname ... --password-stdin
```

### Launch: what MCP clients call

`dbmcp-secure launch <name>` resolves `uvx` (or the per-profile `--server-argv`
override), builds the per-db environment, and `exec`s the underlying MCP server
over stdio. **`launch` writes zero bytes to stdout before `exec`** — stdout is
the MCP protocol channel. Diagnostics go to stderr only.

Point your MCP client at the emitted block:

```json
{
  "mcpServers": {
    "prod-pg": {
      "type": "stdio",
      "command": "/absolute/path/to/dbmcp-secure",
      "args": ["launch", "prod-pg"],
      "env": {}
    }
  }
}
```

`dbmcp-secure emit <name> --client claude-code` prints this block for you (absolute
`dbmcp-secure` path, resolved via `shutil.which`). `--client claude-desktop` omits the
`"type"` key.

## Security model

- **Secrets never touch argv, stdout, or logs.** `list`/`show`/`test` print
  `host:port/db` and `user`, never the secret. Credentials reach the server only
  via environment variables.
- **Passwords are percent-encoded** (`urllib.parse.quote(pw, safe="")`)
  whenever composed into a URL, so characters like `[ ] ( ) | , * > < : @ /`
  never corrupt URL parsing. (The concrete bug that motivated this tool: a
  `[`-containing password made `urlsplit` raise *"Invalid IPv6 URL".*)
- **Deterministic secret redaction.** Every user-facing error string and
  `HandshakeResult.error` passes through `redact(text, password)`, which
  replaces the raw password, its percent-encoded form, and any URL constructed
  from it with `***`. No heuristic "contains `://`" scrubbing.
- **No prompts on a non-tty.** If `stdin.isatty()` is false and a
  secret/passphrase is needed without an env/flag source, `dbmcp` exits 1 with
  a scrubbed message. `launch` never blocks on input.
- **No network calls at import time.**

## Database types

| db_type  | scheme       | env passed to the server                                   | server (resolved via uvx at launch)                     | probe (read-only)          |
|----------|--------------|-------------------------------------------------------------|---------------------------------------------------------|----------------------------|
| postgres | `postgresql` | `DATABASE_URI` (full URL)                                   | `postgres-mcp --access-mode restricted --transport stdio` | `list_schemas`             |
| mysql    | `mysql`      | discrete `MYSQL_HOST/PORT/USER/PASSWORD/DATABASE` vars      | `mysql-mcp-server` → `mysql_mcp_server`                 | `execute_sql` `SELECT 1`   |
| sqlite   | `sqlite`     | none                                                        | `mcp-server-sqlite --db-path <abspath>`                 | `list_tables`              |
| redis    | `redis`      | `REDIS_URL` (full URL; `rediss://` when `--tls`)            | `redis-mcp-server`                                      | `info`                     |

Notes:

- **mysql uses discrete environment variables, not a URL.** `dbmcp` never builds
  a URL for it.
- **sqlite is the archived reference server.** `mcp-server-sqlite` is no longer
  maintained; it remains the default because it is the reference stdio
  implementation and still works for local files. Swap it via
  `--server-argv` for a maintained equivalent.
- Upstream package names were confirmed against PyPI at build time; if a default
  is wrong it is a one-line fix in `src/dbmcp/registry.py` (the registry
  indirection is the point). Probe tool names match each server's cheapest
  read-only tool.

### Read-only role guidance

`postgres-mcp` is launched with `--access-mode restricted` (read-only). For
other servers, connect with a database role that has read-only privileges — the
tool targets read-only MCP usage and has **no write path** by design.

### Cold `uvx` note

The first `uvx` run downloads and builds the server tool; on a cold cache this
can take longer than 10s, so `dbmcp-secure test` will report `SLOW` (not `FAIL`).
`OK` means the handshake completed in under 10s.

### Tunnel caveat

`--mechanism tunnel` only *records* that a profile expects a tunnel — v1 does
not manage SSH/IAP tunnels. On `test`/`launch`, `dbmcp` warns to **stderr** if
the local port is not listening, then still attempts the connection.

## Secret backends

| Backend         | macOS                    | Linux                                  |
|-----------------|--------------------------|----------------------------------------|
| `keyring` (default) | Keychain                | Secret Service (D-Bus) / KWallet       |
| `encrypted-file`   | supported (passphrase)  | supported (passphrase; headless-safe)  |

- `get_backend()` only accepts the OS keyring backends or a keyring chainer
  whose members are all in the allowlist. `fail.Keyring` (no backend
  configured) and plaintext/encrypted *file* keyrings are rejected with
  "use `--backend encrypted-file`".
- **macOS Keychain ACL re-prompt:** the Keychain entry created for `dbmcp` is
  tied to the executable that stored it. `uv tool upgrade` replaces the
  `uvx`/`dbmcp-secure` binary, which can trigger an ACL re-prompt (or a denial) the
  next time the secret is read. Re-run `dbmcp-secure add <name>` to re-store the
  secret if the keychain no longer returns it.
- **encrypted-file trade-off:** the fallback backend encrypts
  `secrets.enc` (scrypt-derived key, AES-256-GCM; see below) with a passphrase
  from `$DBMCP_PASSPHRASE` or an interactive prompt. `dbmcp-secure emit` will warn that
  the passphrase then lives in the MCP client config file. Acceptable for
  headless Linux; prefer the OS keyring where a login keyring exists.

### Encrypted-file format (`secrets.enc`)

```
magic "DBMCP1" (6) | salt (16) | nonce (12) | AES-256-GCM ciphertext
key = scrypt(passphrase, salt, n=2**17, r=8, p=1, dklen=32)
AAD = magic + salt + nonce
plaintext = JSON { "<profile_name>": "<secret>", ... }
```

Written atomically: tmp file + `fsync` + `os.replace`; file mode `0600`,
directory `0700`. Wrong passphrase or corruption raises
`ConfigError("wrong passphrase or corrupt secrets.enc")`.

## Configuration

- Profiles: `${XDG_CONFIG_HOME:-~/.config}/dbmcp/profiles.toml` (TOML,
  `[profiles.<name>]` tables; directory mode `0700`). Unknown keys on load
  fail fast with `ConfigError`.
- Secrets: `${XDG_CONFIG_HOME:-~/.config}/dbmcp/secrets.enc` (file mode `0600`).

## Development

```sh
uv sync --extra dev        # or: pip install -e '.[dev]'
ruff check .
ruff format --check .
pytest
pytest --cov=dbmcp --cov-report=term-missing   # >= 80% line coverage
```

## Caveats & out of scope (v1)

- Tunnel management (`dbmcp-secure tunnel`) is phase 2 — detect + warn only.
- Windows Credential Manager is phase 2.
- MongoDB/MSSQL are phase 2 (the registry makes them additive).
- `dbmcp` does not write your MCP client config — `emit` prints a block you paste.
- No database write path; the tool targets read-only MCP usage.