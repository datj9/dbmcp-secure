# dbmcp — spec (rev 2)

> **Naming (post-build):** the pip distribution and CLI command are **`dbmcp-secure`**; the Python
> import package, config dir (`~/.config/dbmcp`), and `DBMCP_*` env vars stay **`dbmcp`** (packages
> can't contain a hyphen — same pattern as scikit-learn/`sklearn`). Command examples below written as
> `dbmcp` are invoked as `dbmcp-secure`.

A cross-platform (Linux + macOS) CLI that **configures, securely stores credentials for, tests,
and launches database MCP servers**. `dbmcp` does not implement a database driver or an MCP server
itself — it stores connection profiles + secrets, then execs the appropriate existing OSS MCP
server for each database type with the credential injected via environment (never argv/stdout).

- License: MIT. Public repo under GitHub user `datj9`. No proprietary lineage.
- Language: Python 3.10+. Installable via `uv`/`pipx`, exposing a `dbmcp` console script.
- Supported DB types (v1): **postgres, mysql, sqlite, redis**.
- Supported secret backends (v1): **OS keyring** (macOS Keychain / Linux Secret Service via the
  `keyring` package) with an **encrypted-file fallback** for headless Linux with no D-Bus.

Rev 2 folds in review findings: per-db `build_env` (mysql uses split vars, not a URL), non-tty prompt
ban, probe-based `test`, absolute-path resolution for `dbmcp`/`uvx`, deterministic secret redaction,
a concrete encrypted-file format, a keyring backend allowlist, and `validate_profile`.

---

## Glossary

- **profile** — a named connection config (`prod-pg`, `local-redis`). Non-secret fields live in a
  config file; the secret lives in the secret backend keyed by the profile name.
- **db_type** — `postgres | mysql | sqlite | redis`. Selects url scheme, the env the server reads,
  the launch argv, the readiness probe, and whether a secret is required.
- **mechanism** — `direct` or `tunnel`. `dbmcp` does NOT manage tunnels in v1 — it records that a
  profile expects one and warns (to stderr) if the local port is not listening.
- **backend** — where the secret is stored: `keyring` (default) or `encrypted-file`.
- **launch** — read profile + secret, build the per-db env, and `exec` the underlying MCP server over
  stdio. This is what MCP clients invoke.

---

## Non-negotiable invariants

1. **Secrets never touch argv, stdout, or logs.** Credentials reach the underlying server only via
   environment variables. `list`/`show`/`test` print `host:port/db` and `user`, never the secret.
2. **Passwords are percent-encoded** (`urllib.parse.quote(pw, safe="")`) whenever composed into a URL,
   so `[ ] ( ) | , * > < : @ /` never corrupt URL parsing.
3. **Deterministic secret redaction.** Every user-facing error string and `HandshakeResult.error` is
   passed through `redact(text, password)` which replaces `password`, `quote(password, safe="")`, and
   the full built url with `***`. Never rely on heuristic "contains `://`" scrubbing.
4. **No prompts on a non-tty.** If `not sys.stdin.isatty()` and a secret/passphrase is needed and not
   supplied via env/flag → exit 1 with a scrubbed message. `launch` is called by MCP clients with no
   tty and must never block on input.
5. **`launch` writes zero bytes to stdout before `exec`.** stdout is the MCP protocol channel. All
   diagnostics (tunnel warnings, errors) go to stderr. Asserted in `test_cli.py`.
6. **Read-only by default** where supported (postgres restricted mode).
7. **No network calls at import time.**

---

## Repo layout (Files)

```
dbmcp/
├── pyproject.toml            # deps: keyring, click, cryptography; console_scripts: dbmcp = dbmcp.cli:main
├── README.md                 # install, quickstart, security model, per-DB notes, backend matrix, caveats
├── LICENSE                   # MIT
├── src/dbmcp/
│   ├── __init__.py           # __version__
│   ├── cli.py                # click entrypoint: add, list, show, test, launch, emit, remove
│   ├── profiles.py           # Profile model, validate_profile, TOML load/save
│   ├── secrets.py            # SecretBackend protocol + KeyringBackend + EncryptedFileBackend + get_backend
│   ├── registry.py           # DB_TYPES: db_type -> DbTypeSpec (build_env, launch_argv, probe, needs_secret)
│   ├── url.py                # build_url(profile, password); redact(text, password)
│   ├── launcher.py           # launch(profile): resolve uvx, build env, exec server (zero stdout)
│   ├── handshake.py          # mcp_initialize + probe -> HandshakeResult
│   └── errors.py             # DbmcpError hierarchy
└── tests/
    ├── test_url.py           # percent-encoding ([ ) | , *), dbname override, sslmode, sqlite path, ipv6, redact()
    ├── test_registry.py      # each db_type: build_env + launch_argv + probe shape
    ├── test_profiles.py      # round-trip, unknown-field reject, validate_profile rules, missing file
    ├── test_secrets.py       # encrypted-file round-trip + wrong-passphrase InvalidTag; keyring allowlist mocked
    ├── test_handshake.py      # fake stdio server: ok, slow, timeout, probe isError -> FAIL
    └── test_cli.py           # add/list/show/remove/emit via CliRunner; secret never in output; stdout clean
```

- Config file: `${XDG_CONFIG_HOME:-~/.config}/dbmcp/profiles.toml` (dir 0700).
- Encrypted secret store: `${XDG_CONFIG_HOME:-~/.config}/dbmcp/secrets.enc` (file 0600).

---

## Contracts

### `registry.py`

```python
from dataclasses import dataclass
from collections.abc import Callable

@dataclass(frozen=True)
class DbTypeSpec:
    db_type: str
    scheme: str                     # "postgresql" | "mysql" | "redis" | "sqlite"
    needs_secret: bool              # sqlite: False; others: True
    default_port: int | None        # None for sqlite
    # Build the environment the underlying server reads. password is None for sqlite.
    build_env: Callable[["Profile", str | None], dict[str, str]]
    # Build the argv to exec (bare tool name at argv[0]; launcher resolves it to an absolute path).
    launch_argv: Callable[["Profile"], list[str]]
    # Readiness probe used by `test`: an MCP tools/call after initialize.
    probe: tuple[str, dict]         # (tool_name, arguments)

DB_TYPES: dict[str, DbTypeSpec]
def get_spec(db_type: str) -> DbTypeSpec:   # raises UnknownDbType
```

v1 registry (upstream package names to be confirmed against PyPI at build time; a wrong default is a
one-line registry fix — that indirection is the point. Record final choices in README):

| db_type  | scheme       | build_env(profile, pw)                                                                                  | launch_argv (argv[0] resolved to abs path)                                                        | probe |
|----------|--------------|---------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|-------|
| postgres | `postgresql` | `{"DATABASE_URI": build_url(profile, pw)}`                                                               | `uvx --from postgres-mcp --with mcp<2 postgres-mcp --access-mode restricted --transport stdio`     | `("list_schemas", {})` |
| mysql    | `mysql`      | `{"MYSQL_HOST":host,"MYSQL_PORT":str(port),"MYSQL_USER":user,"MYSQL_PASSWORD":pw,"MYSQL_DATABASE":dbname}` | `uvx --from mysql-mcp-server mysql_mcp_server`                                                     | `("execute_sql", {"query": "SELECT 1"})` |
| sqlite   | `sqlite`     | `{}`                                                                                                     | `uvx mcp-server-sqlite --db-path <abspath(dbname)>`                                                | `("list_tables", {})` |
| redis    | `redis`      | `{"REDIS_URL": build_url(profile, pw)}`                                                                  | `uvx redis-mcp-server`                                                                             | `("info", {})` |

Notes: mysql's server reads **discrete env vars, not a URL** — do not build a URL for it. `mcp<2` in
argv is a bare token, no shell quotes. `mcp-server-sqlite` is the archived reference server; either
keep it (document archived status in README) or swap for a maintained equivalent verified on PyPI.
Probe tool names must be confirmed against each server's actual tool list at build time; if a name
differs, use that server's cheapest read-only tool and record it in README.

### `profiles.py`

```python
@dataclass(frozen=True)
class Profile:
    name: str                       # ^[a-z0-9][a-z0-9_-]{0,63}$
    db_type: str
    host: str | None                # None for sqlite
    port: int | None
    user: str | None                # None for sqlite; validated ^[A-Za-z0-9_.-]+$
    dbname: str | None              # pg/mysql: db name; sqlite: file path; redis: numeric index string (^\d+$)
    sslmode: str | None             # postgres only; mysql/redis see notes
    mechanism: str                  # "direct" | "tunnel"
    backend: str                    # "keyring" | "encrypted-file"
    tls: bool                       # redis only: rediss:// when True (default False)
    mcp_server_argv: list[str] | None   # override registry default; None = use default

def load_profiles(path: Path | None = None) -> dict[str, Profile]     # {} if file missing
def get_profile(name: str, path: Path | None = None) -> Profile       # raises ProfileNotFound
def save_profile(profile: Profile, path: Path | None = None) -> None  # upsert by name; NEVER writes a secret
def delete_profile(name: str, path: Path | None = None) -> None

def validate_profile(p: Profile) -> None:   # raises ConfigError on any violation
    # db_type in DB_TYPES; mechanism in {direct,tunnel}; backend in {keyring,encrypted-file}
    # name matches pattern; user (if set) matches ^[A-Za-z0-9_.-]+$
    # non-sqlite: host and user and port required; 1 <= port <= 65535
    # sqlite: dbname required (a path); host/user/port must be None
    # postgres: sslmode in {disable,allow,prefer,require,verify-ca,verify-full} if set
    # redis: dbname (if set) matches ^\d+$
```

Config is TOML, one `[profiles.<name>]` table each. Unknown keys on load → `ConfigError` (fail fast).
Corrupt TOML → `ConfigError`, never a partial load.

### `secrets.py`

```python
class SecretBackend(Protocol):
    def set_secret(self, profile_name: str, secret: str) -> None: ...
    def get_secret(self, profile_name: str) -> str | None: ...   # None if absent
    def delete_secret(self, profile_name: str) -> None: ...

class KeyringBackend:
    # service = f"dbmcp:{profile_name}", username = getpass.getuser().
    # At use time: kr = keyring.get_keyring(); accept only macOS.Keyring, SecretService.Keyring,
    #   kwallet.DBusKeyring, or a keyring.backends.chainer whose members are all in that allowlist.
    #   Anything else (fail.Keyring, keyrings.alt Plaintext/Encrypted) -> BackendUnavailable telling
    #   the user to use `--backend encrypted-file`. Map keyring.errors.KeyringLocked / InitError
    #   to BackendUnavailable with a scrubbed message.

class EncryptedFileBackend:
    # Passphrase from env DBMCP_PASSPHRASE, else click.prompt(hide_input=True) IFF stdin.isatty(),
    #   else BackendUnavailable (invariant 4). File format (secrets.enc):
    #     bytes: magic b"DBMCP1" (6) | salt(16) | nonce(12) | ciphertext
    #     key = scrypt(passphrase, salt, n=2**17, r=8, p=1, dklen=32)
    #     AES-256-GCM, AAD = magic+salt+nonce, plaintext = JSON {profile_name: secret, ...}
    #     write via tmpfile + fsync + os.replace; file 0600, dir 0700
    #   cryptography.exceptions.InvalidTag -> ConfigError("wrong passphrase or corrupt secrets.enc")

def get_backend(name: str) -> SecretBackend   # "keyring"|"encrypted-file"; else ConfigError
```

### `url.py`

```python
def build_url(profile: Profile, password: str | None) -> str
def redact(text: str, password: str | None) -> str
```

- postgres: `postgresql://{user}:{quote(pw)}@{H}:{P}/{dbname}` + `?sslmode={sslmode}` if set.
- redis: `{rediss if profile.tls else redis}://{user or ''}:{quote(pw)}@{H}:{P}/{dbname or 0}`.
- sqlite: `sqlite:///{abspath(dbname)}` — no host/user/secret.
- mysql: build_url is NOT used (mysql uses discrete env vars). Calling it for mysql → `UrlError`.
- `quote(pw, safe="")`. `user` never encoded (validated at add). IPv6 host (contains `:`) wrapped in `[...]`.
- Missing required field for the db_type → `UrlError`.
- `redact(text, pw)` → replace each of `pw`, `quote(pw, safe="")`, and `build_url(...)` with `***`
  when `pw` is truthy; returns `text` unchanged when `pw` is None.

### `handshake.py`

```python
@dataclass(frozen=True)
class HandshakeResult:
    status: str                     # "OK" | "SLOW" | "FAIL"
    elapsed_seconds: float
    error: str | None               # already redacted

def mcp_initialize(argv: list[str], env: dict[str, str], probe: tuple[str, dict],
                   password: str | None, timeout: float = 40.0) -> HandshakeResult
```

Protocol (newline-delimited JSON-RPC over the child's stdio):
1. Send `initialize` params `{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"dbmcp","version":__version__}}`; read the first response line; require `"result"`.
2. Send `notifications/initialized`.
3. Send `tools/call` with `{"name": probe[0], "arguments": probe[1]}`; read response.
4. `FAIL` if: child exits early, no response before `timeout`, initialize lacks `result`, or the probe
   response has `error` or `result.isError == true`. Otherwise status by elapsed:
   `OK` if elapsed < 10s, `SLOW` if 10s ≤ elapsed < timeout.
- Read stderr on a thread (or `communicate`) to avoid pipe deadlock. Terminate child: SIGTERM, then
  SIGKILL after 2s. `error` runs through `redact(..., password)`.

### `launcher.py`

```python
def resolve_tool(name: str) -> str   # shutil.which(name) or search ~/.local/bin, ~/.cargo/bin,
                                      # /opt/homebrew/bin, /usr/local/bin; else DbmcpError "<name> not found"
def launch(profile: Profile) -> NoReturn   # build env, os.execv the resolved argv[0]; writes nothing to stdout
```

`launch` resolves `argv[0]` (typically `uvx`) via `resolve_tool` because macOS GUI clients run with a
minimal PATH. On missing secret for a `needs_secret` profile → exit 1 `secret missing for '<name>'; re-run add`.

### `errors.py`

`DbmcpError` (base) → `ConfigError`, `ProfileNotFound`, `UnknownDbType`, `UrlError`,
`BackendUnavailable`, `SecretNotFound`, `HandshakeError`. `main()` catches `DbmcpError`, prints the
(already-redacted) message to stderr, exits 1. No stack traces to stdout/stderr on expected errors.

### CLI (`cli.py`)

```
dbmcp add <name> --type <t> [--host H --port P --user U --dbname D --sslmode S]
                 [--mechanism direct|tunnel] [--backend keyring|encrypted-file] [--tls]
                 [--server-argv '<override>'] [--password-stdin] [--force]
dbmcp list                          # table: name, type, host:port/db, mechanism, backend (NO secret)
dbmcp show <name>                   # one profile + resolved launch argv, secret-free; --server-argv printed verbatim
dbmcp test <name>                   # mcp_initialize + probe; prints "OK <e>s" | "SLOW <e>s (>10s)" | "FAIL <err>"
dbmcp launch <name>                 # exec underlying server over stdio (what MCP clients call)
dbmcp emit <name> [--client claude-code|claude-desktop]   # print MCP client JSON block
dbmcp remove <name>                 # delete profile + secret (if backend unavailable: remove profile, warn secret left)
```

- `add`: password via `click.prompt("Password", hide_input=True)` when tty, or `--password-stdin`
  (read one line from stdin) otherwise. `--type sqlite` needs no password. Runs `validate_profile`
  before saving. Duplicate name → confirm (or `--force`) then overwrite profile + rotate secret.
- `emit` resolves the `dbmcp` command to an absolute path via `shutil.which("dbmcp")`:
  - `--client claude-code` (default):
    ```json
    { "mcpServers": { "<name>": { "type": "stdio", "command": "<abs dbmcp>", "args": ["launch","<name>"], "env": {} } } }
    ```
  - `--client claude-desktop`: same but no `"type"` key.
  - If `backend == "encrypted-file"`, `env` includes `"DBMCP_PASSPHRASE": "<fill-in>"` and a stderr
    note warns the passphrase will live in the client config (trade-off documented in README).
- All commands exit non-zero with a redacted message on error; no stack traces to stdout.

---

## Behavior & edge cases

- Password with `[ ) | , *` → stored raw; percent-encoded only when the URL is built → the server
  parses it correctly. (The concrete bug that motivated the tool.)
- `--mechanism tunnel` + local port not listening on `test`/`launch` → warn to **stderr**, still attempt.
- postgres `dbname` overrides the URL path; `sslmode` preserved as query param. mysql db name goes to
  `MYSQL_DATABASE`. redis `dbname` is the numeric DB index. sqlite `dbname` is a file path (→ abspath).
- Duplicate `add <name>` → upsert after confirm/`--force` (overwrite profile, rotate secret).
- `remove`/`test`/`launch`/`show` on unknown name → exit 1 `profile not found`.
- Missing config file → `list` prints "no profiles", exit 0.
- Non-tty + secret needed + no env/flag → exit 1 (invariant 4). encrypted-file `launch` reads
  `DBMCP_PASSPHRASE` from env only.
- `uvx` (or override argv[0]) not resolvable → exit 1 `<tool> not found`.

---

## Worked example

```
$ dbmcp add prod-pg --type postgres --host 10.0.0.5 --port 5432 --user dbo --dbname appdb --sslmode require
Password: ****************        # hidden; value K)|UzFe[...]* contains [ ) | , *
stored secret for 'prod-pg' (keyring); profile written to ~/.config/dbmcp/profiles.toml

$ dbmcp list
NAME     TYPE      TARGET               MECH    BACKEND
prod-pg  postgres  10.0.0.5:5432/appdb  direct  keyring

# launch sets env DATABASE_URI to the url below (shown ONLY to specify behavior — never printed):
#   postgresql://dbo:K%29%7CUzFe%5B...%2A@10.0.0.5:5432/appdb?sslmode=require
#   ) -> %29, | -> %7C, [ -> %5B, * -> %2A  → urllib.parse.urlsplit no longer raises "Invalid IPv6 URL"

$ dbmcp test prod-pg          # initialize, then tools/call list_schemas
OK 3.4s

$ dbmcp emit prod-pg --client claude-code
{ "mcpServers": { "prod-pg": { "type": "stdio", "command": "/Users/you/.local/bin/dbmcp",
                               "args": ["launch","prod-pg"], "env": {} } } }
```

The MCP client then calls `dbmcp launch prod-pg`, which resolves `uvx`, sets `DATABASE_URI`, and execs
`uvx --from postgres-mcp --with mcp<2 postgres-mcp --access-mode restricted --transport stdio`.

---

## Acceptance

- [ ] `pip install -e . && dbmcp --help` works on macOS and Linux.
- [ ] `add → list → test → emit → remove` round-trips for postgres, mysql, sqlite, redis (sqlite no
      password; others with a password containing `[ ) | , *`).
- [ ] `test` uses initialize **+ probe**: a deliberately wrong password reports `FAIL` (probe errors),
      never `OK`, and never hangs past the 40s timeout; a healthy DB reports `OK`/`SLOW` with elapsed.
- [ ] No command prints the password or a full connection URL — asserted in `test_cli.py`; `launch`
      writes zero bytes to stdout before exec — asserted in `test_cli.py`.
- [ ] `build_url` percent-encodes the password; a `[`-containing password yields a URL that
      `urllib.parse.urlsplit` parses without raising — asserted in `test_url.py`. `redact()` masks
      raw + encoded password and the url.
- [ ] `EncryptedFileBackend` round-trips and raises `ConfigError` on wrong passphrase; keyring
      allowlist rejects `fail.Keyring`/plaintext — asserted in `test_secrets.py`.
- [ ] `validate_profile` rejects bad port, bad sslmode, sqlite-with-host, missing host/user — `test_profiles.py`.
- [ ] `ruff check` + `ruff format --check` clean; `pytest` ≥ 80% line coverage.
- [ ] README documents install, the 4 DB types + their upstream servers (incl. sqlite archive status),
      the macOS/Linux secret-backend matrix (incl. macOS Keychain ACL re-prompt on `uv tool upgrade`,
      and the encrypted-file passphrase-in-client-config trade-off), read-only-role guidance, cold-`uvx`
      >10s SLOW note, and the tunnel caveat.

---

## Out of scope (v1)

- Managing SSH/IAP tunnels (only detect + warn). `dbmcp tunnel` is phase 2.
- Windows Credential Manager backend — phase 2.
- MongoDB, MSSQL — phase 2 (registry makes them additive).
- Writing to the MCP client config file directly — `emit` prints a block the user pastes.
- Any database write path — the tool targets read-only MCP usage.
```
