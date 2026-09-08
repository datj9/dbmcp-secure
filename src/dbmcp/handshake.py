"""MCP handshake (initialize + probe) over stdio."""

import json
import os
import selectors
import subprocess
import threading
import time
from dataclasses import dataclass

from dbmcp import __version__
from dbmcp.errors import HandshakeError
from dbmcp.url import redact


@dataclass(frozen=True)
class HandshakeResult:
    status: str  # "OK" | "SLOW" | "FAIL"
    elapsed_seconds: float
    error: str | None


def mcp_initialize(
    argv: list[str],
    env: dict[str, str],
    probe: tuple[str, dict],
    password: str | None,
    timeout: float = 40.0,
) -> HandshakeResult:
    start = time.monotonic()
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, **env},
        text=True,
    )

    stderr_lines: list[str] = []

    def read_stderr() -> None:
        if proc.stderr is None:
            return
        for line in iter(proc.stderr.readline, ""):
            if not line:
                break
            stderr_lines.append(line)

    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stderr_thread.start()

    def send(method: str, params: dict, msg_id: int | None) -> None:
        assert proc.stdin is not None
        payload: dict = {"jsonrpc": "2.0", "method": method, "params": params}
        if msg_id is not None:
            payload["id"] = msg_id
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()

    def recv(expected_id: int, timeout_seconds: float) -> dict:
        assert proc.stdout is not None
        deadline = time.monotonic() + timeout_seconds
        with selectors.DefaultSelector() as sel:
            sel.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HandshakeError("timeout waiting for response")
                if not sel.select(remaining):
                    raise HandshakeError("timeout waiting for response")
                line = proc.stdout.readline()
                if line:
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise HandshakeError(f"invalid JSON from server: {line}") from exc
                    if msg.get("id") == expected_id:
                        return msg
                    if "id" in msg:
                        continue
                    # notification/response without id; ignore
                if proc.poll() is not None:
                    raise HandshakeError("child process exited before response")

    try:
        send(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "dbmcp", "version": __version__},
            },
            1,
        )
        init = recv(1, timeout)
        if "result" not in init:
            raise HandshakeError(f"initialize failed: {init}")

        send("notifications/initialized", {}, None)

        send("tools/call", {"name": probe[0], "arguments": probe[1]}, 2)
        probe_resp = recv(2, timeout)
    except Exception as exc:  # noqa: BLE001
        _terminate(proc)
        elapsed = time.monotonic() - start
        error = redact(str(exc), password)
        return HandshakeResult(status="FAIL", elapsed_seconds=elapsed, error=error)
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        stderr_thread.join(timeout=2)
        _terminate(proc)

    elapsed = time.monotonic() - start

    result = probe_resp.get("result", {})
    if "error" in probe_resp or result.get("isError"):
        error = redact(f"probe failed: {probe_resp}", password)
        return HandshakeResult(status="FAIL", elapsed_seconds=elapsed, error=error)

    if elapsed < 10.0:
        status = "OK"
    elif elapsed < timeout:
        status = "SLOW"
    else:
        status = "FAIL"
        error = f"probe timeout after {elapsed:.1f}s"
        return HandshakeResult(
            status="FAIL", elapsed_seconds=elapsed, error=redact(error, password)
        )

    return HandshakeResult(status=status, elapsed_seconds=elapsed, error=None)


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:
            pass
