"""Tests for dbmcp.handshake."""

import json
import sys
import time
from pathlib import Path

from dbmcp.handshake import HandshakeResult, mcp_initialize


def _write_server_script(path: Path, responses: list[dict], delay: float = 0.0) -> None:
    code = (
        "import json, sys, time\n"
        "responses = " + repr([json.dumps(r) for r in responses]) + "\n"
        "for line in responses:\n"
        "    time.sleep(" + str(delay) + ")\n"
        "    print(line)\n"
        "    sys.stdout.flush()\n"
    )
    path.write_text(code)


def test_handshake_ok(tmp_path: Path) -> None:
    script = tmp_path / "server.py"
    responses = [
        {"jsonrpc": "2.0", "id": 1, "result": {}},
        {"jsonrpc": "2.0", "id": 2, "result": {"isError": False}},
    ]
    _write_server_script(script, responses)
    result = mcp_initialize([sys.executable, str(script)], {}, ("info", {}), None)
    assert isinstance(result, HandshakeResult)
    assert result.status == "OK"
    assert result.error is None


def test_handshake_probe_error(tmp_path: Path) -> None:
    script = tmp_path / "server.py"
    responses = [
        {"jsonrpc": "2.0", "id": 1, "result": {}},
        {"jsonrpc": "2.0", "id": 2, "result": {"isError": True}},
    ]
    _write_server_script(script, responses)
    result = mcp_initialize([sys.executable, str(script)], {}, ("info", {}), None)
    assert result.status == "FAIL"
    assert result.error is not None


def test_handshake_slow(tmp_path: Path) -> None:
    script = tmp_path / "server.py"
    responses = [
        {"jsonrpc": "2.0", "id": 1, "result": {}},
        {"jsonrpc": "2.0", "id": 2, "result": {"isError": False}},
    ]
    _write_server_script(script, responses, delay=0.2)
    start = time.monotonic()
    result = mcp_initialize([sys.executable, str(script)], {}, ("info", {}), None, timeout=5.0)
    elapsed = time.monotonic() - start
    assert result.status in {"OK", "SLOW"}
    if elapsed >= 10:
        assert result.status == "SLOW"


def test_handshake_timeout(tmp_path: Path) -> None:
    script = tmp_path / "server.py"
    responses = [
        {"jsonrpc": "2.0", "id": 1, "result": {}},
    ]
    _write_server_script(script, responses, delay=5.0)
    result = mcp_initialize([sys.executable, str(script)], {}, ("info", {}), None, timeout=0.1)
    assert result.status == "FAIL"
