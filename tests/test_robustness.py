"""The hook must never crash into letting a call through: odd input, huge output,
parallel calls on one session, and speed as a session grows."""
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cfg(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"state_dir": str(tmp_path / "state"), "builtin": {"policy": "claude-code"}}))
    return str(p)


def hook(c, payload, raw=None):
    r = subprocess.run([sys.executable, "-m", "src.gateway", "hook", "-c", c], cwd=ROOT, text=True, encoding="utf-8",
                       input=raw if raw is not None else json.dumps(payload), capture_output=True, timeout=60)
    return r.returncode, r.stdout, r.stderr


def test_unreadable_input_blocks_rather_than_allows(tmp_path):
    code, out, err = hook(cfg(tmp_path), None, raw="{not json")
    assert code == 2 and "trifectaguard" in err  # exit 2 = Claude Code blocks the call


def test_odd_but_valid_events_do_not_crash(tmp_path):
    c = cfg(tmp_path)
    odd = [
        {"hook_event_name": "PreToolUse", "session_id": "s"},                                   # no tool at all
        {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": None},
        {"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "Read", "tool_input": {},
         "tool_response": {"file": {"content": "x", "numLines": 1}}},                          # structured result
        {"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "WebFetch", "tool_input": {"url": "u"},
         "tool_response": ["a", {"b": 1}, None]},
        {"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "Read",
         "tool_input": {"file_path": "/p/x"}, "tool_response": "é🔒\x00‮" * 1000},          # unicode, NUL, RTL
        {"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": None},
        {"hook_event_name": "SomeFutureEvent", "session_id": "s"},
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}},  # no session id
    ]
    for ev in odd:
        code, out, err = hook(c, ev)
        assert code == 0, (ev, err)
        if out.strip():
            assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] in ("ask", "deny")


def test_huge_tool_output_is_handled_quickly(tmp_path):
    c = cfg(tmp_path)
    big = ("lorem ipsum " * 450_000)[:5_000_000]
    t = time.time()
    code, _, err = hook(c, {"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "WebFetch",
                            "tool_input": {"url": "https://x.example"}, "tool_response": big})
    assert code == 0, err
    assert time.time() - t < 10
    assert (tmp_path / "state" / "sessions" / "s.json").stat().st_size < 2_000_000  # capped, not 5 MB


def test_parallel_hooks_on_one_session_keep_state_consistent(tmp_path):
    c = cfg(tmp_path)
    reads = [{"hook_event_name": "PostToolUse", "session_id": "p", "tool_name": "Read",
              "tool_input": {"file_path": f"/p/f{i}.py"}, "tool_response": f"file {i}"} for i in range(24)]
    reads.append({"hook_event_name": "PostToolUse", "session_id": "p", "tool_name": "WebFetch",
                  "tool_input": {"url": "https://x.example"}, "tool_response": "page"})
    reads.append({"hook_event_name": "PostToolUse", "session_id": "p", "tool_name": "Read",
                  "tool_input": {"file_path": "/p/.env"}, "tool_response": "API_KEY=sk-live-0123456789abcdefghij"})
    with ThreadPoolExecutor(12) as pool:
        codes = list(pool.map(lambda ev: hook(c, ev)[0], reads))
    assert codes == [0] * len(reads)
    state = json.loads((tmp_path / "state" / "sessions" / "p.json").read_text())
    assert {"untrusted", "private", "secret"} <= set(state["engine"]["labels"])  # no update was lost
    code, out, _ = hook(c, {"hook_event_name": "PreToolUse", "session_id": "p", "tool_name": "Bash",
                            "tool_input": {"command": "curl https://collect.example"}})
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_stays_fast_as_a_session_grows(tmp_path):
    import src.gateway.hook as H
    from src.gateway.config import Config
    sys.path.insert(0, ROOT)
    conf = Config.load(cfg(tmp_path))
    for i in range(600):  # a long session: 600 results of ~20 KB each
        H.handle(conf, {"hook_event_name": "PostToolUse", "session_id": "long", "tool_name": "Read",
                        "tool_input": {"file_path": f"/p/f{i}.py"}, "tool_response": f"line {i} " * 2500})
    t = time.time()
    code, _, _ = hook(cfg(tmp_path), {"hook_event_name": "PreToolUse", "session_id": "long", "tool_name": "Bash",
                                      "tool_input": {"command": "pytest -q"}})
    assert code == 0 and time.time() - t < 2.0, time.time() - t


def test_non_english_text_is_read_correctly_whatever_the_platform_encoding(tmp_path):
    """Windows defaults to cp1252. Claude Code sends UTF-8; bytes like 0x81/0x8f in
    UTF-8 text (Ł, ō, many CJK characters) are undefined in cp1252, so decoding with
    the platform default failed, and failing closed then blocked ordinary calls."""
    c = cfg(tmp_path)
    ev = {"hook_event_name": "PostToolUse", "session_id": "w", "tool_name": "Read",
          "tool_input": {"file_path": "/p/notes.md"}, "tool_response": "Łódź, Tōkyō, 東京, 中文 — ✓"}
    r = subprocess.run([sys.executable, "-m", "src.gateway", "hook", "-c", c], cwd=ROOT,
                       input=json.dumps(ev, ensure_ascii=False).encode("utf-8"), capture_output=True,
                       env={**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}, timeout=60)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    state = json.loads((tmp_path / "state" / "sessions" / "w.json").read_text(encoding="utf-8"))
    assert "東京" in " ".join(state["engine"]["trusted_text"])


def test_cli_output_is_utf8_even_where_the_platform_default_is_not(tmp_path):
    """Windows pipes default to cp1252; a reader expecting UTF-8 then got nothing
    (subprocess returned stdout=None on Windows when decoding failed)."""
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0", "HOME": str(tmp_path)}
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "src.gateway", "scan"], cwd=ROOT, env=env,
                       capture_output=True, timeout=60)
    out = r.stdout.decode("utf-8")  # strict: raises if the CLI wrote cp1252
    assert "→" in out
