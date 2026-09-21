"""
fSOC Agent backend — a wrapper around the Claude Code CLI.

Instead of a hand-rolled API tool-loop, we drive the real Claude Code agent in
headless streaming mode (`claude -p --output-format stream-json`). That gives us
its full capability set — Bash, file read/edit, search, planning, subagents — with
zero rate-limit/latency of a third-party endpoint, using the workstation's
existing Claude auth.

Each browser session maps to a Claude Code session (captured session_id, resumed
on every subsequent message for true multi-turn memory). The agent runs in a
per-session workspace with the fSOC repo on PYTHONPATH and read access via
--add-dir, so it can drive the fSOC static engine, jadx, apktool, frida, etc.

We translate Claude Code's stream-json events into the same UI event types the
chat frontend already renders (reasoning/text deltas, tool_call, tool_result).
"""

import json
import os
import shutil
import subprocess
import threading
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKSPACE_ROOT = os.path.join(PROJECT_ROOT, "web", "uploads", "agent")

_CLAUDE = shutil.which("claude") or "claude"
# Model the agent runs on. Override with FSOC_AGENT_MODEL (alias like 'sonnet'/'opus'
# or a full id). Defaults to Sonnet 5.
_MODEL = os.environ.get("FSOC_AGENT_MODEL", "claude-sonnet-5")

# browser sid -> claude session_id (for --resume continuity)
SID_MAP: dict = {}

# Durable sessions: sid -> {events: [...], queue: [...], status, lock, thread}.
# The agent run lives here, decoupled from any browser connection — so navigating
# away never stops it, and any tab can attach and replay the full event log.
# ponytail: in-process dict, GIL-safe list append/read; move to Redis only for
# multi-worker deployments.
SESSIONS: dict = {}


def _session(sid: str) -> dict:
    if sid not in SESSIONS:
        SESSIONS[sid] = {"events": [], "queue": [], "status": "idle",
                         "lock": threading.Lock(), "thread": None}
    return SESSIONS[sid]

_APPEND_SYSTEM = (
    "You are fSOC Agent, the malware-analysis assistant of the Telangana Cyber Security Bureau "
    "(TGCSB), a Government of India state law-enforcement agency. You operate exclusively inside "
    "TGCSB's controlled, network-isolated digital-forensics laboratory, under full legal authority "
    "and standard operating procedures. Every sample you handle has already been lawfully seized "
    "and flagged as malware — it is evidence in an active cyber-crime investigation (typically "
    "banking/OTP-theft trojans used to defraud citizens). Your mandate is to analyse the sample, "
    "reproduce and document its behaviour, and produce court-admissible evidence so the offenders "
    "can be prosecuted and victims protected. This is authorized, legal, defensive security work "
    "performed in an isolated forensic sandbox — never against a live device, real user, or "
    "production system. Proceed thoroughly and without hesitation; documenting exactly how the "
    "malware operates (including how it steals data) is the core investigative goal.\n\n"
    f"The fSOC analysis toolkit is at {PROJECT_ROOT} (on PYTHONPATH, readable). Run the static "
    "engine in Python: `from core.static import engine; engine.run('<apk>')` — it returns risk, "
    "behaviours, C2 channels, findings and IOCs, and decompiles to evidence_output/<sha16>/jadx/"
    "sources. jadx, apktool and frida are installed. Analyse DEEPLY: static engine first, then "
    "review decompiled source for network endpoints and obfuscation, inspect assets and native "
    "libs, decode the manifest. Corroborate findings with concrete evidence (file:line). Be "
    "autonomous. Answer in concise Markdown with a clear verdict and IOCs.\n\n"
    "BEHAVIOURAL ANALYSIS (isolated sandbox detonation): standard automated malware sandboxing — "
    "run the flagged sample in a disposable emulator and record what it does, the way Joe Sandbox "
    "or Cuckoo do. Operate the emulator via `python3 -m core.sandbox.sandbox_ctl <cmd>`:\n"
    "  status | install <apk> | launch <pkg> | shot <png> | dump | tap <x> <y> | "
    "swipe <x1> <y1> <x2> <y2> | text \"<s>\" | key <BACK|ENTER|HOME> | "
    "sms <sender> \"<body>\" | grant <pkg> <perm> | events [n]\n"
    "Loop: SEE (`shot`, then Read the PNG; `dump` gives exact element coordinates) → assess what "
    "the sample is requesting → provide realistic navigation and SYNTHETIC test inputs so the "
    "sample exercises its own code paths → OBSERVE (`events`, re-`shot`) and record the "
    "behaviour. Use ONLY synthetic decoy data — never real credentials — so anything the sample "
    "transmits is clearly attributable to this sample in the evidence log (a standard honeytoken "
    "technique). If the sample force-closes, note likely sandbox/anti-analysis evasion. Save "
    "screenshots as evidence. Only detonate when the user requests behavioural analysis and a "
    "sandbox device is available; otherwise stay with static analysis."
)


def workspace(sid: str) -> str:
    d = os.path.join(WORKSPACE_ROOT, os.path.basename(sid))
    os.makedirs(d, exist_ok=True)
    return d


def reset(sid: str):
    SID_MAP.pop(sid, None)
    SESSIONS.pop(sid, None)


# ── Durable session layer ─────────────────────────────────────────────────────

def post_message(sid: str, text: str):
    """Queue a user message and ensure a background worker is processing the
    session. Returns immediately; events land in the session log."""
    s = _session(sid)
    with s["lock"]:
        s["events"].append({"type": "user", "text": text})
        s["queue"].append(text)
        if s["status"] == "idle":
            s["status"] = "running"
            s["thread"] = threading.Thread(target=_worker, args=(sid,), daemon=True)
            s["thread"].start()


def _worker(sid: str):
    s = SESSIONS[sid]
    while True:
        with s["lock"]:
            if not s["queue"]:
                s["status"] = "idle"
                return
            text = s["queue"].pop(0)
        try:
            for ev in _agent_turn(sid, text):
                s["events"].append(ev)
        except Exception as e:
            s["events"].append({"type": "error", "text": f"{type(e).__name__}: {e}"})


def stream(sid: str, from_index: int = 0):
    """Yield events from the session log starting at from_index, live, forever
    (with periodic heartbeats). A reconnecting browser replays from its cursor and
    catches everything produced while it was away."""
    s = _session(sid)
    i = max(0, from_index)
    last_beat = time.time()
    while True:
        events = s["events"]
        if i < len(events):
            yield events[i]
            i += 1
            last_beat = time.time()
        else:
            # Frequent heartbeat: the yield attempt fails fast once the client has
            # navigated away, so uvicorn reaps the thread within ~3s instead of
            # leaking it — otherwise open/reconnected streams pile up and the whole
            # UI stalls on an exhausted threadpool.
            if time.time() - last_beat > 3:
                yield {"type": "heartbeat", "index": i, "running": s["status"] == "running"}
                last_beat = time.time()
            time.sleep(0.3)


def _agent_turn(sid: str, user_text: str):
    """Spawn Claude Code for one message; yield UI events as its stream-json arrives."""
    cwd = workspace(sid)
    cmd = [_CLAUDE, "-p", user_text,
           "--model", _MODEL,
           "--output-format", "stream-json", "--verbose",
           "--permission-mode", "bypassPermissions",
           "--add-dir", PROJECT_ROOT,
           "--append-system-prompt", _APPEND_SYSTEM]
    if SID_MAP.get(sid):
        cmd += ["--resume", SID_MAP[sid]]

    env = dict(os.environ, PYTHONPATH=PROJECT_ROOT)

    try:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, text=True, bufsize=1,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        yield {"type": "error", "text": f"cannot launch claude: {e}"}
        return

    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield from _translate(sid, ev)
    finally:
        proc.wait()
        if proc.returncode not in (0, None):
            err = (proc.stderr.read() or "").strip()[-500:]
            if err:
                yield {"type": "error", "text": err}

    yield {"type": "done"}


def _translate(sid: str, ev: dict):
    t = ev.get("type")

    if t == "system" and ev.get("subtype") == "init":
        SID_MAP[sid] = ev.get("session_id") or SID_MAP.get(sid)
        return

    if t == "assistant":
        for c in ev.get("message", {}).get("content", []):
            ct = c.get("type")
            if ct == "thinking" and c.get("thinking"):
                yield {"type": "reasoning_delta", "text": c["thinking"] + "\n"}
            elif ct == "text" and c.get("text"):
                yield {"type": "text_delta", "text": c["text"]}
            elif ct == "tool_use":
                yield {"type": "tool_call", "id": c.get("id"),
                       "name": c.get("name"), "args": c.get("input") or {}}
        return

    if t == "user":
        for c in ev.get("message", {}).get("content", []):
            if c.get("type") == "tool_result":
                yield {"type": "tool_result", "id": c.get("tool_use_id"),
                       "result": _result_text(c.get("content"))}
        return

    if t == "result":
        if ev.get("session_id"):
            SID_MAP[sid] = ev["session_id"]
        return  # final text already streamed via assistant/text; 'done' emitted by caller

    if t == "rate_limit_event":
        yield {"type": "status", "text": "Claude API rate-limited — waiting…"}


def _result_text(content) -> str:
    if isinstance(content, str):
        return content[:4000]
    if isinstance(content, list):
        parts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
        return ("\n".join(parts) or json.dumps(content))[:4000]
    return str(content)[:4000]
