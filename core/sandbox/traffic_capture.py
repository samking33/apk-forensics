"""
Network Traffic Capture — mitmproxy + PCAP
Intercepts all HTTPS traffic from the emulator via mitmproxy.
Certificate pinning is bypassed by Frida hooks.
Saves: flow log (JSON), HAR export, and raw PCAP via tcpdump.

Requires:
  - mitmproxy (pip install mitmproxy)
  - adb in PATH
  - tcpdump on the emulator (/data/local/tmp/tcpdump)
"""

import os
import json
import time
import shutil
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


MITM_PORT   = 8080
PCAP_REMOTE = "/data/local/tmp/capture.pcap"


class CaptureSession:
    def __init__(self):
        self.mitm_proc  = None
        self.pcap_proc  = None
        self.flow_log   : list = []


def start_capture(session_dir: str, port: int = MITM_PORT) -> CaptureSession:
    """
    Start mitmproxy in dump mode + tcpdump on the emulator.
    Returns a CaptureSession object.
    """
    os.makedirs(session_dir, exist_ok=True)
    session = CaptureSession()

    flow_log_path = os.path.join(session_dir, "flows.jsonl")
    har_path      = os.path.join(session_dir, "traffic.har")

    # ── Start mitmproxy dump ───────────────────────────────────────────────
    mitmdump = shutil.which("mitmdump")
    if mitmdump:
        session.mitm_proc = subprocess.Popen(
            [
                mitmdump,
                "--listen-port", str(port),
                "--save-stream-file", flow_log_path,
                "--set", "flow_detail=3",
                "--set", "hardump=" + har_path,
                "--ssl-insecure",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        session.flow_log.append("WARNING: mitmdump not found — install mitmproxy")

    # ── Push and start tcpdump on emulator for PCAP (optional) ────────────
    adb = shutil.which("adb") or "adb"
    tcpdump_bin = _push_tcpdump(adb)   # returns the remote path or None

    if tcpdump_bin:
        session.pcap_proc = subprocess.Popen(
            [adb, "-s", "emulator-5554", "shell",
             f"{tcpdump_bin} -i any -w {PCAP_REMOTE} -n &"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    else:
        session.flow_log.append("INFO: tcpdump not available — PCAP skipped; mitmproxy flows captured")

    return session


def stop_capture(session: CaptureSession, session_dir: str) -> dict:
    """Stop capture processes and pull the PCAP from the emulator."""
    adb = shutil.which("adb") or "adb"

    # Kill tcpdump on device (if it was running)
    subprocess.run([adb, "-s", "emulator-5554", "shell",
                    "pkill -2 tcpdump 2>/dev/null; true"], timeout=5, shell=False)
    time.sleep(1)

    # Pull PCAP
    local_pcap = os.path.join(session_dir, "capture.pcap")
    subprocess.run([adb, "-s", "emulator-5554", "pull", PCAP_REMOTE, local_pcap], timeout=30)

    # Stop mitmproxy
    if session.mitm_proc:
        session.mitm_proc.terminate()
        try:
            session.mitm_proc.wait(timeout=10)
        except Exception:
            session.mitm_proc.kill()

    # Parse flow log
    flow_log_path = os.path.join(session_dir, "flows.jsonl")
    flows = parse_flows(flow_log_path)

    return {
        "pcap_path"   : local_pcap if os.path.exists(local_pcap) else None,
        "flow_count"  : len(flows),
        "flows"       : flows,
        "har_path"    : os.path.join(session_dir, "traffic.har"),
    }


def parse_flows(flow_log_path: str) -> list:
    """Parse mitmproxy flow log into list of request/response dicts."""
    flows = []
    if not os.path.exists(flow_log_path):
        return flows

    try:
        from mitmproxy.io import FlowReader
        from mitmproxy import http as mhttp
        with open(flow_log_path, "rb") as f:
            reader = FlowReader(f)
            for flow in reader.stream():
                if isinstance(flow, mhttp.HTTPFlow):
                    req = flow.request
                    rsp = flow.response
                    entry = {
                        "timestamp": req.timestamp_start,
                        "method"   : req.method,
                        "url"      : req.pretty_url,
                        "host"     : req.host,
                        "path"     : req.path,
                        "status"   : rsp.status_code if rsp else None,
                        "req_size" : len(req.content) if req.content else 0,
                        "rsp_size" : len(rsp.content) if rsp and rsp.content else 0,
                    }
                    # Flag Firebase C2 traffic
                    if "firestore.googleapis.com" in req.host or "firebase" in req.host:
                        entry["is_c2"] = True
                        try:
                            entry["req_body"] = req.content.decode("utf-8", errors="replace")[:2000]
                            entry["rsp_body"] = rsp.content.decode("utf-8", errors="replace")[:2000] if rsp else ""
                        except Exception:
                            pass
                    flows.append(entry)
    except ImportError:
        # mitmproxy not installed — parse as plain text
        with open(flow_log_path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        flows.append(json.loads(line))
                    except Exception:
                        pass

    return flows


def generate_traffic_report(flows: list, out_path: str) -> str:
    """Write a readable network traffic summary for court evidence."""
    c2_flows    = [f for f in flows if f.get("is_c2")]
    other_flows = [f for f in flows if not f.get("is_c2")]

    lines = [
        "=" * 72,
        "  NETWORK TRAFFIC ANALYSIS — SANDBOX CAPTURE",
        "=" * 72, "",
        f"  Total Requests  : {len(flows)}",
        f"  Firebase C2     : {len(c2_flows)} requests (EVIDENCE OF DATA EXFILTRATION)",
        f"  Other Requests  : {len(other_flows)}",
        "",
        "─" * 72,
        "  FIREBASE C2 TRAFFIC (EVIDENCE OF LIVE DATA UPLOAD)",
        "─" * 72, "",
    ]
    for f in c2_flows[:50]:
        lines.append(f"  [{f.get('method','?')}] {f.get('url','')[:80]}")
        if f.get("req_body"):
            lines.append(f"       Body: {f['req_body'][:200]}")
        lines.append("")

    lines += ["─" * 72, "  ALL UNIQUE HOSTS CONTACTED", "─" * 72, ""]
    hosts = sorted(set(f.get("host", "") for f in flows if f.get("host")))
    for h in hosts:
        lines.append(f"  {h}")

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out_path


def _push_tcpdump(adb: str) -> Optional[str]:
    """
    Push a static tcpdump binary if one exists in tools/.
    Fallback: check if the emulator already has tcpdump in /system/bin.
    Returns the remote binary path to use, or None if unavailable.
    """
    tools = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "tools", "tcpdump"
    )
    if os.path.exists(tools) and os.path.getsize(tools) > 1024:
        r = subprocess.run([adb, "-s", "emulator-5554", "push", tools,
                            "/data/local/tmp/tcpdump"], timeout=30,
                           capture_output=True)
        if r.returncode == 0:
            subprocess.run([adb, "-s", "emulator-5554", "shell",
                            "chmod 755 /data/local/tmp/tcpdump"], timeout=10,
                           capture_output=True)
            return "/data/local/tmp/tcpdump"

    # Check if emulator already has tcpdump in /system/bin (debug builds)
    r = subprocess.run([adb, "-s", "emulator-5554", "shell",
                        "which tcpdump 2>/dev/null || ls /system/bin/tcpdump 2>/dev/null"],
                       capture_output=True, text=True, timeout=10)
    path = r.stdout.strip()
    if path and "tcpdump" in path:
        return path

    return None
