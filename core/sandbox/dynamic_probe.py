"""
Dynamic Probe — runtime evidence collection on a live emulator.

Adds the high-value runtime artefacts on top of the existing Frida hooks:
  * screenshots            — visual proof of overlays / phishing screens
  * synthetic SMS injection — feed a known OTP and watch it get stolen
  * OTP-theft proof         — correlate the injected OTP against captured exfil
  * activity exercising     — poke exported activities to trigger hidden behaviour

⚠️  DEVICE-DEPENDENT: the functions that talk to adb/the emulator require a
running AVD with frida-server and cannot run in CI. They are written for a live
sandbox host and are NOT exercised by the offline test suite. The one piece that
IS pure and tested is `analyze_otp_theft()` — the forensic core that decides
whether the injected OTP was exfiltrated.
"""

import os
import shutil
import subprocess

_ADB = shutil.which("adb") or "adb"


def _adb(serial: str, *args, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run([_ADB, "-s", serial, *args],
                          capture_output=True, timeout=timeout)


# ── Live device I/O (device-dependent; untested offline) ──────────────────────

def screenshot(serial: str, out_path: str) -> str | None:
    """Capture the current screen to a PNG. Returns the path or None on failure."""
    try:
        r = _adb(serial, "exec-out", "screencap", "-p", timeout=20)
        if r.returncode == 0 and r.stdout[:8] == b"\x89PNG\r\n\x1a\n":
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(r.stdout)
            return out_path
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def inject_sms(serial: str, sender: str, body: str) -> bool:
    """Inject a synthetic incoming SMS via the emulator console (`adb emu sms send`).
    Used to feed a controlled OTP the malware will try to steal."""
    try:
        r = _adb(serial, "emu", "sms", "send", sender, body, timeout=15)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def exercise_activities(serial: str, package: str, activities: list[str],
                        settle: float = 1.5) -> list[dict]:
    """Launch each exported activity to trigger hidden behaviour. Returns per-
    activity launch results. ponytail: sequential am start; parallelism buys
    nothing on a single emulator."""
    import time
    results = []
    for act in activities:
        comp = act if "/" in act else f"{package}/{act}"
        try:
            r = _adb(serial, "shell", "am", "start", "-n", comp, timeout=15)
            ok = r.returncode == 0 and b"Error" not in r.stdout
        except (subprocess.SubprocessError, OSError):
            ok = False
        results.append({"activity": comp, "launched": ok})
        time.sleep(settle)
    return results


def run_otp_theft_proof(serial: str, session_dir: str, *, sender: str = "VK-HDFCBK",
                        otp: str = "874512", wait: float = 8.0,
                        evidence: dict | None = None) -> dict:
    """
    Orchestrate the courtroom artefact: with Frida hooks already capturing into
    `evidence`, inject a bank-style SMS carrying a known OTP, screenshot, wait for
    the app to react, then prove whether the OTP was exfiltrated.

    Assumes frida_hooks.attach_and_hook() is already running against the target
    and writing into `evidence`. Device-dependent; not run offline.
    """
    import time
    evidence = evidence if evidence is not None else {}
    body = f"{otp} is your HDFC Bank OTP. Do not share with anyone."

    shot_before = screenshot(serial, os.path.join(session_dir, "before_sms.png"))
    injected = inject_sms(serial, sender, body)
    time.sleep(wait)
    shot_after = screenshot(serial, os.path.join(session_dir, "after_sms.png"))

    proof = analyze_otp_theft(evidence, otp)
    proof.update({"injected": injected, "otp": otp, "sender": sender,
                  "screenshots": [p for p in (shot_before, shot_after) if p]})
    return proof


# ── Pure proof logic (tested offline) ─────────────────────────────────────────

def analyze_otp_theft(evidence: dict, otp: str) -> dict:
    """Decide whether the injected OTP left the device. Scans captured SMS-sent,
    network and OkHttp events for the OTP value. This is the artefact that proves
    interception+exfiltration rather than mere capability."""
    channels = []

    for e in evidence.get("sms_ops", []):
        content = str(e.get("content") or e.get("data", {}).get("content") or "")
        dest = e.get("destination") or e.get("data", {}).get("destination")
        if otp in content:
            channels.append({"channel": "sms", "destination": dest})

    for e in evidence.get("network", []):
        blob = str(e)
        if otp in blob:
            channels.append({"channel": "network", "url": e.get("url")})

    read = any(otp in str(e) for e in evidence.get("sms_read", []) + evidence.get("api_calls", []))

    return {
        "otp_read": read,
        "otp_exfiltrated": bool(channels),
        "exfil_channels": channels,
        "verdict": ("OTP intercepted and exfiltrated" if channels
                    else "OTP read but no exfil observed" if read
                    else "no OTP theft observed"),
    }


if __name__ == "__main__":
    # ponytail self-check: the pure proof logic must catch an OTP that was read
    # and then forwarded, and stay quiet when nothing happened.
    otp = "874512"
    stolen = {
        "sms_read": [{"content": f"{otp} is your HDFC Bank OTP"}],
        "sms_ops":  [{"destination": "+919000000000", "content": f"otp={otp}"}],
        "network":  [{"url": f"http://c2.example/log?otp={otp}"}],
    }
    p = analyze_otp_theft(stolen, otp)
    assert p["otp_read"] and p["otp_exfiltrated"], p
    assert {c["channel"] for c in p["exfil_channels"]} == {"sms", "network"}, p

    clean = analyze_otp_theft({"sms_read": [], "sms_ops": [], "network": []}, otp)
    assert not clean["otp_exfiltrated"] and clean["verdict"] == "no OTP theft observed"
    print(f"OK — proof logic: '{p['verdict']}' via {[c['channel'] for c in p['exfil_channels']]}")
