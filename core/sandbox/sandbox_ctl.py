"""
sandbox_ctl — the fSOC Agent's remote-control for a live Android sandbox.

Thin, reliable adb primitives the agent invokes over its shell to operate the
phone like a human analyst: SEE (shot, dump), THINK (agent), ACT (tap, text, key,
swipe, sms, grant), OBSERVE (events). Screenshots feed the agent's vision; the
UI dump gives exact tap coordinates so it never guesses pixels.

Usage (the agent runs these via bash):
    python3 -m core.sandbox.sandbox_ctl status
    python3 -m core.sandbox.sandbox_ctl install /path/app.apk
    python3 -m core.sandbox.sandbox_ctl launch com.evil.app
    python3 -m core.sandbox.sandbox_ctl shot /tmp/s1.png
    python3 -m core.sandbox.sandbox_ctl dump            # tappable elements + coords
    python3 -m core.sandbox.sandbox_ctl tap 540 1180
    python3 -m core.sandbox.sandbox_ctl text "victim@example.com"
    python3 -m core.sandbox.sandbox_ctl key BACK
    python3 -m core.sandbox.sandbox_ctl sms VK-HDFCBK "874512 is your OTP"
    python3 -m core.sandbox.sandbox_ctl grant com.evil.app android.permission.RECEIVE_SMS
    python3 -m core.sandbox.sandbox_ctl events 200      # recent logcat for the app

DEVICE-DEPENDENT: needs a running AVD + adb. Only the UI-dump parser is unit-tested
offline (the forensically load-bearing bit); the adb calls run on a sandbox host.
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import time

from core.sandbox import dynamic_probe

_ADB = shutil.which("adb") or "adb"
_BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SDK = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME") \
       or "/opt/homebrew/share/android-commandlinetools"
_AVD = os.environ.get("FSOC_AVD", "TGCSB_Sandbox")


def _serial() -> str:
    """Resolve the target device serial: $ANDROID_SERIAL, else first online device."""
    if os.getenv("ANDROID_SERIAL"):
        return os.environ["ANDROID_SERIAL"]
    try:
        out = subprocess.run([_ADB, "devices"], capture_output=True, text=True, timeout=10).stdout
    except (subprocess.SubprocessError, OSError):
        return "emulator-5554"
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and parts[1] == "device":
            return parts[0]
    return "emulator-5554"


def _sh(serial, *args, timeout=30):
    return dynamic_probe._adb(serial, *args, timeout=timeout)


# ── SEE ───────────────────────────────────────────────────────────────────────

def cmd_shot(serial, a):
    p = dynamic_probe.screenshot(serial, a.path)
    print(f"OK screenshot -> {p}" if p else "FAIL screenshot")


def cmd_dump(serial, a):
    """uiautomator dump → compact list of interactive/text elements with centres.
    Dump to a file then cat it — dumping to /dev/tty interleaves status text and
    corrupts the XML."""
    _sh(serial, "shell", "uiautomator", "dump", "/sdcard/ui.xml", timeout=25)
    r = _sh(serial, "exec-out", "cat", "/sdcard/ui.xml", timeout=15)
    xml = r.stdout.decode("utf-8", "replace") if isinstance(r.stdout, bytes) else (r.stdout or "")
    lines = compact_ui(xml)
    print("\n".join(lines) if lines else "(no UI elements parsed)")


# ── ACT ───────────────────────────────────────────────────────────────────────

def cmd_tap(serial, a):
    _sh(serial, "shell", "input", "tap", str(a.x), str(a.y))
    print(f"OK tap {a.x},{a.y}")


def cmd_swipe(serial, a):
    _sh(serial, "shell", "input", "swipe", str(a.x1), str(a.y1), str(a.x2), str(a.y2), str(a.ms))
    print(f"OK swipe {a.x1},{a.y1}->{a.x2},{a.y2}")


def cmd_text(serial, a):
    esc = a.value.replace(" ", "%s").replace("'", "\\'").replace('"', '\\"')
    _sh(serial, "shell", "input", "text", esc)
    print(f"OK text ({len(a.value)} chars)")


def cmd_key(serial, a):
    code = a.code if a.code.isdigit() else "KEYCODE_" + a.code.upper()
    _sh(serial, "shell", "input", "keyevent", code)
    print(f"OK key {code}")


def cmd_sms(serial, a):
    print("OK sms sent" if dynamic_probe.inject_sms(serial, a.sender, a.body) else "FAIL sms")


def cmd_grant(serial, a):
    r = _sh(serial, "shell", "pm", "grant", a.pkg, a.perm)
    ok = r.returncode == 0
    print(f"{'OK' if ok else 'FAIL'} grant {a.perm}")


# ── LIFECYCLE ─────────────────────────────────────────────────────────────────

def cmd_install(serial, a):
    r = _sh(serial, "install", "-r", "-g", a.apk, timeout=180)
    out = (r.stdout or b"").decode("utf-8", "replace") if isinstance(r.stdout, bytes) else (r.stdout or "")
    print("OK installed" if "Success" in out else f"FAIL install: {out.strip()[:200]}")


def _main_activity(serial, pkg):
    """Resolve the app's MAIN activity from dumpsys — works even when the malware
    hides its icon (category INFO instead of LAUNCHER), which monkey can't start."""
    r = _sh(serial, "shell", "dumpsys", "package", pkg, timeout=20)
    out = r.stdout.decode("utf-8", "replace") if isinstance(r.stdout, bytes) else (r.stdout or "")
    in_main = False
    for line in out.splitlines():
        if "android.intent.action.MAIN" in line:
            in_main = True
            continue
        if in_main:
            m = re.search(re.escape(pkg) + r"/[\w.$]+", line)
            if m:
                return m.group(0)
            if line.strip().startswith("android.intent.action"):
                in_main = False
    m = re.search(re.escape(pkg) + r"/[\w.$]+[Aa]ctivity", out)
    return m.group(0) if m else None


def cmd_launch(serial, a):
    comp = _main_activity(serial, a.pkg)
    if comp:
        _sh(serial, "shell", "am", "start", "-n", comp, timeout=20)
        print(f"OK launched {comp}")
    else:
        _sh(serial, "shell", "monkey", "-p", a.pkg, "-c",
            "android.intent.category.LAUNCHER", "1", timeout=20)
        print(f"OK launched {a.pkg} (monkey fallback)")


def cmd_events(serial, a):
    r = _sh(serial, "exec-out", "logcat", "-d", "-t", str(a.count), timeout=15)
    out = r.stdout.decode("utf-8", "replace") if isinstance(r.stdout, bytes) else (r.stdout or "")
    print(out[-6000:])


def _serial_online() -> bool:
    try:
        out = subprocess.run([_ADB, "devices"], capture_output=True, text=True, timeout=10).stdout
        return any(len(l.split()) == 2 and l.split()[1] == "device" for l in out.splitlines()[1:])
    except (subprocess.SubprocessError, OSError):
        return False


def _frida_binary():
    cands = sorted(glob.glob(os.path.join(_ROOT, "tools", "frida-server-*")), reverse=True)
    cands.append(os.path.join(_ROOT, "tools", "frida-server"))
    return next((c for c in cands if os.path.exists(c)), None)


def _ensure_frida():
    subprocess.run([_ADB, "root"], capture_output=True, timeout=15)
    time.sleep(1)
    subprocess.run([_ADB, "wait-for-device"], timeout=30)
    fs = _frida_binary()
    if not fs:
        return False
    subprocess.run([_ADB, "push", fs, "/data/local/tmp/frida-server"], capture_output=True, timeout=90)
    subprocess.run([_ADB, "shell", "chmod", "755", "/data/local/tmp/frida-server"], capture_output=True, timeout=10)
    chk = subprocess.run([_ADB, "shell", "pgrep", "-f", "frida-server"], capture_output=True, text=True, timeout=8)
    if not chk.stdout.strip():
        subprocess.Popen([_ADB, "shell", "/data/local/tmp/frida-server"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
    return True


def cmd_boot(serial, a):
    """Start the AVD headless and bring up frida-server. Idempotent."""
    if _serial_online():
        _ensure_frida()
        print("OK emulator already running (frida ensured)")
        return
    emu = os.path.join(_SDK, "emulator", "emulator")
    subprocess.Popen([emu, "-avd", _AVD, "-no-window", "-no-audio", "-no-boot-anim",
                      "-no-snapshot", "-gpu", "swiftshader_indirect"],
                     stdout=open("/tmp/fsoc_emu.log", "w"), stderr=subprocess.STDOUT,
                     start_new_session=True, env=dict(os.environ, ANDROID_SDK_ROOT=_SDK))
    try:
        subprocess.run([_ADB, "wait-for-device"], timeout=a.timeout)
    except subprocess.TimeoutExpired:
        print("FAIL emulator did not appear"); return
    deadline = time.time() + a.timeout
    while time.time() < deadline:
        r = subprocess.run([_ADB, "shell", "getprop", "sys.boot_completed"],
                           capture_output=True, text=True, timeout=10)
        if r.stdout.strip() == "1":
            _ensure_frida()
            print("OK emulator booted + frida-server started")
            return
        time.sleep(3)
    print("FAIL boot timeout")


def cmd_frida(serial, a):
    ok = _ensure_frida()
    chk = subprocess.run([_ADB, "shell", "pgrep", "-f", "frida-server"],
                         capture_output=True, text=True, timeout=8)
    print("OK frida-server running" if (ok and chk.stdout.strip()) else "FAIL frida-server")


def cmd_stop(serial, a):
    subprocess.run([_ADB, "emu", "kill"], capture_output=True, timeout=15)
    print("OK emulator stopped")


def cmd_status(serial, a):
    try:
        devs = subprocess.run([_ADB, "devices"], capture_output=True, text=True, timeout=10).stdout.strip()
    except (subprocess.SubprocessError, OSError) as e:
        devs = f"adb error: {e}"
    frida = _sh(serial, "shell", "pgrep", "-f", "frida-server", timeout=8)
    fout = (frida.stdout or b"").decode() if isinstance(frida.stdout, bytes) else (frida.stdout or "")
    print(f"serial={serial}\n{devs}\nfrida-server={'running' if fout.strip() else 'not running'}")


# ── Pure UI parser (unit-tested) ──────────────────────────────────────────────

def compact_ui(xml: str, limit: int = 80) -> list[str]:
    """Reduce a uiautomator XML dump to the actionable elements the agent needs:
    anything with text, a content-desc, or that is clickable — each with its tap
    centre. Keeps the agent's context small and its taps exact."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []

    out = []
    for n in root.iter("node"):
        text = (n.get("text") or "").strip()
        desc = (n.get("content-desc") or "").strip()
        rid  = (n.get("resource-id") or "").split("/")[-1]
        clickable = n.get("clickable") == "true"
        if not (text or desc or (clickable and rid)):
            continue
        m = _BOUNDS.match(n.get("bounds") or "")
        if not m:
            continue
        x1, y1, x2, y2 = map(int, m.groups())
        cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
        label = text or desc or rid
        flag = "clickable" if clickable else "text"
        extra = f" id={rid}" if rid and rid != label else ""
        out.append(f"[{cx},{cy}] {flag}: {label[:60]!r}{extra}")
        if len(out) >= limit:
            break
    return out


_COMMANDS = {
    "boot": cmd_boot, "frida": cmd_frida, "stop": cmd_stop,
    "status": cmd_status, "install": cmd_install, "launch": cmd_launch,
    "shot": cmd_shot, "dump": cmd_dump, "tap": cmd_tap, "swipe": cmd_swipe,
    "text": cmd_text, "key": cmd_key, "sms": cmd_sms, "grant": cmd_grant,
    "events": cmd_events,
}


def main(argv=None):
    p = argparse.ArgumentParser(prog="sandbox_ctl")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("boot"); sp.add_argument("--timeout", type=int, default=240)
    sub.add_parser("frida")
    sub.add_parser("stop")
    sub.add_parser("status")
    sp = sub.add_parser("install"); sp.add_argument("apk")
    sp = sub.add_parser("launch");  sp.add_argument("pkg")
    sp = sub.add_parser("shot");    sp.add_argument("path")
    sub.add_parser("dump")
    sp = sub.add_parser("tap");     sp.add_argument("x", type=int); sp.add_argument("y", type=int)
    sp = sub.add_parser("swipe")
    for k in ("x1", "y1", "x2", "y2"): sp.add_argument(k, type=int)
    sp.add_argument("ms", type=int, nargs="?", default=300)
    sp = sub.add_parser("text");    sp.add_argument("value")
    sp = sub.add_parser("key");     sp.add_argument("code")
    sp = sub.add_parser("sms");     sp.add_argument("sender"); sp.add_argument("body")
    sp = sub.add_parser("grant");   sp.add_argument("pkg"); sp.add_argument("perm")
    sp = sub.add_parser("events");  sp.add_argument("count", type=int, nargs="?", default=200)

    args = p.parse_args(argv)
    serial = _serial()
    _COMMANDS[args.cmd](serial, args)


if __name__ == "__main__":
    main()
