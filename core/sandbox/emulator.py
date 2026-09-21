"""
Android Emulator Sandbox — AVD Management & APK Runtime Analysis
Manages Android Virtual Devices via Android SDK command-line tools.
Runs the malware APK in an isolated emulator, captures all runtime behaviour.

Requirements (system-level, not pip):
  - Android SDK with emulator + adb (set ANDROID_HOME or ANDROID_SDK_ROOT)
  - An AVD named "TGCSB_Sandbox" (auto-created by setup() if missing)
  - mitmproxy (pip install mitmproxy) for traffic capture
  - frida-server ARM binary pushed to /data/local/tmp/ on AVD

Usage:
    from core.sandbox.emulator import Emulator
    e = Emulator()
    e.setup()       # one-time: creates AVD
    session = e.run_apk("path/to/malware.apk", duration=120)
    print(session)  # dict with all captured evidence
"""

import os
import re
import json
import time
import shutil
import subprocess
import threading
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


AVD_NAME     = "TGCSB_Sandbox"
AVD_PACKAGE  = "system-images;android-29;default;arm64-v8a"   # arm64 for Apple Silicon
FRIDA_SERVER = "frida-server-16.2.1-android-arm64"   # rename to frida-server after push
ADB_SERIAL   = "emulator-5554"
CAPTURE_DIR  = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__)))), "evidence_output", "sandbox")


def _find_sdk() -> Optional[str]:
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT", "ANDROID_SDK"):
        val = os.environ.get(env)
        if val and os.path.isdir(val):
            return val
    # Common macOS/Linux paths
    for p in [
        os.path.expanduser("~/Android/Sdk"),
        os.path.expanduser("~/Library/Android/sdk"),
        "/opt/homebrew/share/android-commandlinetools",
        "/opt/android-sdk",
    ]:
        if os.path.isdir(p):
            return p
    return None


def _adb(*args, timeout=30) -> subprocess.CompletedProcess:
    sdk = _find_sdk()
    adb = shutil.which("adb") or (os.path.join(sdk, "platform-tools", "adb") if sdk else "adb")
    return subprocess.run([adb] + list(args), capture_output=True, text=True, timeout=timeout)


def _emulator(*args, timeout=10) -> subprocess.CompletedProcess:
    sdk = _find_sdk()
    emu = shutil.which("emulator") or (os.path.join(sdk, "emulator", "emulator") if sdk else "emulator")
    return subprocess.run([emu] + list(args), capture_output=True, text=True, timeout=timeout)


def _sdkmanager(*args, timeout=300) -> subprocess.CompletedProcess:
    sdk = _find_sdk()
    mgr = shutil.which("sdkmanager") or (
        os.path.join(sdk, "cmdline-tools", "latest", "bin", "sdkmanager") if sdk else "sdkmanager"
    )
    return subprocess.run([mgr] + list(args), capture_output=True, text=True, timeout=timeout)


def _avdmanager(*args, timeout=120) -> subprocess.CompletedProcess:
    sdk = _find_sdk()
    mgr = shutil.which("avdmanager") or (
        os.path.join(sdk, "cmdline-tools", "latest", "bin", "avdmanager") if sdk else "avdmanager"
    )
    return subprocess.run([mgr] + list(args), capture_output=True, text=True, timeout=timeout)


class Emulator:
    def __init__(self, avd_name: str = AVD_NAME, capture_dir: str = CAPTURE_DIR):
        self.avd_name    = avd_name
        self.capture_dir = capture_dir
        self._proc       = None   # emulator subprocess
        os.makedirs(capture_dir, exist_ok=True)

    # ── Setup ──────────────────────────────────────────────────────────────

    def check_prerequisites(self) -> dict:
        sdk = _find_sdk()
        adb_ok  = bool(shutil.which("adb") or (sdk and os.path.exists(os.path.join(sdk, "platform-tools", "adb"))))
        emu_ok  = bool(shutil.which("emulator") or (sdk and os.path.exists(os.path.join(sdk, "emulator", "emulator"))))
        avd_ok  = self.avd_name in self._list_avds()

        try:
            import frida
            frida_ok = True
        except ImportError:
            frida_ok = False

        try:
            import mitmproxy
            mitm_ok = True
        except ImportError:
            mitm_ok = False

        return {
            "sdk_path"    : sdk,
            "adb"         : adb_ok,
            "emulator"    : emu_ok,
            "avd_exists"  : avd_ok,
            "frida_python": frida_ok,
            "mitmproxy"   : mitm_ok,
            "ready"       : adb_ok and emu_ok and avd_ok,
        }

    def setup(self) -> bool:
        """One-time setup: install system image and create AVD."""
        sdk = _find_sdk()
        if not sdk:
            raise EnvironmentError(
                "Android SDK not found. Set ANDROID_HOME environment variable."
            )

        # Install system image
        r = _sdkmanager("--install", AVD_PACKAGE, "--channel=0")
        if r.returncode != 0:
            raise EnvironmentError(f"sdkmanager failed: {r.stderr}")

        # Create AVD
        r = _avdmanager(
            "create", "avd",
            "--name", self.avd_name,
            "--package", AVD_PACKAGE,
            "--device", "pixel_3a",
            "--force",
            timeout=120,
        )
        if r.returncode != 0:
            raise EnvironmentError(f"avdmanager failed: {r.stderr}")

        return True

    def _list_avds(self) -> list:
        try:
            r = _avdmanager("list", "avd", "-c")
            return [line.strip() for line in r.stdout.splitlines() if line.strip()]
        except FileNotFoundError:
            return []

    # ── Emulator lifecycle ─────────────────────────────────────────────────

    def start(self, headless: bool = True) -> bool:
        """Boot the AVD. Returns True when adb shell is ready."""
        sdk     = _find_sdk()
        emu_bin = shutil.which("emulator") or os.path.join(sdk, "emulator", "emulator")
        args    = [emu_bin, f"@{self.avd_name}", "-no-snapshot", "-no-audio", "-no-boot-anim"]
        if headless:
            args += ["-no-window"]

        self._proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for boot (up to 180s)
        for _ in range(90):
            time.sleep(2)
            r = _adb("-s", ADB_SERIAL, "shell", "getprop", "sys.boot_completed")
            if r.stdout.strip() == "1":
                return True
        raise TimeoutError("Emulator did not boot within 180 seconds")

    def stop(self):
        """Kill the emulator."""
        _adb("-s", ADB_SERIAL, "emu", "kill")
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=10)
            except Exception:
                self._proc.kill()
            self._proc = None

    # ── APK analysis session ───────────────────────────────────────────────

    def run_apk(self, apk_path: str, duration: int = 120,
                headless: bool = True) -> dict:
        """
        Full sandbox run:
          1. Start emulator
          2. Push frida-server
          3. Start mitmproxy HTTPS interception
          4. Install and launch APK
          5. Attach Frida hooks
          6. Wait duration seconds
          7. Collect all evidence
          8. Stop emulator

        Returns evidence dict.
        """
        from core.sandbox import frida_hooks, traffic_capture

        session_id  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        session_dir = os.path.join(self.capture_dir, session_id)
        os.makedirs(session_dir, exist_ok=True)

        evidence = {
            "session_id"  : session_id,
            "apk_path"    : apk_path,
            "session_dir" : session_dir,
            "started_at"  : datetime.now(timezone.utc).isoformat(),
            "duration_s"  : duration,
            "network"     : [],
            "sms_ops"     : [],
            "file_ops"    : [],
            "api_calls"   : [],
            "errors"      : [],
        }

        try:
            # 1. Boot emulator
            evidence["status"] = "booting"
            self.start(headless=headless)

            # 2. Push and start frida-server
            evidence["status"] = "frida_setup"
            frida_hooks.push_server(ADB_SERIAL)

            # 3. Start mitmproxy in background
            evidence["status"] = "mitm_start"
            mitm = traffic_capture.start_capture(session_dir)

            # 4. Configure proxy on device
            _adb("-s", ADB_SERIAL, "shell", "settings", "put", "global",
                 "http_proxy", "127.0.0.1:8080")

            # 5. Install APK
            evidence["status"] = "installing"
            r = _adb("-s", ADB_SERIAL, "install", "-r", "-t", apk_path, timeout=60)
            if r.returncode != 0:
                raise RuntimeError(f"APK install failed: {r.stderr}")

            # Get package name from APK
            pkg = _get_package_name(apk_path)
            evidence["package_name"] = pkg

            # 6. Launch APK
            evidence["status"] = "running"
            _adb("-s", ADB_SERIAL, "shell", "monkey", "-p", pkg, "-c",
                 "android.intent.category.LAUNCHER", "1")

            # 7. Attach Frida hooks
            hook_thread = threading.Thread(
                target=frida_hooks.attach_and_hook,
                args=(ADB_SERIAL, pkg, session_dir, evidence),
                daemon=True
            )
            hook_thread.start()

            # 8. Wait
            time.sleep(duration)

            # 9. Collect logcat
            evidence["status"] = "collecting"
            logcat = _adb("-s", ADB_SERIAL, "logcat", "-d", "-v", "threadtime",
                          timeout=30)
            logcat_path = os.path.join(session_dir, "logcat.txt")
            with open(logcat_path, "w") as f:
                f.write(logcat.stdout)
            evidence["logcat_path"] = logcat_path

            # 10. Stop mitmproxy and get PCAP
            traffic_capture.stop_capture(mitm, session_dir)
            evidence["pcap_path"] = os.path.join(session_dir, "capture.pcap")

            evidence["status"] = "complete"

        except Exception as e:
            evidence["status"] = "error"
            evidence["errors"].append(str(e))

        finally:
            try:
                self.stop()
            except Exception:
                pass

        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
        manifest_path = os.path.join(session_dir, "session_manifest.json")
        with open(manifest_path, "w") as f:
            json.dump(evidence, f, indent=2)

        return evidence


def _get_package_name(apk_path: str) -> str:
    """Extract package name from APK using aapt or androguard."""
    aapt = shutil.which("aapt") or shutil.which("aapt2")
    if aapt:
        r = subprocess.run([aapt, "dump", "badging", apk_path],
                           capture_output=True, text=True, timeout=30)
        m = re.search(r"package: name='([^']+)'", r.stdout)
        if m:
            return m.group(1)
    # Fallback: androguard
    try:
        from androguard.misc import AnalyzeAPK
        a, _, _ = AnalyzeAPK(apk_path)
        return a.get_package()
    except Exception:
        return "unknown.package"
