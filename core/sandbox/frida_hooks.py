"""
Frida API Hooking
Instruments the target APK at runtime to capture:
  - SmsManager.sendTextMessage() — OTP forwarding interception
  - TelephonyManager.listen() — SMS listener registration
  - SmsMessage.getMessageBody() — incoming SMS content reads
  - URL/HttpURLConnection opens — C2 network calls
  - SharedPreferences reads — credential access
  - File write operations — data exfiltration to local storage

Requires:
  - frida Python package (pip install frida-tools)
  - frida-server binary pushed to /data/local/tmp/ on device
  - Frida server matching version of Python frida package
"""

import os
import json
import time
import subprocess
import shutil
from datetime import datetime, timezone
from typing import Optional


FRIDA_SERVER_REMOTE = "/data/local/tmp/frida-server"

# ── JavaScript hook script injected into the target app ───────────────────────
HOOK_SCRIPT = """
'use strict';

var results = {
    sms_sent: [],
    sms_read: [],
    network:  [],
    files:    [],
    prefs:    [],
};

// ── Hook: SmsManager.sendTextMessage ──────────────────────────────────────────
Java.perform(function() {
    try {
        var SmsManager = Java.use('android.telephony.SmsManager');
        SmsManager.sendTextMessage.overload(
            'java.lang.String','java.lang.String','java.lang.String',
            'android.app.PendingIntent','android.app.PendingIntent'
        ).implementation = function(destAddr, scAddr, text, sentIntent, deliveryIntent) {
            var entry = {
                timestamp: new Date().toISOString(),
                type: 'SMS_SENT',
                destination: destAddr,
                content: text,
            };
            results.sms_sent.push(entry);
            send({type: 'SMS_SENT', data: entry});
            return this.sendTextMessage(destAddr, scAddr, text, sentIntent, deliveryIntent);
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'sendTextMessage', error: e.message}); }

    // ── Hook: SmsMessage.getMessageBody ───────────────────────────────────────
    try {
        var SmsMsg = Java.use('android.telephony.SmsMessage');
        SmsMsg.getMessageBody.implementation = function() {
            var body = this.getMessageBody();
            if (body && body.length > 0) {
                var entry = {timestamp: new Date().toISOString(), type: 'SMS_READ', content: body};
                results.sms_read.push(entry);
                send({type: 'SMS_READ', data: entry});
            }
            return body;
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'getMessageBody', error: e.message}); }

    // ── Hook: URL.openConnection ───────────────────────────────────────────────
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            var url = this.toString();
            var entry = {timestamp: new Date().toISOString(), type: 'NETWORK', url: url};
            results.network.push(entry);
            send({type: 'NETWORK', data: entry});
            return this.openConnection();
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'URL.openConnection', error: e.message}); }

    // ── Hook: HttpURLConnection.getOutputStream (POST body capture) ────────────
    try {
        var HttpConn = Java.use('java.net.HttpURLConnection');
        HttpConn.getOutputStream.implementation = function() {
            send({type: 'HTTP_POST_START', url: this.getURL().toString()});
            return this.getOutputStream();
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'getOutputStream', error: e.message}); }

    // ── Hook: OkHttp (used by Firebase SDK) ───────────────────────────────────
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var RealCall     = Java.use('okhttp3.internal.connection.RealCall');
        RealCall.execute.implementation = function() {
            var req  = this.request();
            var body = req.body();
            var entry = {
                timestamp: new Date().toISOString(),
                type: 'OKHTTP',
                method: req.method(),
                url: req.url().toString(),
            };
            results.network.push(entry);
            send({type: 'OKHTTP', data: entry});
            return this.execute();
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'OkHttpClient', error: e.message}); }

    // ── Hook: SharedPreferences (credential reads) ─────────────────────────────
    try {
        var SharedPrefsImpl = Java.use('android.app.SharedPreferencesImpl');
        SharedPrefsImpl.getString.implementation = function(key, defVal) {
            var val = this.getString(key, defVal);
            if (val && val.length > 0) {
                send({type: 'PREF_READ', key: key, value: val});
            }
            return val;
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'SharedPreferences', error: e.message}); }

    // ── Hook: File writes ──────────────────────────────────────────────────────
    try {
        var FileOutputStream = Java.use('java.io.FileOutputStream');
        FileOutputStream.$init.overload('java.io.File','boolean').implementation = function(file, append) {
            var path = file.getAbsolutePath();
            send({type: 'FILE_WRITE', path: path});
            return this.$init(file, append);
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'FileOutputStream', error: e.message}); }

    // ── Hook: Cipher.doFinal — recover decrypted strings / C2 at runtime ──────
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function(input) {
            var out = this.doFinal(input);
            try {
                var Str = Java.use('java.lang.String');
                var entry = {
                    timestamp: new Date().toISOString(), type: 'CRYPTO',
                    algorithm: this.getAlgorithm(),
                    plaintext: Str.$new(out).toString().substring(0, 300),
                };
                results.crypto ? results.crypto.push(entry) : (results.crypto = [entry]);
                send({type: 'CRYPTO', data: entry});
            } catch(e2) {}
            return out;
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'Cipher.doFinal', error: e.message}); }

    // ── Hook: DexClassLoader — second-stage payload loading ───────────────────
    try {
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.$init.implementation = function(dexPath, optDir, libPath, parent) {
            send({type: 'DEX_LOAD', data: {timestamp: new Date().toISOString(), dexPath: dexPath}});
            return this.$init(dexPath, optDir, libPath, parent);
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'DexClassLoader', error: e.message}); }

    // ── Hook: AccessibilityService.onAccessibilityEvent — screen scraping ─────
    try {
        var ASvc = Java.use('android.accessibilityservice.AccessibilityService');
        ASvc.onAccessibilityEvent.implementation = function(ev) {
            try {
                var pkg = ev.getPackageName();
                send({type: 'ACCESSIBILITY', data: {timestamp: new Date().toISOString(),
                    eventType: ev.getEventType(), targetPackage: pkg ? pkg.toString() : null}});
            } catch(e2) {}
            return this.onAccessibilityEvent(ev);
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'AccessibilityService', error: e.message}); }

    send({type: 'HOOKS_INSTALLED', timestamp: new Date().toISOString()});
});
"""

# ── Universal TLS-pinning bypass — injected when C2 traffic must be decrypted ──
# Neutralises the common pinning surfaces (custom TrustManager, OkHttp
# CertificatePinner) so mitmproxy can read the C2 protocol. Load alongside
# HOOK_SCRIPT for a full man-in-the-middle capture.
TLS_UNPIN_SCRIPT = """
'use strict';
Java.perform(function() {
    try {
        var X509TM = Java.use('javax.net.ssl.X509TrustManager');
        var SSLCtx = Java.use('javax.net.ssl.SSLContext');
        var TrustAll = Java.registerClass({
            name: 'com.fsoc.TrustAll', implements: [X509TM],
            methods: {
                checkClientTrusted: function(c, a) {}, checkServerTrusted: function(c, a) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var init = SSLCtx.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom');
        init.implementation = function(km, tm, sr) {
            init.call(this, km, [TrustAll.$new()], sr);
            send({type: 'TLS_UNPIN', data: {surface: 'SSLContext'}});
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'SSLContext', error: e.message}); }

    try {
        var Pinner = Java.use('okhttp3.CertificatePinner');
        Pinner.check.overload('java.lang.String', 'java.util.List').implementation = function(h, p) {
            send({type: 'TLS_UNPIN', data: {surface: 'OkHttp CertificatePinner', host: h}});
        };
    } catch(e) { send({type:'HOOK_ERROR', hook:'CertificatePinner', error: e.message}); }
});
"""


def push_server(adb_serial: str) -> bool:
    """
    Push frida-server binary to /data/local/tmp/ and start it.
    Requires frida-server binary at FRIDA_SERVER_LOCAL path.
    """
    # Look for frida-server in tools/ directory
    tools_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "tools"
    )
    local_server = os.path.join(tools_dir, "frida-server")

    if not os.path.exists(local_server):
        raise FileNotFoundError(
            f"frida-server binary not found at {local_server}. "
            "Download from https://github.com/frida/frida/releases "
            "and place at tgcsb_apk_analyser/tools/frida-server"
        )

    adb = shutil.which("adb") or "adb"

    # Push binary
    subprocess.run([adb, "-s", adb_serial, "push", local_server, FRIDA_SERVER_REMOTE],
                   check=True, timeout=30)
    # chmod +x
    subprocess.run([adb, "-s", adb_serial, "shell", "chmod", "755", FRIDA_SERVER_REMOTE],
                   check=True, timeout=10)
    # Kill any existing frida-server
    subprocess.run([adb, "-s", adb_serial, "shell", "pkill", "-f", "frida-server"],
                   timeout=5)
    time.sleep(1)
    # Start frida-server in background
    subprocess.Popen(
        [adb, "-s", adb_serial, "shell", FRIDA_SERVER_REMOTE, "&"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(2)   # give it time to start
    return True


def attach_and_hook(adb_serial: str, package_name: str,
                    session_dir: str, evidence: dict):
    """
    Attach Frida to the running app and inject hooks.
    Runs in a background thread — writes all intercepted events to evidence dict.
    """
    try:
        import frida
    except ImportError:
        evidence["errors"].append("frida Python package not installed. pip install frida-tools")
        return

    os.makedirs(session_dir, exist_ok=True)
    events_path = os.path.join(session_dir, "frida_events.jsonl")
    events_file = open(events_path, "w")
    evidence["frida_events_path"] = events_path

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message.get("payload", {})
            payload["_ts"] = datetime.now(timezone.utc).isoformat()
            events_file.write(json.dumps(payload) + "\n")
            events_file.flush()

            mtype = payload.get("type", "")
            if mtype == "SMS_SENT":
                evidence["sms_ops"].append(payload)
            elif mtype in ("NETWORK", "OKHTTP", "HTTP_POST_START"):
                evidence["network"].append(payload.get("data", payload))
            elif mtype == "FILE_WRITE":
                evidence["file_ops"].append(payload)
            elif mtype == "PREF_READ":
                evidence["api_calls"].append(payload)
            elif mtype == "CRYPTO":
                evidence.setdefault("crypto", []).append(payload.get("data", payload))
            elif mtype == "DEX_LOAD":
                evidence.setdefault("dex_loads", []).append(payload.get("data", payload))
            elif mtype == "ACCESSIBILITY":
                evidence.setdefault("accessibility", []).append(payload.get("data", payload))
            elif mtype == "TLS_UNPIN":
                evidence.setdefault("tls_unpin", []).append(payload.get("data", payload))

    # Retry attach a few times (app may not be fully started)
    device  = None
    session = None
    for attempt in range(5):
        try:
            mgr    = frida.get_device_manager()
            device = mgr.get_device(adb_serial, timeout=10)
            pid    = device.get_process(package_name)
            session = device.attach(pid)
            break
        except Exception as e:
            if attempt == 4:
                evidence["errors"].append(f"Frida attach failed after 5 attempts: {e}")
                events_file.close()
                return
            time.sleep(3)

    script = session.create_script(HOOK_SCRIPT)
    script.on("message", on_message)
    script.load()

    # Keep thread alive until evidence["status"] != "running"
    while evidence.get("status") == "running":
        time.sleep(1)

    try:
        script.unload()
        session.detach()
    except Exception:
        pass

    events_file.close()


def parse_events(events_path: str) -> dict:
    """Parse frida_events.jsonl into a structured summary."""
    if not os.path.exists(events_path):
        return {}

    sms_sent   = []
    sms_read   = []
    networks   = []
    files      = []
    prefs      = []
    errors     = []

    with open(events_path) as f:
        for line in f:
            try:
                evt = json.loads(line.strip())
                t   = evt.get("type", "")
                if t == "SMS_SENT":
                    sms_sent.append(evt.get("data", evt))
                elif t == "SMS_READ":
                    sms_read.append(evt.get("data", evt))
                elif t in ("NETWORK", "OKHTTP", "HTTP_POST_START"):
                    networks.append(evt.get("data", evt))
                elif t == "FILE_WRITE":
                    files.append(evt)
                elif t == "PREF_READ":
                    prefs.append(evt)
                elif t == "HOOK_ERROR":
                    errors.append(evt)
            except Exception:
                continue

    return {
        "sms_forwarded"  : sms_sent,
        "sms_intercepted": sms_read,
        "c2_urls"        : list({n.get("url", "") for n in networks if n.get("url")}),
        "network_calls"  : len(networks),
        "file_writes"    : files,
        "pref_reads"     : prefs,
        "hook_errors"    : errors,
    }
