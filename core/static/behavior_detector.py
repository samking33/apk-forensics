"""
Behaviour Detector — banking-trojan TTP detection (roadmap §2, the moat).

Where MobSF is a generic app-security scanner, this module encodes the specific
tradecraft of Indian OTP-theft / banking trojans and correlates three evidence
sources into malicious-intent verdicts:

  * manifest facts   — accessibility service, SMS_RECEIVED receiver, overlay perm
  * dex string pool  — Telegram tokens, C2 URLs, emulator/root/packer markers
  * decompiled Java  — API usage (performGlobalAction, createFromPdu, sendText…)

Detectors (each emits findings + feeds the summary):
  accessibility abuse · SMS/OTP interception + exfil channel · overlay phishing ·
  C2 channel classification · dropper/second-stage · string decryption /
  reflection · anti-analysis · packer.

Everything degrades gracefully: manifest + string signals work with no jadx;
source signals sharpen the verdict when decompilation is available.
"""

import os
import re
import zipfile

from core.static.decompiler import iter_java_files

_NS = "{http://schemas.android.com/apk/res/android}"

# ── Signatures over the DEX string pool (constants; available without jadx) ────
_STRING_SIGS = {
    "telegram_token":  re.compile(r"\b\d{6,10}:[A-Za-z0-9_-]{35}\b"),
    "telegram_api":    re.compile(r"api\.telegram\.org"),
    "pastebin":        re.compile(r"pastebin\.com/raw"),
    "github_raw":      re.compile(r"raw\.githubusercontent\.com"),
    "emulator":        re.compile(r"ro\.kernel\.qemu|goldfish|ranchu|sdk_gphone|vbox86|Genymotion", re.I),
    "root":            re.compile(r"/system/(x?bin)/su\b|Superuser\.apk|com\.topjohnwu\.magisk|eu\.chainfire", re.I),
    "root_check_word": re.compile(r"\bisDeviceRooted\b|\bRootBeer\b"),
    "otp_keyword":     re.compile(r"\bOTP\b|one[\s_-]?time[\s_-]?password", re.I),
}

# ── Signatures over decompiled Java source (API usage) ────────────────────────
_SOURCE_SIGS = {
    "accessibility_api": re.compile(r"onAccessibilityEvent|performGlobalAction|dispatchGesture|getRootInActiveWindow|AccessibilityNodeInfo"),
    "sms_read":          re.compile(r"createFromPdu|getMessageBody|getOriginatingAddress|SmsMessage"),
    "sms_send":          re.compile(r"sendTextMessage|sendMultipartTextMessage|SmsManager"),
    "webview_bridge":    re.compile(r"addJavascriptInterface"),
    "overlay_api":       re.compile(r"TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|TYPE_PHONE"),
    "dex_loader":        re.compile(r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader|DexFile"),
    "pkg_installer":     re.compile(r"PackageInstaller|ACTION_INSTALL_PACKAGE|installPackage|commitSession"),
    "reflection":        re.compile(r"Class\.forName|getDeclaredMethod|getMethod\(|Method\.invoke"),
    "decrypt":           re.compile(r"Cipher\.getInstance|SecretKeySpec|Base64\.decode|doFinal\("),
    "device_admin":      re.compile(r"DevicePolicyManager|DeviceAdminReceiver|lockNow\(|resetPassword"),
    "frida_xposed":      re.compile(r"frida|xposed|de\.robv\.android", re.I),
    "debugger_check":    re.compile(r"isDebuggerConnected|TracerPid"),
}

# Known packer class-path prefixes.
_PACKER_CLASSES = {
    "com/qihoo/util": "Qihoo 360 Jiagu", "com/stub/StubApp": "Jiagu StubApp",
    "com/secneo/apkwrapper": "Bangcle/SecNeo", "s/h/e/l/l": "Bangcle",
    "com/tencent/StubShell": "Tencent Legu", "com/ali/mobisecenhance": "Alibaba",
    "com/baidu/protect": "Baidu", "com/kiwisec": "Kiwi", "com/nqshield": "NQShield",
}

_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
_IP_RE  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def detect(ctx, apk_meta: dict, dex_strings: list[str]) -> tuple[list[dict], dict]:
    """Returns (findings, summary). summary carries c2_channels, exfil_channel,
    phishing_assets and the list of matched behaviours for reporting/DB."""
    findings: list[dict] = []
    summary = {"behaviors": [], "c2_channels": [], "exfil_channel": None,
               "phishing_assets": []}

    def add(sev, title, detail, where="static analysis"):
        findings.append({"category": "BEHAVIOUR", "severity": sev, "title": title,
                         "detail": detail, "found_at": where})

    sigs   = _gather_signals(ctx, dex_strings)
    mani   = _manifest_facts(ctx.a)
    perms  = set(apk_meta.get("permissions", []))
    tags   = set(apk_meta.get("malware_tags", []))
    assets = _asset_inventory(ctx.apk_path)

    # ── C2 channel classification (needed by SMS/overlay exfil labelling) ──────
    channels = _classify_c2(sigs, dex_strings)
    summary["c2_channels"] = channels
    if channels:
        top = channels[0]
        add("CRITICAL" if top["type"] in ("telegram", "firebase") else "HIGH",
            f"C2 channel: {top['type']}",
            "; ".join(f"{c['type']}={c['value']}" for c in channels[:6]),
            "C2 configuration")

    # ── Accessibility-service abuse ───────────────────────────────────────────
    if mani["accessibility_service"] or "accessibility_abuse" in tags or "accessibility_api" in sigs:
        strong = mani["accessibility_service"] and "accessibility_api" in sigs
        add("CRITICAL" if strong else "HIGH", "Accessibility-service abuse",
            "Declares an accessibility service"
            + (" and uses screen-reading / gesture APIs" if "accessibility_api" in sigs else "")
            + " — used to auto-grant permissions, read on-screen OTPs and drive banking apps.",
            _loc(sigs, "accessibility_api"))
        summary["behaviors"].append("accessibility_abuse")

    # ── SMS / OTP interception + exfil ────────────────────────────────────────
    sms_recv = mani["sms_received_receiver"] or {"android.permission.RECEIVE_SMS",
               "android.permission.READ_SMS"} & perms
    if sms_recv or "sms_read" in sigs:
        exfil = _exfil_channel(channels, sigs)
        summary["exfil_channel"] = exfil
        if "sms_read" in sigs and (exfil or "sms_send" in sigs):
            summary["behaviors"].append("otp_interception")
            add("CRITICAL", "SMS/OTP interception with exfiltration",
                f"Reads incoming SMS (PDU parsing) and forwards via "
                f"{exfil or 'SMS'} — core OTP-theft behaviour.",
                _loc(sigs, "sms_read"))
        else:
            add("HIGH", "SMS interception capability",
                "Registers for incoming SMS / reads the inbox — OTP interception vector.",
                _loc(sigs, "sms_read") if "sms_read" in sigs else "AndroidManifest.xml")

    # ── Overlay / phishing screens ────────────────────────────────────────────
    overlay = ("android.permission.SYSTEM_ALERT_WINDOW" in perms
               or "overlay_api" in sigs or "overlay" in tags)
    if overlay:
        html_assets = assets["html"]
        summary["phishing_assets"] = html_assets
        if html_assets and "webview_bridge" in sigs:
            summary["behaviors"].append("overlay_phishing")
            add("CRITICAL", "Overlay phishing with bundled HTML",
                f"Overlay capability + WebView JS bridge + {len(html_assets)} bundled "
                f"HTML asset(s): {', '.join(html_assets[:5])} — fake bank login surface.",
                "assets/")
            _extract_phishing_html(ctx, html_assets)
        else:
            add("HIGH", "Overlay window capability",
                "Can draw windows over other apps (TYPE_APPLICATION_OVERLAY / "
                "SYSTEM_ALERT_WINDOW) — overlay-attack surface.",
                _loc(sigs, "overlay_api") if "overlay_api" in sigs else "AndroidManifest.xml")

    # ── Dropper / second-stage ────────────────────────────────────────────────
    hidden = assets["dex"] + assets["apk"]
    if ("dropper" in tags or "pkg_installer" in sigs or "dex_loader" in sigs or hidden):
        detail = []
        if hidden:              detail.append(f"hidden payload(s): {', '.join(hidden[:5])}")
        if "dex_loader" in sigs: detail.append("dynamic DEX loading")
        if "pkg_installer" in sigs: detail.append("PackageInstaller usage")
        if "android.permission.REQUEST_INSTALL_PACKAGES" in perms: detail.append("install-packages permission")
        sev = "CRITICAL" if (hidden and ("dex_loader" in sigs or "pkg_installer" in sigs)) else "HIGH"
        summary["behaviors"].append("dropper")
        add(sev, "Dropper / second-stage payload",
            "; ".join(detail) or "second-stage capability present", "assets/ + code")

    # ── String decryption / heavy reflection (obfuscation) ────────────────────
    if "decrypt" in sigs and "reflection" in sigs:
        add("MEDIUM", "String decryption + reflection (obfuscation)",
            "Combines runtime decryption with reflective invocation — C2/strings "
            "are likely hidden; prioritise dynamic analysis to recover them.",
            _loc(sigs, "decrypt"))
        summary["behaviors"].append("obfuscation")

    # ── Device-admin persistence ──────────────────────────────────────────────
    if "device_admin" in sigs or "android.permission.BIND_DEVICE_ADMIN" in perms:
        add("HIGH", "Device-admin persistence",
            "Requests device-administrator powers — resists uninstall and can lock "
            "the device / reset credentials.", _loc(sigs, "device_admin"))
        summary["behaviors"].append("device_admin")

    # ── Anti-analysis ─────────────────────────────────────────────────────────
    anti = [k for k in ("emulator", "root", "root_check_word") if k in sigs] + \
           [k for k in ("frida_xposed", "debugger_check") if k in sigs]
    if anti:
        add("MEDIUM", "Anti-analysis / evasion",
            "Checks for " + ", ".join(sorted({
                "emulator" if a == "emulator" else
                "root" if a in ("root", "root_check_word") else
                "Frida/Xposed" if a == "frida_xposed" else "debugger"
                for a in anti})) + " — the sample resists sandboxing.",
            "static analysis")
        summary["behaviors"].append("anti_analysis")

    # ── Packer ────────────────────────────────────────────────────────────────
    packer = _detect_packer(ctx.class_names)
    if packer:
        add("HIGH", f"Packed with {packer}",
            f"Commercial packer '{packer}' detected — DEX is protected/encrypted; "
            "static coverage is limited, route to unpacking/dynamic analysis.",
            "DEX classes")
        summary["behaviors"].append("packed")

    return findings, summary


# ── Signal gathering ──────────────────────────────────────────────────────────

def _gather_signals(ctx, dex_strings) -> dict:
    """Return {sig_id: (location, sample)} for every matched signature."""
    present = {}

    blob = "\n".join(dex_strings)
    for sid, rx in _STRING_SIGS.items():
        m = rx.search(blob)
        if m:
            present[sid] = ("dex-strings", m.group(0)[:80])

    if ctx.source_dir:
        remaining = set(_SOURCE_SIGS)
        for jf in iter_java_files(ctx.source_dir):
            if not remaining:
                break
            try:
                text = open(jf, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            rel = os.path.relpath(jf, ctx.source_dir)
            for sid in list(remaining):
                if _SOURCE_SIGS[sid].search(text):
                    present[sid] = (rel, "")
                    remaining.discard(sid)
    return present


def _loc(sigs, sid):
    return sigs.get(sid, ("static analysis", ""))[0]


def _manifest_facts(a) -> dict:
    facts = {"accessibility_service": False, "sms_received_receiver": False}
    try:
        m = a.get_android_manifest_xml()
    except Exception:
        return facts
    for svc in m.iter("service"):
        if svc.get(_NS + "permission") == "android.permission.BIND_ACCESSIBILITY_SERVICE":
            facts["accessibility_service"] = True
        for act in svc.iter("action"):
            if act.get(_NS + "name") == "android.accessibilityservice.AccessibilityService":
                facts["accessibility_service"] = True
    for recv in m.iter("receiver"):
        for act in recv.iter("action"):
            if act.get(_NS + "name") == "android.provider.Telephony.SMS_RECEIVED":
                facts["sms_received_receiver"] = True
    return facts


def _asset_inventory(apk_path: str) -> dict:
    inv = {"html": [], "dex": [], "apk": [], "js": []}
    try:
        with zipfile.ZipFile(apk_path) as z:
            for n in z.namelist():
                low = n.lower()
                if low.startswith(("assets/", "res/raw/")):
                    if low.endswith((".html", ".htm")): inv["html"].append(n)
                    elif low.endswith(".js"):           inv["js"].append(n)
                    elif low.endswith(".dex"):          inv["dex"].append(n)
                    elif low.endswith((".apk", ".jar")): inv["apk"].append(n)
    except (zipfile.BadZipFile, OSError):
        pass
    return inv


def _classify_c2(sigs, dex_strings) -> list[dict]:
    """Ordered list of C2 channels, most-attributable first."""
    channels = []
    if "telegram_token" in sigs:
        channels.append({"type": "telegram", "value": sigs["telegram_token"][1]})
    elif "telegram_api" in sigs:
        channels.append({"type": "telegram", "value": "api.telegram.org"})
    if "pastebin" in sigs:
        channels.append({"type": "dead_drop", "value": "pastebin.com/raw"})
    if "github_raw" in sigs:
        channels.append({"type": "dead_drop", "value": "raw.githubusercontent.com"})

    blob = "\n".join(dex_strings)
    urls = [u for u in dict.fromkeys(_URL_RE.findall(blob))
            if not any(s in u for s in ("schemas.android.com", "w3.org", "apache.org",
                                        "google.com/apis", "goo.gl", "gstatic.com"))]
    for u in urls[:8]:
        channels.append({"type": "http", "value": u[:120]})
    ips = [ip for ip in dict.fromkeys(_IP_RE.findall(blob))
           if not ip.startswith(("0.", "127.", "255.", "1.2.3", "8.8.8"))]
    for ip in ips[:5]:
        channels.append({"type": "ip", "value": ip})
    return channels


def _exfil_channel(channels, sigs) -> str | None:
    for c in channels:
        if c["type"] in ("telegram", "firebase", "http", "ip", "dead_drop"):
            return c["type"]
    if "sms_send" in sigs:
        return "sms"
    return None


def _detect_packer(class_names) -> str | None:
    for prefix, name in _PACKER_CLASSES.items():
        if any(cn.startswith(prefix) for cn in class_names):
            return name
    return None


def _extract_phishing_html(ctx, html_assets):
    """Copy bundled phishing HTML into the evidence directory for the case pack."""
    from config import EVIDENCE_DIR
    out = os.path.join(EVIDENCE_DIR, ctx.sha256[:16], "phishing")
    try:
        os.makedirs(out, exist_ok=True)
        with zipfile.ZipFile(ctx.apk_path) as z:
            for name in html_assets[:20]:
                dst = os.path.join(out, os.path.basename(name))
                with z.open(name) as src, open(dst, "wb") as f:
                    f.write(src.read())
    except (zipfile.BadZipFile, OSError):
        pass
