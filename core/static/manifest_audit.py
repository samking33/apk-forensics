"""
Manifest Security Audit — MobSF-style scorecard over AndroidManifest.xml.

Flags the classic misconfigurations: debuggable, allowBackup, cleartext traffic,
exported components without a guarding permission, exported content providers,
and weakly-protected custom permissions. Returns findings + a manifest risk
contribution (points, capped) that feeds the overall score.

Works off the single parsed androguard APK object (ctx.a) — no re-parsing.
"""

_NS = "{http://schemas.android.com/apk/res/android}"


def _attr(el, name):
    return el.get(_NS + name)


def _is_exported(el, target_sdk):
    """Effective export state of a component element.
    Explicit android:exported wins. Absent + has intent-filter = exported
    (implicit export; on targetSdk>=31 Android forbids this, so if we still see
    it, treat it as exported and let the finding note the anomaly)."""
    exp = _attr(el, "exported")
    if exp is not None:
        return exp.strip().lower() == "true"
    return el.find("intent-filter") is not None


def audit(a) -> tuple[list[dict], int]:
    findings: list[dict] = []
    points = 0

    def add(severity, title, detail, pts, found_at="AndroidManifest.xml"):
        nonlocal points
        findings.append({"category": "MANIFEST", "severity": severity,
                         "title": title, "detail": detail, "found_at": found_at})
        points += pts

    try:
        m = a.get_android_manifest_xml()
    except Exception as e:
        return [{"category": "MANIFEST", "severity": "INFO",
                 "title": "Manifest parse failed", "detail": str(e),
                 "found_at": "AndroidManifest.xml"}], 0

    target_sdk = _safe_int(a.get_target_sdk_version()) or 0
    app = m.find("application")

    # ── Application-level flags ───────────────────────────────────────────────
    if app is not None:
        if _truthy(_attr(app, "debuggable")):
            add("HIGH", "Application is debuggable",
                "android:debuggable=\"true\" — runtime memory and data can be "
                "inspected on any device; must never ship in production.", 15)

        backup = _attr(app, "allowBackup")
        if _truthy(backup) or (backup is None and target_sdk < 31):
            add("MEDIUM", "Backups allowed",
                "android:allowBackup is enabled (explicitly or by default) — app "
                "data can be extracted via adb backup without root.", 6)

        if _truthy(_attr(app, "usesCleartextTraffic")):
            add("MEDIUM", "Cleartext traffic permitted",
                "android:usesCleartextTraffic=\"true\" — HTTP exfiltration/C2 "
                "is allowed unencrypted.", 8)

        if _attr(app, "networkSecurityConfig") is None and target_sdk < 28:
            add("LOW", "No network security config",
                f"targetSdk={target_sdk} and no networkSecurityConfig — cleartext "
                "is allowed by platform default.", 3)

    # ── Exported components ───────────────────────────────────────────────────
    exported_no_perm = {"activity": [], "service": [], "receiver": []}
    for tag in ("activity", "activity-alias", "service", "receiver"):
        for el in m.iter(tag):
            if not _is_exported(el, target_sdk):
                continue
            perm = _attr(el, "permission")
            name = _attr(el, "name") or "?"
            bucket = "activity" if tag.startswith("activity") else tag
            if not perm:
                exported_no_perm[bucket].append(name)

    for kind, names in exported_no_perm.items():
        if not names:
            continue
        shown = ", ".join(n.split(".")[-1] for n in names[:6])
        more = f" (+{len(names) - 6} more)" if len(names) > 6 else ""
        add("MEDIUM", f"Exported {kind} without permission ({len(names)})",
            f"Reachable by any other app with no guarding permission: {shown}{more}",
            min(4 + len(names), 12))

    # Exported content providers — data exfiltration surface, weighted higher.
    exported_providers = []
    for el in m.iter("provider"):
        if _is_exported(el, target_sdk) and not _attr(el, "permission"):
            exported_providers.append(_attr(el, "name") or "?")
    if exported_providers:
        shown = ", ".join(p.split(".")[-1] for p in exported_providers[:6])
        add("HIGH", f"Exported content provider ({len(exported_providers)})",
            f"Unprotected provider(s) expose app data to any installed app: {shown}", 12)

    # ── Weakly-protected custom permissions ───────────────────────────────────
    weak_perms = []
    for el in m.iter("permission"):
        level = (_attr(el, "protectionLevel") or "normal").lower()
        if "signature" not in level:   # normal/dangerous are app-grabbable
            weak_perms.append((_attr(el, "name") or "?", level))
    if weak_perms:
        shown = ", ".join(f"{n.split('.')[-1]}={lvl}" for n, lvl in weak_perms[:5])
        add("MEDIUM", f"Custom permission with weak protection ({len(weak_perms)})",
            f"protectionLevel not 'signature' — another app can hold it: {shown}", 5)

    return findings, min(points, 45)


def _truthy(v):
    return v is not None and str(v).strip().lower() == "true"


def _safe_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
