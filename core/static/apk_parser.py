"""
APK Parser — uses androguard to extract manifest, certificates, permissions,
components, and basic metadata without any external binary tools.
"""

import hashlib
import os
from datetime import datetime, timezone

from rich.console import Console

console = Console()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_apk(apk_path: str, a=None, d=None, dx=None) -> dict:
    """
    Full APK metadata extraction.
    Returns a dict with all static fields ready to populate the Apk model.

    Pass pre-analyzed androguard objects (a, d, dx) to reuse a single AnalyzeAPK
    call — the analysis is the slowest step in the pipeline. Falls back to
    analyzing here if they are not supplied (keeps standalone callers working).
    """
    console.print(f"  [cyan]Parsing APK: {os.path.basename(apk_path)}[/cyan]")

    result = {
        "sha256"        : sha256_file(apk_path),
        "filename"      : os.path.basename(apk_path),
        "file_path"     : os.path.abspath(apk_path),
        "package_name"  : None,
        "version_name"  : None,
        "version_code"  : None,
        "min_sdk"       : None,
        "target_sdk"    : None,
        "cert_serial"   : None,
        "cert_subject"  : None,
        "cert_sha256"   : None,
        "permissions"   : [],
        "dangerous_perms": [],
        "activities"    : [],
        "services"      : [],
        "receivers"     : [],
        "providers"     : [],
        "main_activity" : None,
        "exported_components": [],
        "errors"        : [],
    }

    try:
        if a is None:
            from androguard.misc import AnalyzeAPK
            a, d, dx = AnalyzeAPK(apk_path)

        result["package_name"]  = a.get_package()
        result["version_name"]  = a.get_androidversion_name()
        result["version_code"]  = a.get_androidversion_code()
        result["min_sdk"]       = _safe_int(a.get_min_sdk_version())
        result["target_sdk"]    = _safe_int(a.get_target_sdk_version())
        result["main_activity"] = a.get_main_activity()
        result["activities"]    = list(a.get_activities())
        result["services"]      = list(a.get_services())
        result["receivers"]     = list(a.get_receivers())
        result["providers"]     = list(a.get_providers())

        # Permissions
        perms = list(a.get_permissions())
        result["permissions"] = perms

        from config import DANGEROUS_PERMISSIONS
        result["dangerous_perms"] = [p for p in perms if p in DANGEROUS_PERMISSIONS]

        # Exported components (attack surface) — read the real android:exported
        # attribute / implicit export via intent-filter from the manifest XML.
        result["exported_components"] = _exported_components(a)

        # Certificate
        try:
            certs = a.get_certificates_der_v2() or a.get_certificates_der_v1()
            if certs:
                from androguard.core.apk import Certificate
                cert_der = list(certs.values())[0][0] if isinstance(certs, dict) else certs[0]
                cert_hash = hashlib.sha256(cert_der).hexdigest()
                result["cert_sha256"] = cert_hash

                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                    result["cert_subject"] = cert_obj.subject.rfc4514_string()
                    result["cert_serial"]  = hex(cert_obj.serial_number)
                except Exception:
                    pass
        except Exception as e:
            result["errors"].append(f"cert: {e}")

    except Exception as e:
        result["errors"].append(f"parse: {e}")
        console.print(f"  [red]Parse error: {e}[/red]")

    return result


def _safe_int(val):
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _exported_components(a) -> list[str]:
    """Component names that are reachable by other apps: explicit
    android:exported="true", or (attribute absent) an intent-filter is present."""
    exported = []
    try:
        m = a.get_android_manifest_xml()
    except Exception:
        return exported
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for el in m.iter(tag):
            exp = el.get(_ANDROID_NS + "exported")
            is_exp = (exp.strip().lower() == "true") if exp is not None \
                     else el.find("intent-filter") is not None
            if is_exp:
                exported.append(el.get(_ANDROID_NS + "name") or "?")
    return exported


def extract_dex_strings(apk_path: str, d=None) -> list[str]:
    """Extract all strings from DEX bytecode via androguard.
    Pass the pre-analyzed DEX list `d` to avoid re-running AnalyzeAPK."""
    strings = []
    try:
        if d is None:
            from androguard.misc import AnalyzeAPK
            _a, d, _dx = AnalyzeAPK(apk_path)
        for dex in (d if isinstance(d, list) else [d]):
            if dex is None:
                continue
            for s in dex.get_strings():
                val = str(s)
                if len(val) > 4:
                    strings.append(val)
    except Exception as e:
        console.print(f"  [yellow]DEX string extraction warning: {e}[/yellow]")
    return strings


def extract_resource_strings(apk_path: str) -> list[str]:
    """Extract strings from res/values/strings.xml and assets."""
    import zipfile
    strings = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if name.startswith("assets/") or name == "res/values/strings.xml":
                    try:
                        data = z.read(name).decode("utf-8", errors="replace")
                        strings.append(data)
                    except Exception:
                        pass
                # google-services.json — critical for Firebase config
                if name == "assets/google-services.json" or name == "google-services.json":
                    try:
                        data = z.read(name).decode("utf-8", errors="replace")
                        strings.append(data)
                    except Exception:
                        pass
    except Exception as e:
        console.print(f"  [yellow]Resource extraction warning: {e}[/yellow]")
    return strings
