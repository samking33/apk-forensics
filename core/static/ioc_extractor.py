"""
IoC Extractor — builds structured Indicator of Compromise table from all findings.
"""

import hashlib
import os
from rich.console import Console

console = Console()


def extract(apk_path: str, apk_meta: dict, mined: dict, firebase: dict) -> list[dict]:
    iocs = []

    def add(ioc_type, value, description):
        if value:
            iocs.append({
                "ioc_type"   : ioc_type,
                "value"      : str(value).strip(),
                "description": description,
            })

    # File hashes
    add("HASH_SHA256", apk_meta.get("sha256"), f"SHA-256 of {apk_meta.get('filename')}")

    # Try MD5 as well
    try:
        h = hashlib.md5()
        with open(apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        add("HASH_MD5", h.hexdigest(), f"MD5 of {apk_meta.get('filename')}")
    except Exception:
        pass

    # Package
    add("PACKAGE", apk_meta.get("package_name"), "Android package name")

    # Certificate
    add("CERT_SHA256", apk_meta.get("cert_sha256"),    "APK signing certificate SHA-256")
    add("CERT_SERIAL", apk_meta.get("cert_serial"),    "Certificate serial number")
    add("CERT_SUBJECT", apk_meta.get("cert_subject"),  "Certificate subject (CN)")

    # Firebase
    add("FIREBASE_PROJECT", firebase.get("firebase_project"), "Firebase project ID (C2 backend)")
    add("FIREBASE_API_KEY", firebase.get("firebase_api_key"), "Firebase API key (embedded in APK)")
    add("FIREBASE_RTDB",    firebase.get("rtdb_url"),         "Firebase Realtime DB URL")
    add("FIREBASE_BUCKET",  firebase.get("storage_bucket"),   "Firebase Storage bucket")

    # Phones
    for ph in mined.get("phone_in", []):
        clean = ph.replace("+91", "").replace("91", "", 1).strip()
        if len(clean) == 10:
            add("PHONE", clean, "Indian phone number found in APK strings")

    # URLs / Domains
    for url in mined.get("url_http", [])[:30]:
        add("URL", url, "URL found in APK strings")

    # IPs
    for ip in mined.get("ip_address", []):
        if not ip.startswith(("127.", "10.", "192.168.", "0.")):
            add("IP", ip, "IP address found in APK strings")

    # Emails
    for em in mined.get("email", []):
        if not any(x in em for x in ["@android.", "@google.", "@example."]):
            add("EMAIL", em, "Email address found in APK strings")

    # AES keys
    for key in mined.get("aes_key", []):
        add("AES_KEY", key, "Possible AES encryption key found in APK strings")

    # Dangerous permissions as IoC
    for perm in apk_meta.get("dangerous_perms", []):
        add("PERMISSION", perm, "Dangerous Android permission declared")

    return iocs
