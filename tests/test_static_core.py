"""
Regression tests for the static-analysis core.

Covers the logic that has no external dependency: permission intelligence,
manifest security audit (via a synthetic androguard-like object), and YARA
rule compilation. Run: python3 -m tests.test_static_core
"""

from lxml import etree

from core.static import permission_intel, manifest_audit

_NS = "http://schemas.android.com/apk/res/android"


def _a(name):
    return f"{{{_NS}}}{name}"


class _FakeAPK:
    """Minimal stand-in exposing the two methods manifest_audit.audit() uses."""
    def __init__(self, xml_root, target_sdk):
        self._root = xml_root
        self._target = target_sdk

    def get_android_manifest_xml(self):
        return self._root

    def get_target_sdk_version(self):
        return self._target


def _build_manifest():
    manifest = etree.Element("manifest")
    app = etree.SubElement(manifest, "application")
    app.set(_a("debuggable"), "true")
    app.set(_a("usesCleartextTraffic"), "true")

    # Exported activity with no guarding permission.
    act = etree.SubElement(app, "activity")
    act.set(_a("name"), "com.evil.MainActivity")
    act.set(_a("exported"), "true")

    # Exported provider, unprotected.
    prov = etree.SubElement(app, "provider")
    prov.set(_a("name"), "com.evil.LeakProvider")
    prov.set(_a("exported"), "true")

    # Weakly-protected custom permission.
    perm = etree.SubElement(manifest, "permission")
    perm.set(_a("name"), "com.evil.SECRET")
    perm.set(_a("protectionLevel"), "normal")
    return manifest


def test_permission_intel():
    perms = [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.RECEIVE_SMS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.INTERNET",
    ]
    findings, pts, tags = permission_intel.analyse(perms)
    assert pts >= 40, f"trojan perm set should score high, got {pts}"
    assert {"accessibility_abuse", "sms_intercept", "overlay"} <= set(tags)
    assert any(f["severity"] == "CRITICAL" for f in findings)

    # Benign app scores ~0 and raises no tags.
    f2, p2, t2 = permission_intel.analyse(["android.permission.VIBRATE"])
    assert p2 <= 1 and t2 == []


def test_manifest_audit():
    a = _FakeAPK(_build_manifest(), target_sdk=33)
    findings, pts = manifest_audit.audit(a)
    titles = " ".join(f["title"] for f in findings)
    assert "debuggable" in titles
    assert "Cleartext" in titles
    assert "content provider" in titles
    assert "Exported activity" in titles
    assert "weak protection" in titles
    assert pts > 0

    # Clean manifest → no findings, zero points.
    clean = etree.Element("manifest")
    etree.SubElement(clean, "application")
    f2, p2 = manifest_audit.audit(_FakeAPK(clean, 33))
    assert p2 == 0 and f2 == []


def test_yara_rules_compile():
    import yara, os
    from config import YARA_RULES_DIR
    for f in os.listdir(YARA_RULES_DIR):
        if f.endswith(".yar"):
            yara.compile(filepath=os.path.join(YARA_RULES_DIR, f))  # raises on error


if __name__ == "__main__":
    test_permission_intel()
    test_manifest_audit()
    test_yara_rules_compile()
    print("OK — static core: permission_intel, manifest_audit, yara compile all pass")
