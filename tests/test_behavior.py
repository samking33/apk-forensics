"""
Behaviour-detector regression test — the banking-trojan moat.

Builds a synthetic trojan from its constituent evidence (malicious manifest,
decompiled source with the tell-tale API calls, a hidden second-stage payload,
and a Telegram C2 token in the string pool) and asserts every §2 detector fires.
Run: python3 -m tests.test_behavior
"""

import os
import tempfile
import zipfile

from lxml import etree
from core.static import behavior_detector

_NS = "http://schemas.android.com/apk/res/android"


def _a(n):
    return f"{{{_NS}}}{n}"


class _FakeAPK:
    def __init__(self, root):
        self._root = root

    def get_android_manifest_xml(self):
        return self._root


class _FakeCtx:
    def __init__(self, apk_path, source_dir):
        self.apk_path = apk_path
        self.source_dir = source_dir
        self.sha256 = "test0000test0000test0000test0000test0000test0000test0000test0000"
        self.class_names = ["com/qihoo/util/StubApp", "com/evil/Main"]  # packer
        self.a = _FakeAPK(self._manifest())

    def _manifest(self):
        m = etree.Element("manifest")
        app = etree.SubElement(m, "application")
        svc = etree.SubElement(app, "service")
        svc.set(_a("permission"), "android.permission.BIND_ACCESSIBILITY_SERVICE")
        recv = etree.SubElement(app, "receiver")
        itf = etree.SubElement(recv, "intent-filter")
        act = etree.SubElement(itf, "action")
        act.set(_a("name"), "android.provider.Telephony.SMS_RECEIVED")
        return m


_MALICIOUS_JAVA = """
public class Payload {
  public void onAccessibilityEvent(AccessibilityEvent e) { performGlobalAction(1); }
  void steal(Object pdu) { SmsMessage m = SmsMessage.createFromPdu((byte[])pdu); m.getMessageBody(); }
  void forward(String otp) { SmsManager.getDefault().sendTextMessage(a,b,otp,c,d); }
  void overlay() { wm.addView(v, TYPE_APPLICATION_OVERLAY); web.addJavascriptInterface(o, "x"); }
  void stage2() { new DexClassLoader(p,o,l,cl); new PackageInstaller(); }
  String dec(byte[] b) { Cipher.getInstance("AES"); return new String(Base64.decode(b,0)); }
  void refl() { Class.forName("x").getDeclaredMethod("y"); }
}
"""


def build_case():
    d = tempfile.mkdtemp()
    src = os.path.join(d, "src")
    os.makedirs(src)
    with open(os.path.join(src, "Payload.java"), "w") as f:
        f.write(_MALICIOUS_JAVA)

    apk = os.path.join(d, "evil.apk")
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("assets/login.html", "<html>fake bank login</html>")
        z.writestr("assets/stage2.dex", b"dex\n035\x00payload")
    return _FakeCtx(apk, src)


def test_moat():
    ctx = build_case()
    apk_meta = {
        "permissions": [
            "android.permission.RECEIVE_SMS", "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
        ],
        "malware_tags": ["accessibility_abuse", "sms_intercept", "overlay", "dropper"],
    }
    dex_strings = [
        "123456789:AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQRS",  # telegram bot token (35 char tail)
        "api.telegram.org",
        "goldfish ro.kernel.qemu",
        "/system/xbin/su",
        "http://evil-c2.example/gate.php",
    ]

    findings, summary = behavior_detector.detect(ctx, apk_meta, dex_strings)
    behaviors = set(summary["behaviors"])

    expected = {"accessibility_abuse", "otp_interception", "overlay_phishing",
                "dropper", "device_admin", "obfuscation", "anti_analysis", "packed"}
    missing = expected - behaviors
    assert not missing, f"detectors missed: {missing} (got {behaviors})"

    assert summary["c2_channels"] and summary["c2_channels"][0]["type"] == "telegram", summary["c2_channels"]
    assert summary["exfil_channel"] == "telegram", summary["exfil_channel"]
    assert any(f["severity"] == "CRITICAL" for f in findings)

    # Phishing HTML must have been extracted into the evidence dir.
    from config import EVIDENCE_DIR
    extracted = os.path.join(EVIDENCE_DIR, ctx.sha256[:16], "phishing", "login.html")
    assert os.path.exists(extracted), "phishing HTML not extracted"

    print(f"OK — behaviours={sorted(behaviors)} | c2={summary['c2_channels'][0]['type']} "
          f"| exfil={summary['exfil_channel']} | findings={len(findings)}")


if __name__ == "__main__":
    test_moat()
