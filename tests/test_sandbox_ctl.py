"""
Test the one piece of sandbox_ctl with real logic: the uiautomator-dump parser
that turns a raw UI hierarchy into tappable targets with exact centre coords.
Run: python3 -m tests.test_sandbox_ctl
"""

from core.sandbox.sandbox_ctl import compact_ui

_SAMPLE = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" bounds="[0,0][1080,2340]">
    <node text="Enable Accessibility" resource-id="com.evil.app:id/btn_enable"
          clickable="true" class="android.widget.Button" bounds="[100,1000][980,1120]"/>
    <node text="" content-desc="Close dialog" resource-id="com.evil.app:id/close"
          clickable="true" class="android.widget.ImageView" bounds="[960,40][1040,120]"/>
    <node text="Enter your bank OTP" resource-id="com.evil.app:id/otp_label"
          clickable="false" class="android.widget.TextView" bounds="[100,600][980,660]"/>
    <node text="" resource-id="" clickable="false" class="android.view.View" bounds="[0,0][10,10]"/>
  </node>
</hierarchy>"""


def test_parses_actionable_elements():
    lines = compact_ui(_SAMPLE)
    joined = "\n".join(lines)

    # The accessibility button — the thing a trojan wants tapped — must be found
    # with its centre coordinate ((100+980)/2, (1000+1120)/2) = (540, 1060).
    assert any("[540,1060]" in l and "Enable Accessibility" in l for l in lines), joined

    # A no-text icon that is clickable is still surfaced via its content-desc.
    assert any("Close dialog" in l for l in lines), joined

    # A plain text label is captured (agent reads screen state), marked as text.
    assert any("Enter your bank OTP" in l and "text:" in l for l in lines), joined

    # The empty, unlabelled, non-clickable view is noise and must be dropped.
    assert "[5,5]" not in joined, "noise element not filtered"


def test_bad_xml_is_safe():
    assert compact_ui("not xml at all") == []
    assert compact_ui("") == []


if __name__ == "__main__":
    test_parses_actionable_elements()
    test_bad_xml_is_safe()
    for l in compact_ui(_SAMPLE):
        print("  ", l)
    print("OK — sandbox_ctl UI parser: tap targets + coords + noise filtering")
