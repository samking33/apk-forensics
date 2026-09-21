"""
Permission Intelligence — replaces the flat DANGEROUS_PERMISSIONS set with a
scored, described, malware-tagged table (data/permissions.json).

For each requested permission we emit a finding carrying a human description and
severity, accumulate a permission risk contribution, and collect malware-relevance
tags (accessibility_abuse, sms_intercept, overlay, dropper, …) that downstream
behaviour detection keys off.
"""

import json
import os

_DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "data", "permissions.json")

_SEVERITY_POINTS = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1, "INFO": 0}


def _load_map():
    with open(_DATA, encoding="utf-8") as f:
        data = json.load(f)
    data.pop("_comment", None)
    return data


def analyse(permissions: list[str]) -> tuple[list[dict], int, list[str]]:
    """
    Returns (findings, permission_points, malware_tags).
    permission_points is capped so a permission-spray app can't alone max the score.
    """
    perm_map = _load_map()
    findings: list[dict] = []
    tags: set[str] = set()
    points = 0

    for perm in permissions:
        info = perm_map.get(perm)
        if not info:
            continue
        sev = info["severity"]
        points += _SEVERITY_POINTS.get(sev, 0)
        if info.get("tag"):
            tags.add(info["tag"])
        findings.append({
            "category": "PERMISSION",
            "severity": sev,
            "title"   : f"Permission: {perm.split('.')[-1]}",
            "detail"  : info["desc"],
            "found_at": "AndroidManifest.xml",
        })

    return findings, min(points, 50), sorted(tags)


if __name__ == "__main__":
    # ponytail self-check: a known banking-trojan permission set must score high
    # and surface the accessibility + sms + overlay tags.
    perms = [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.RECEIVE_SMS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.INTERNET",
        "android.permission.VIBRATE",
    ]
    f, pts, tags = analyse(perms)
    assert pts >= 40, f"expected high score, got {pts}"
    assert {"accessibility_abuse", "sms_intercept", "overlay"} <= set(tags), tags
    assert any(x["severity"] == "CRITICAL" for x in f)
    print(f"OK — findings={len(f)} points={pts} tags={tags}")
