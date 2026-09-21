"""
Tracker / Ad-SDK Detection — Exodus-Privacy-style fingerprinting.

Matches bundled tracker class-path signatures (data/trackers.json) against the
APK's class names. For banking-trojan casework trackers are context rather than
verdict — but their presence (and which analytics/ad networks) helps profile
repackaged apps and distinguishes a genuine app from a hollow malware shell.
"""

import json
import os

_DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "data", "trackers.json")


def _load():
    with open(_DATA, encoding="utf-8") as f:
        return json.load(f)["trackers"]


def detect(class_names: list[str]) -> tuple[list[dict], list[dict]]:
    """Returns (findings, trackers_found). trackers_found = [{name, category}]."""
    trackers = _load()
    found = []
    for t in trackers:
        sig = t["signature"]
        if any(cn.startswith(sig) for cn in class_names):
            found.append({"name": t["name"], "category": t["category"]})

    findings = []
    if found:
        by_cat: dict[str, list[str]] = {}
        for t in found:
            by_cat.setdefault(t["category"], []).append(t["name"])
        detail = "; ".join(f"{cat}: {', '.join(names)}" for cat, names in sorted(by_cat.items()))
        findings.append({
            "category": "TRACKER",
            "severity": "LOW",
            "title"   : f"Third-party trackers detected ({len(found)})",
            "detail"  : detail,
            "found_at": "DEX classes",
        })
    return findings, found


if __name__ == "__main__":
    # ponytail self-check: planted firebase/admob class names must be detected.
    classes = [
        "com/google/firebase/analytics/FirebaseAnalytics",
        "com/google/android/gms/ads/AdView",
        "com/example/app/MainActivity",
    ]
    f, found = detect(classes)
    names = {t["name"] for t in found}
    assert "Google Firebase Analytics" in names, names
    assert "Google AdMob" in names, names
    assert f and f[0]["category"] == "TRACKER"
    print(f"OK — trackers found={sorted(names)}")
