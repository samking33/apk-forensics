"""
SBOM Fingerprinting — identify third-party libraries bundled in the APK by
matching class-path prefixes against a known-library map (data/libraries.json).

Forensic value: a hollow malware shell has almost no legitimate libraries; a
repackaged/trojanized real app carries the original app's full dependency set.
The delta between the two is itself a signal, and the framework (Flutter, Unity,
Cordova) tells the analyst where to look for the real code.
"""

import json
import os

_DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "data", "libraries.json")


def _load():
    with open(_DATA, encoding="utf-8") as f:
        return json.load(f)["libraries"]


def analyse(class_names: list[str], app_package: str | None = None) -> tuple[list[dict], list[str]]:
    """Returns (findings, libraries). libraries = friendly names, sorted."""
    known = _load()
    present = set()
    for prefix, friendly in known.items():
        if any(cn.startswith(prefix) for cn in class_names):
            present.add(friendly)

    libraries = sorted(present)
    findings = []
    if libraries:
        findings.append({
            "category": "SBOM",
            "severity": "INFO",
            "title"   : f"Bundled libraries ({len(libraries)})",
            "detail"  : ", ".join(libraries),
            "found_at": "DEX classes",
        })

    # A cross-platform framework tells the analyst the real logic isn't in DEX.
    frameworks = {"Flutter", "React Native", "Unity Engine", "Apache Cordova", "Cocos2d-x"}
    for fw in sorted(frameworks & present):
        findings.append({
            "category": "SBOM", "severity": "LOW",
            "title": f"Cross-platform framework: {fw}",
            "detail": f"Core logic likely lives outside DEX ({fw}) — inspect "
                      "assets/native payload, not just decompiled Java.",
            "found_at": "DEX classes",
        })

    return findings, libraries


if __name__ == "__main__":
    classes = ["okhttp3/OkHttpClient", "retrofit2/Retrofit",
               "io/flutter/embedding/FlutterActivity", "com/evil/Main"]
    f, libs = analyse(classes, "com.evil")
    assert "OkHttp" in libs and "Retrofit" in libs and "Flutter" in libs, libs
    assert any("framework" in x["title"].lower() for x in f)
    print(f"OK — libraries={libs}")
