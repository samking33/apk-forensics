"""
Insecure-API Code Scanner — MobSF-style source scanning over jadx output.

Streams every decompiled .java line against a versioned regex ruleset
(data/code_rules.json): weak crypto, disabled TLS validation, WebView JS bridges,
command execution, world-readable storage, etc. Each hit is a finding anchored to
file:line. Per-rule caps stop one noisy pattern from flooding the report.

Generic security-hygiene patterns live here; malicious *intent* patterns
(SMS forwarding, accessibility abuse, droppers) live in behavior_detector.
"""

import json
import os
import re

from core.static.decompiler import iter_java_files

_RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "data", "code_rules.json")

_PER_RULE_CAP = 20
_TOTAL_CAP    = 300


def _load_rules():
    with open(_RULES_PATH, encoding="utf-8") as f:
        rules = json.load(f)
    for r in rules:
        r["_re"] = re.compile(r["regex"])
    return rules


def scan(source_dir: str | None) -> list[dict]:
    """Scan decompiled sources. Returns findings; empty if no source (jadx absent)."""
    if not source_dir:
        return []

    rules = _load_rules()
    findings: list[dict] = []
    counts: dict[str, int] = {}

    for jf in iter_java_files(source_dir):
        rel = os.path.relpath(jf, source_dir)
        try:
            with open(jf, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    if len(line) > 2000:        # skip minified/one-line blobs
                        continue
                    for r in rules:
                        if counts.get(r["id"], 0) >= _PER_RULE_CAP:
                            continue
                        if r["_re"].search(line):
                            findings.append({
                                "category": "CODE",
                                "severity": r["severity"],
                                "title"   : r["title"],
                                "detail"  : line.strip()[:180],
                                "found_at": f"{rel}:{lineno}",
                            })
                            counts[r["id"]] = counts.get(r["id"], 0) + 1
                            if len(findings) >= _TOTAL_CAP:
                                return findings
        except OSError:
            continue

    return findings


if __name__ == "__main__":
    # ponytail self-check: rules must compile and flag a planted insecure snippet.
    import tempfile
    rules = _load_rules()
    assert len(rules) >= 10
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "Evil.java")
        with open(p, "w") as f:
            f.write('Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
                    'web.addJavascriptInterface(obj, "bridge");\n')
        hits = scan(d)
    ids = {h["title"] for h in hits}
    assert any("ECB" in t for t in ids), ids
    assert any("JavaScript bridge" in t for t in ids), ids
    print(f"OK — {len(rules)} rules, planted-snippet hits={len(hits)}")
