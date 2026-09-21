"""
Consolidated regression runner — one command to verify the whole analysis stack.

Runs every module self-check and every regression test as a subprocess, so a
failure in one never masks another, and reports a single pass/fail summary.
Run: python3 -m tests.run_all
"""

import subprocess
import sys

# (label, module) — each is executed as `python3 -m <module>` and must print a
# line starting with "OK" and exit 0.
_TARGETS = [
    ("static: permission_intel", "core.static.permission_intel"),
    ("static: code_scanner",     "core.static.code_scanner"),
    ("static: tracker_detector", "core.static.tracker_detector"),
    ("static: native_scan",      "core.static.native_scan"),
    ("static: sbom",             "core.static.sbom"),
    ("static: decompiler",       "core.static.decompiler"),
    ("intel: similarity",        "core.intelligence.similarity"),
    ("intel: actor_graph",       "core.intelligence.actor_graph"),
    ("intel: mule_network",      "core.intelligence.mule_network"),
    ("intel: risk_score",        "core.intelligence.risk_score"),
    ("intel: enrichment",        "core.intelligence.enrichment"),
    ("report: section65b",       "reporting.section65b"),
    ("report: stix_export",      "reporting.stix_export"),
    ("report: scorecard",        "reporting.scorecard"),
    ("report: timeline",         "reporting.timeline"),
    ("sandbox: dynamic_probe",   "core.sandbox.dynamic_probe"),
    ("test: static_core",        "tests.test_static_core"),
    ("test: behavior",           "tests.test_behavior"),
]


def main():
    passed, failed = 0, []
    for label, module in _TARGETS:
        try:
            r = subprocess.run([sys.executable, "-m", module],
                               capture_output=True, text=True, timeout=300)
            ok = r.returncode == 0 and "OK" in r.stdout
        except subprocess.SubprocessError as e:
            ok, r = False, None
        if ok:
            passed += 1
            print(f"  \033[32mPASS\033[0m  {label}")
        else:
            failed.append(label)
            tail = (r.stderr.strip().splitlines()[-1] if r and r.stderr.strip()
                    else "no OK line") if r else "subprocess error"
            print(f"  \033[31mFAIL\033[0m  {label}  — {tail}")

    print(f"\n{passed}/{len(_TARGETS)} passed"
          + (f", {len(failed)} FAILED: {', '.join(failed)}" if failed else " — all green"))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
