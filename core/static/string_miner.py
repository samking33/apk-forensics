"""
String Miner — scans all DEX strings and resource files for hardcoded credentials,
URLs, phone numbers, and any attacker-controlled values.
"""

import re
from config import PATTERNS
from rich.console import Console

console = Console()


def mine(apk_path: str, dex_strings: list[str], resource_strings: list[str]) -> dict:
    """
    Run all regex patterns against every string extracted from the APK.
    Returns categorised hit lists.
    """
    all_text = "\n".join(dex_strings + resource_strings)

    results = {k: [] for k in PATTERNS}
    results["raw_strings"] = dex_strings[:500]  # first 500 for manual review

    for pattern_name, regex in PATTERNS.items():
        seen = set()
        for m in re.finditer(regex, all_text):
            val = m.group(0).strip()
            if val not in seen:
                seen.add(val)
                results[pattern_name].append(val)

    # Deduplicate and clean
    for k in results:
        if isinstance(results[k], list) and k != "raw_strings":
            results[k] = sorted(set(results[k]))

    _log_summary(results)
    return results


def _log_summary(results: dict):
    for key, vals in results.items():
        if key == "raw_strings" or not vals:
            continue
        sev = "[bold red]" if key in ("firebase_api_key", "phone_in", "aes_key") else "[yellow]"
        console.print(f"  {sev}[{key}][/] found {len(vals)} match(es)")
        for v in vals[:3]:
            console.print(f"    → {v[:100]}")
        if len(vals) > 3:
            console.print(f"    ... and {len(vals)-3} more")
