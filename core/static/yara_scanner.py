"""
YARA Scanner — scans the raw APK bytes against all rule files in yara_rules/.
"""

import os
from config import YARA_RULES_DIR
from rich.console import Console

console = Console()


def scan(apk_path: str) -> list[dict]:
    """
    Returns list of YARA match dicts: {rule, tags, meta, strings}.
    Returns empty list if yara-python not installed.
    """
    try:
        import yara
    except ImportError:
        console.print("  [yellow]yara-python not installed — skipping YARA scan.[/yellow]")
        return []

    matches = []
    rule_files = [
        os.path.join(YARA_RULES_DIR, f)
        for f in os.listdir(YARA_RULES_DIR)
        if f.endswith(".yar")
    ]

    if not rule_files:
        return []

    for rule_path in rule_files:
        try:
            rules = yara.compile(filepath=rule_path)
            hits  = rules.match(apk_path)
            for h in hits:
                matches.append({
                    "rule"   : h.rule,
                    "tags"   : list(h.tags),
                    "meta"   : dict(h.meta),
                    "strings": [(s.identifier, s.instances[0].offset if s.instances else 0)
                                for s in h.strings[:10]],
                    "source_file": os.path.basename(rule_path),
                })
                console.print(f"  [bold red]YARA HIT: {h.rule}[/bold red]  [{rule_path}]")
        except Exception as e:
            console.print(f"  [yellow]YARA error in {rule_path}: {e}[/yellow]")

    if not matches:
        console.print("  [dim]No YARA matches.[/dim]")

    return matches
