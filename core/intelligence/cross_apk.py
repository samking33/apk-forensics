"""
Cross-APK Correlation — finds APKs in the DB that share infrastructure,
certificates, or attacker phone numbers. Links serial criminal campaigns.
"""

import collections
from rich.console import Console
from rich.table import Table

console = Console()


def correlate(db_session) -> list[dict]:
    """
    Analyse all APKs in DB and return correlation groups.
    Same Firebase project OR same cert OR same attacker phone = same criminal.
    """
    from db.models import Apk
    apks = db_session.query(Apk).all()

    if len(apks) < 2:
        console.print("[dim]Need at least 2 APKs in DB for correlation.[/dim]")
        return []

    groups = []

    # Group by Firebase project
    groups += _group_by(apks, "firebase_project", "FIREBASE_PROJECT",
                        "Same Firebase project = same C2 infrastructure = same criminal")

    # Group by certificate SHA256
    groups += _group_by(apks, "cert_sha256", "CERTIFICATE",
                        "Same signing certificate = same developer / build environment")

    # Group by attacker phone
    groups += _group_by(apks, "attacker_phone", "ATTACKER_PHONE",
                        "Same OTP forwarding phone = same criminal operation")

    # Group by package name prefix (e.g. com.app.*)
    pkg_groups = collections.defaultdict(list)
    for apk in apks:
        if apk.package_name:
            prefix = ".".join(apk.package_name.split(".")[:2])
            pkg_groups[prefix].append(apk)
    for prefix, group in pkg_groups.items():
        if len(group) >= 2:
            groups.append({
                "correlation_type": "PACKAGE_PREFIX",
                "shared_value"    : prefix,
                "apk_count"       : len(group),
                "apk_ids"         : [a.id for a in group],
                "filenames"       : [a.filename for a in group],
                "description"     : f"Same package prefix '{prefix}' — same author namespace",
            })

    _print_results(groups)
    return groups


def _group_by(apks, field: str, label: str, description: str) -> list[dict]:
    buckets = collections.defaultdict(list)
    for apk in apks:
        val = getattr(apk, field, None)
        if val:
            buckets[val].append(apk)

    results = []
    for val, group in buckets.items():
        if len(group) >= 2:
            results.append({
                "correlation_type": label,
                "shared_value"    : val,
                "apk_count"       : len(group),
                "apk_ids"         : [a.id[:16] + "..." for a in group],
                "filenames"       : [a.filename for a in group],
                "description"     : description,
            })
    return results


def _print_results(groups: list[dict]):
    if not groups:
        console.print("[dim]No correlations found across APKs.[/dim]")
        return

    console.print(f"\n[bold red]{len(groups)} correlation group(s) found:[/bold red]\n")

    t = Table(title="Cross-APK Correlations", show_lines=True)
    t.add_column("Type",          style="red")
    t.add_column("Shared Value",  style="yellow", max_width=40)
    t.add_column("APK Count",     style="cyan")
    t.add_column("Files",         style="white", max_width=50)
    t.add_column("Significance",  style="dim",   max_width=40)

    for g in sorted(groups, key=lambda x: -x["apk_count"]):
        t.add_row(
            g["correlation_type"],
            g["shared_value"][:40],
            str(g["apk_count"]),
            "\n".join(g["filenames"][:5]),
            g["description"][:40],
        )

    console.print(t)
