#!/usr/bin/env python3
"""
TGCSB APK Analyser — Production malware analysis tool
Telangana Cyber Security Bureau

Usage:
  python cli.py analyse  <apk_path>         Full pipeline (static + dynamic)
  python cli.py analyse  <apk_path> --static  Static analysis only
  python cli.py batch    <folder>            Analyse all APKs in folder
  python cli.py report   <apk_sha256>        Generate all reports
  python cli.py victims  <apk_sha256>        Print victim register
  python cli.py leads    <apk_sha256>        Print criminal leads
  python cli.py correlate                    Cross-APK correlation
  python cli.py cases                        List all cases in DB
  python cli.py case     <apk_sha256>        Show case summary
"""

import os
import sys

# Ensure the tool's own directory is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def _init():
    from db.session import init_db
    init_db()


# ─────────────────────────────────────────────────────────────────────────────
@click.group()
def cli():
    """TGCSB APK Analyser — Android malware analysis for law enforcement."""
    _init()


# ─────────────────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--static",  "mode", flag_value="static",  help="Static analysis only (no network)")
@click.option("--dynamic", "mode", flag_value="dynamic", help="Dynamic analysis only")
@click.option("--full",    "mode", flag_value="full", default=True, help="Full pipeline (default)")
@click.option("--case-id",          default=None, help="Associate with a case ID (e.g. TGCSB-2026-001)")
@click.option("--report",           is_flag=True, default=True, help="Auto-generate reports after analysis")
@click.option("--firebase-project", default=None, help="Override Firebase project ID (when auto-detect fails)")
@click.option("--firebase-key",     default=None, help="Override Firebase API key (when auto-detect fails)")
def analyse(apk_path, mode, case_id, report, firebase_project, firebase_key):
    """Analyse a single APK file — static + dynamic + reports."""
    from db.session import get_session
    from core.static.engine  import run as static_run
    from core.dynamic.engine import run as dynamic_run

    session = get_session()

    console.print(Panel(
        f"[bold red]TGCSB APK ANALYSER[/bold red]\n"
        f"File : [yellow]{os.path.basename(apk_path)}[/yellow]\n"
        f"Mode : [cyan]{mode}[/cyan]",
        border_style="red"
    ))

    static_result  = None
    dynamic_result = None

    if mode in ("static", "full"):
        static_result = static_run(apk_path, case_id=case_id, db_session=session)

    if mode in ("dynamic", "full"):
        _firebase_project = firebase_project  # from CLI override
        _firebase_api_key = firebase_key

        if static_result:
            _firebase_project = _firebase_project or static_result["firebase"].get("firebase_project")
            _firebase_api_key = _firebase_api_key or static_result["firebase"].get("firebase_api_key")
            apk_id            = static_result["apk_meta"]["sha256"]
        else:
            from core.static.apk_parser import sha256_file
            apk_id = sha256_file(apk_path)
            from db.models import Apk
            apk_row = session.get(Apk, apk_id)
            if apk_row:
                _firebase_project = _firebase_project or apk_row.firebase_project
                _firebase_api_key = _firebase_api_key or apk_row.firebase_api_key

        # Update DB with override values if supplied
        if (firebase_project or firebase_key) and static_result:
            from db.models import Apk
            apk_row = session.get(Apk, static_result["apk_meta"]["sha256"])
            if apk_row:
                if firebase_project: apk_row.firebase_project = firebase_project
                if firebase_key:     apk_row.firebase_api_key = firebase_key
                session.commit()

        firebase_project = _firebase_project
        firebase_api_key = _firebase_api_key

        if firebase_project and firebase_api_key:
            dynamic_result = dynamic_run(
                firebase_project, firebase_api_key,
                apk_id=static_result["apk_meta"]["sha256"] if static_result else apk_id,
                db_session=session
            )
        else:
            console.print("[yellow]No Firebase credentials found — skipping dynamic analysis.[/yellow]")

    if report and static_result:
        _generate_all_reports(static_result["apk_meta"]["sha256"], session)

    session.close()
    console.print("[bold green]Analysis complete.[/bold green]")


# ─────────────────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("folder", type=click.Path(exists=True, file_okay=False))
@click.option("--case-id", default=None)
@click.option("--workers", default=1, help="Parallel workers (default 1)")
@click.option("--static-only", is_flag=True, default=False)
def batch(folder, case_id, workers, static_only):
    """Analyse all APK files in a folder (batch mode for 150+ APKs)."""
    import glob
    from db.session import get_session
    from core.static.engine  import run as static_run
    from core.dynamic.engine import run as dynamic_run

    apk_files = glob.glob(os.path.join(folder, "**/*.apk"), recursive=True)
    apk_files += glob.glob(os.path.join(folder, "*.apk"))
    apk_files  = list(set(apk_files))

    if not apk_files:
        console.print(f"[yellow]No APK files found in {folder}[/yellow]")
        return

    console.print(Panel(
        f"[bold]BATCH ANALYSIS[/bold]\n"
        f"Folder  : {folder}\n"
        f"APKs    : [red]{len(apk_files)}[/red]\n"
        f"Workers : {workers}",
        border_style="cyan"
    ))

    if workers > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_analyse_one, f, case_id, static_only): f
                for f in apk_files
            }
            done = 0
            for fut in as_completed(futures):
                done += 1
                fname = os.path.basename(futures[fut])
                try:
                    risk = fut.result()
                    console.print(f"  [{done}/{len(apk_files)}] [green]✓[/green] {fname}  risk={risk}")
                except Exception as e:
                    console.print(f"  [{done}/{len(apk_files)}] [red]✗[/red] {fname}: {e}")
    else:
        for i, apk_path in enumerate(apk_files, 1):
            console.print(f"\n[bold cyan]── APK {i}/{len(apk_files)}: {os.path.basename(apk_path)} ──[/bold cyan]")
            try:
                _analyse_one(apk_path, case_id, static_only)
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")

    console.print(f"\n[bold green]Batch complete — {len(apk_files)} APKs processed.[/bold green]")
    console.print("Run [yellow]python cli.py correlate[/yellow] to find shared infrastructure.")


def _analyse_one(apk_path: str, case_id: str, static_only: bool) -> int:
    from db.session import get_session
    from core.static.engine  import run as static_run
    from core.dynamic.engine import run as dynamic_run

    session = get_session()
    try:
        sr = static_run(apk_path, case_id=case_id, db_session=session)
        if not static_only:
            fb  = sr["firebase"]
            if fb.get("firebase_project") and fb.get("firebase_api_key"):
                dynamic_run(
                    fb["firebase_project"], fb["firebase_api_key"],
                    apk_id=sr["apk_meta"]["sha256"],
                    db_session=session
                )
        return sr.get("risk_score", 0)
    finally:
        session.close()


# ─────────────────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("apk_id")
def report(apk_id):
    """Generate all evidence reports for an APK (by SHA-256 prefix or full hash)."""
    from db.session import get_session
    session = get_session()
    _generate_all_reports(apk_id, session)
    session.close()


def _generate_all_reports(apk_id: str, session):
    from db.models import Apk, Finding, IoC, Victim, Lead
    from reporting.forensic_report import generate as gen_forensic
    from reporting.victim_register import generate as gen_victims
    from reporting.leads_report    import generate as gen_leads

    # Support prefix match
    if len(apk_id) < 64:
        apk_row = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
    else:
        apk_row = session.get(Apk, apk_id)

    if not apk_row:
        console.print(f"[red]APK not found in DB: {apk_id}[/red]")
        return

    findings = session.query(Finding).filter_by(apk_id=apk_row.id).all()
    iocs     = session.query(IoC    ).filter_by(apk_id=apk_row.id).all()
    victims  = session.query(Victim ).filter_by(apk_id=apk_row.id).all()
    leads    = session.query(Lead   ).filter_by(apk_id=apk_row.id).all()

    from config import EVIDENCE_DIR
    out_dir = os.path.join(EVIDENCE_DIR, apk_row.id[:16])

    console.print(f"\n[bold cyan]Generating reports → {out_dir}[/bold cyan]")

    p1 = gen_forensic(apk_row, findings, iocs, victims, leads, out_dir)
    console.print(f"  [green]✓[/green] Forensic report    : {p1}")

    if victims:
        p2, p3 = gen_victims(victims, apk_row.id, out_dir)
        console.print(f"  [green]✓[/green] Victim register TXT: {p2}")
        console.print(f"  [green]✓[/green] Victim register CSV: {p3}")

    if leads:
        p4 = gen_leads(apk_row, leads, victims, out_dir)
        console.print(f"  [green]✓[/green] Criminal leads     : {p4}")


# ─────────────────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("apk_id")
def victims(apk_id):
    """Print victim summary table for an APK."""
    from db.session import get_session
    from db.models  import Apk, Victim
    session = get_session()

    if len(apk_id) < 64:
        apk_row = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
    else:
        apk_row = session.get(Apk, apk_id)

    if not apk_row:
        console.print(f"[red]Not found: {apk_id}[/red]")
        return

    victim_rows = session.query(Victim).filter_by(apk_id=apk_row.id).order_by(Victim.risk_level).all()

    t = Table(title=f"Victims — {apk_row.filename}", show_lines=True)
    t.add_column("Risk",   style="red",    width=10)
    t.add_column("Name",   style="white",  width=22)
    t.add_column("Mobile", style="cyan",   width=14)
    t.add_column("OTPs",   style="yellow", width=6)
    t.add_column("UPI",    style="red",    width=5)
    t.add_column("Card",   style="red",    width=5)
    t.add_column("Device", style="dim",    width=20)

    for v in victim_rows:
        t.add_row(
            v.risk_level,
            v.full_name or "?",
            v.mobile or "?",
            str(v.otp_count),
            "YES" if v.upi_pin_stolen else "",
            "YES" if v.card_stolen    else "",
            f"{v.manufacturer or ''} {v.device or ''}".strip()[:20],
        )

    console.print(t)
    console.print(f"Total: {len(victim_rows)} victims")
    session.close()


# ─────────────────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("apk_id")
def leads(apk_id):
    """Print criminal leads for an APK."""
    from db.session import get_session
    from db.models  import Apk, Lead
    session = get_session()

    if len(apk_id) < 64:
        apk_row = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
    else:
        apk_row = session.get(Apk, apk_id)

    if not apk_row:
        console.print(f"[red]Not found: {apk_id}[/red]")
        return

    lead_rows = session.query(Lead).filter_by(apk_id=apk_row.id).order_by(Lead.priority, Lead.victim_count.desc()).all()

    t = Table(title=f"Criminal Leads — {apk_row.filename}", show_lines=True)
    t.add_column("P",       style="red",    width=3)
    t.add_column("Type",    style="yellow", width=14)
    t.add_column("Value",   style="white",  width=40)
    t.add_column("Victims", style="cyan",   width=8)
    t.add_column("Action",  style="dim",    width=40)

    for l in lead_rows:
        t.add_row(
            str(l.priority),
            l.lead_type,
            l.value[:40],
            str(l.victim_count),
            (l.action or "")[:40],
        )

    console.print(t)
    session.close()


# ─────────────────────────────────────────────────────────────────────────────
@cli.command()
def correlate():
    """Find APKs sharing Firebase project, certificate, or attacker phone."""
    from db.session import get_session
    from core.intelligence.cross_apk import correlate as _correlate
    session = get_session()
    _correlate(session)
    session.close()


# ─────────────────────────────────────────────────────────────────────────────
@cli.command()
def cases():
    """List all APKs in the database."""
    from db.session import get_session
    from db.models  import Apk
    session = get_session()

    apks = session.query(Apk).order_by(Apk.analysed_at.desc()).all()
    if not apks:
        console.print("[dim]No APKs in database yet.[/dim]")
        return

    t = Table(title="All Cases", show_lines=True)
    t.add_column("SHA256 (prefix)", style="dim",    width=18)
    t.add_column("Filename",        style="white",  width=30)
    t.add_column("Package",         style="cyan",   width=28)
    t.add_column("Firebase",        style="yellow", width=20)
    t.add_column("Risk",            style="red",    width=6)
    t.add_column("Victims",         style="red",    width=8)
    t.add_column("OTPs",            style="yellow", width=8)
    t.add_column("Analysed",        style="dim",    width=12)

    for a in apks:
        risk_color = "red" if a.risk_score >= 70 else "yellow" if a.risk_score >= 40 else "green"
        t.add_row(
            a.id[:16] + "...",
            a.filename[:30],
            (a.package_name or "?")[:28],
            (a.firebase_project or "")[:20],
            f"[{risk_color}]{a.risk_score}[/{risk_color}]",
            str(a.victim_count or 0),
            f"{a.otp_count or 0:,}",
            str(a.analysed_at)[:10] if a.analysed_at else "",
        )

    console.print(t)
    console.print(f"\nTotal: {len(apks)} APKs in database")
    session.close()


# ─────────────────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("apk_id")
def case(apk_id):
    """Show detailed case summary for one APK."""
    from db.session import get_session
    from db.models  import Apk, Finding, IoC, Victim, Lead
    session = get_session()

    if len(apk_id) < 64:
        apk_row = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
    else:
        apk_row = session.get(Apk, apk_id)

    if not apk_row:
        console.print(f"[red]Not found: {apk_id}[/red]")
        return

    n_findings = session.query(Finding).filter_by(apk_id=apk_row.id).count()
    n_iocs     = session.query(IoC    ).filter_by(apk_id=apk_row.id).count()
    n_victims  = session.query(Victim ).filter_by(apk_id=apk_row.id).count()
    n_leads    = session.query(Lead   ).filter_by(apk_id=apk_row.id).count()

    risk_color = "red" if apk_row.risk_score >= 70 else "yellow" if apk_row.risk_score >= 40 else "green"

    console.print(Panel(
        f"[bold]CASE SUMMARY[/bold]\n\n"
        f"File        : [yellow]{apk_row.filename}[/yellow]\n"
        f"SHA-256     : {apk_row.id}\n"
        f"Package     : [cyan]{apk_row.package_name or 'N/A'}[/cyan]\n"
        f"Version     : {apk_row.version_name or 'N/A'}\n"
        f"Firebase    : [red]{apk_row.firebase_project or 'Not detected'}[/red]\n"
        f"API Key     : {apk_row.firebase_api_key or 'N/A'}\n"
        f"Attacker    : [bold red]{apk_row.attacker_phone or 'Not extracted'}[/bold red]\n"
        f"Risk Score  : [{risk_color}]{apk_row.risk_score}/100[/{risk_color}]\n"
        f"Cert serial : {apk_row.cert_serial or 'N/A'}\n\n"
        f"Victims     : [red]{n_victims}[/red]    OTPs: [red]{apk_row.otp_count or 0:,}[/red]\n"
        f"Findings    : [yellow]{n_findings}[/yellow]    IoCs: [yellow]{n_iocs}[/yellow]    "
        f"Leads: [yellow]{n_leads}[/yellow]\n\n"
        f"Static done : {'[green]YES[/green]' if apk_row.static_done else '[red]NO[/red]'}\n"
        f"Dynamic done: {'[green]YES[/green]' if apk_row.dynamic_done else '[red]NO[/red]'}",
        border_style=risk_color,
        title=f"[bold]{apk_row.filename}[/bold]"
    ))

    session.close()


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    cli()
