"""
Dynamic Analysis Engine — orchestrates Firebase probe + victim processing + leads.
"""

import os
from rich.console import Console
from rich.panel import Panel
from config import EVIDENCE_DIR

from core.dynamic.firebase_probe   import run as firebase_run
from core.dynamic.rtdb_probe       import run as rtdb_run
from core.dynamic.victim_processor import process as process_victims
from core.dynamic.criminal_leads   import generate as generate_leads

console = Console()


def run(firebase_project: str, firebase_api_key: str,
        apk_id: str = None, db_session=None, progress=None) -> dict:

    if not firebase_project or not firebase_api_key:
        console.print("[yellow]No Firebase credentials — skipping dynamic analysis.[/yellow]")
        return {"skipped": True}

    out_dir = os.path.join(EVIDENCE_DIR, firebase_project)
    os.makedirs(out_dir, exist_ok=True)

    # Step 1: Probe Firebase backend. Firestore first (majority of samples);
    # if empty, the C2 may be built on Realtime Database instead — same
    # credentials, different API — so fall back automatically rather than
    # requiring the analyst to know which backend a given trojan uses.
    probe = firebase_run(firebase_project, firebase_api_key, apk_id, out_dir, progress=progress)
    victims_raw = probe.get("victims", [])

    if not victims_raw:
        console.print("[yellow]No victims via Firestore — trying Realtime Database…[/yellow]")
        rtdb_result = rtdb_run(firebase_project, firebase_api_key, apk_id, out_dir, progress=progress)
        if rtdb_result.get("victims"):
            probe = rtdb_result
            victims_raw = probe["victims"]
        else:
            probe["errors"] = probe.get("errors", []) + rtdb_result.get("errors", [])

    if not victims_raw:
        console.print("[yellow]No victim data retrieved from Firebase (Firestore or RTDB).[/yellow]")
        return probe

    # Step 2: Process and classify victims
    console.rule("[red]Processing victim data[/red]")
    victims_processed = process_victims(victims_raw, apk_id, db_session)

    # Step 3: Generate criminal leads
    console.rule("[red]Generating criminal leads[/red]")
    leads = generate_leads(victims_raw, apk_id, db_session)

    # Step 4: Update APK row in DB
    if db_session and apk_id:
        from db.models import Apk
        apk_row = db_session.get(Apk, apk_id)
        if apk_row:
            apk_row.attacker_phone = probe.get("attacker_phone")
            apk_row.victim_count   = len(victims_raw)
            apk_row.otp_count      = probe.get("otp_count", 0)
            apk_row.dynamic_done   = True
            db_session.commit()

    return {
        **probe,
        "victims_processed": victims_processed,
        "leads"            : leads,
    }
