"""
Criminal Leads Report Generator — produces ranked actionable intelligence report.
"""

import os
import datetime
from config import EVIDENCE_DIR


def generate(apk_row, leads, victims, out_dir: str = None) -> str:
    out_dir = out_dir or os.path.join(EVIDENCE_DIR, apk_row.id[:16])
    os.makedirs(out_dir, exist_ok=True)

    now = (datetime.datetime.now(datetime.timezone.utc)
           + datetime.timedelta(hours=5, minutes=30))

    lines = [
        "=" * 80,
        "TELANGANA CYBER SECURITY BUREAU (TGCSB)",
        "CRIMINAL INTELLIGENCE REPORT — ACTIONABLE LEADS",
        f"Case APK    : {apk_row.id}",
        f"Firebase    : {apk_row.firebase_project or 'N/A'}",
        f"Generated   : {now.strftime('%Y-%m-%d %H:%M IST')}",
        "Classification: RESTRICTED — LAW ENFORCEMENT ONLY",
        "=" * 80,
        "",
        f"Attacker phone : {apk_row.attacker_phone or 'See historical Firebase records'}",
        f"Victims        : {apk_row.victim_count}",
        f"OTPs stolen    : {apk_row.otp_count:,}",
        "",
    ]

    tier_labels = {1: "TIER 1 — IMMEDIATE ACTION (FILE TODAY)", 2: "TIER 2 — HIGH PRIORITY", 3: "TIER 3 — INTELLIGENCE"}
    sorted_leads = sorted(leads, key=lambda x: (x.priority, -x.victim_count))

    current_tier = None
    for lead in sorted_leads:
        if lead.priority != current_tier:
            current_tier = lead.priority
            lines += ["", "━" * 80, tier_labels.get(current_tier, f"TIER {current_tier}"), "━" * 80, ""]

        lines += [
            f"  TYPE     : {lead.lead_type}",
            f"  VALUE    : {lead.value}",
            f"  VICTIMS  : {lead.victim_count}",
            f"  DETAILS  : {lead.description}",
            f"  ACTION   : {lead.action}",
            "",
        ]

    lines += [
        "=" * 80,
        "IMMEDIATE CHECKLIST FOR FIELD COMMANDER",
        "=" * 80,
        "",
    ]

    # Auto-generate checklist from P1 leads
    p1 = [l for l in leads if l.priority == 1]
    for i, lead in enumerate(p1[:10], 1):
        lines.append(f"  □ {i}. [{lead.lead_type}] {lead.value[:60]}")
        lines.append(f"       Action: {lead.action[:120]}")
        lines.append("")

    lines += [
        "",
        "GOOGLE / FIREBASE LEGAL PROCESS",
        "─" * 60,
        f"  Firebase Project  : {apk_row.firebase_project or 'N/A'}",
        f"  Target            : Google India Pvt Ltd / Google LLC",
        "  Request           : Account email, phone, billing, IP logs for Firebase Console",
        "  Critical: Include request for HISTORICAL values of Firestore admin/number field",
        "  File via: CERT-In cert-in.org.in OR I4C / MHA OR CrPC Section 91 BNSS",
        "",
        "=" * 80,
        "END OF CRIMINAL LEADS REPORT",
        "=" * 80,
    ]

    report_text = "\n".join(lines)
    path = os.path.join(out_dir, "CRIMINAL_LEADS_REPORT.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(report_text)
    return path
