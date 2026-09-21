"""
Forensic Report Generator — produces Section 65B-ready forensic report for one APK.
"""

import os
import datetime
from config import EVIDENCE_DIR


def generate(apk_row, findings, iocs, victims, leads, out_dir: str = None) -> str:
    out_dir = out_dir or os.path.join(EVIDENCE_DIR, apk_row.id[:16])
    os.makedirs(out_dir, exist_ok=True)

    now    = datetime.datetime.now(datetime.timezone.utc)
    ist    = now + datetime.timedelta(hours=5, minutes=30)
    ts_str = ist.strftime("%Y-%m-%d %H:%M IST")

    lines = [
        "=" * 80,
        "TELANGANA CYBER SECURITY BUREAU (TGCSB)",
        "FORENSIC MALWARE ANALYSIS REPORT",
        f"Generated   : {ts_str}",
        f"Report ID   : TGCSB-{ist.strftime('%Y%m%d')}-{apk_row.id[:8].upper()}",
        "Classification: RESTRICTED — LAW ENFORCEMENT ONLY",
        "=" * 80,
        "",
        "SECTION 1 — EXHIBIT IDENTIFICATION",
        "─" * 60,
        f"  Filename       : {apk_row.filename}",
        f"  SHA-256        : {apk_row.id}",
        f"  Package Name   : {apk_row.package_name or 'N/A'}",
        f"  Version        : {apk_row.version_name or 'N/A'} (code {apk_row.version_code or 'N/A'})",
        f"  Min SDK        : {apk_row.min_sdk or 'N/A'}   Target SDK: {apk_row.target_sdk or 'N/A'}",
        f"  Case ID        : {apk_row.case_id or 'Unassigned'}",
        f"  File Path      : {apk_row.file_path}",
        "",
        "SECTION 2 — CERTIFICATE / SIGNING IDENTITY",
        "─" * 60,
        f"  Certificate SHA-256 : {apk_row.cert_sha256 or 'N/A'}",
        f"  Certificate Serial  : {apk_row.cert_serial or 'N/A'}",
        f"  Certificate Subject : {apk_row.cert_subject or 'N/A'}",
        "",
        "SECTION 3 — C2 INFRASTRUCTURE (FIREBASE)",
        "─" * 60,
        f"  Firebase Project ID : {apk_row.firebase_project or 'Not detected'}",
        f"  Firebase API Key    : {apk_row.firebase_api_key or 'Not detected'}",
        f"  Attacker Phone      : {apk_row.attacker_phone or 'Not extracted (run dynamic analysis)'}",
        "",
        "SECTION 4 — RISK ASSESSMENT",
        "─" * 60,
        f"  Risk Score     : {apk_row.risk_score}/100",
        f"  Victims        : {apk_row.victim_count}",
        f"  OTPs Stolen    : {apk_row.otp_count:,}",
        "",
        "SECTION 5 — FINDINGS",
        "─" * 60,
    ]

    crit = [f for f in findings if f.severity == "CRITICAL"]
    high = [f for f in findings if f.severity == "HIGH"]
    rest = [f for f in findings if f.severity not in ("CRITICAL", "HIGH")]

    for severity_group, label in [(crit, "CRITICAL"), (high, "HIGH"), (rest, "OTHER")]:
        if severity_group:
            lines.append(f"\n  [{label}]")
            for f in severity_group:
                lines.append(f"  [{f.severity}] {f.title}")
                lines.append(f"    Category : {f.category}")
                lines.append(f"    Detail   : {f.detail}")
                lines.append(f"    Location : {f.found_at}")
                lines.append("")

    lines += [
        "SECTION 6 — INDICATORS OF COMPROMISE (IoC)",
        "─" * 60,
    ]
    ioc_groups = {}
    for ioc in iocs:
        ioc_groups.setdefault(ioc.ioc_type, []).append(ioc)
    for ioc_type, group in sorted(ioc_groups.items()):
        lines.append(f"\n  {ioc_type}:")
        for ioc in group:
            lines.append(f"    {ioc.value[:80]}")
            if ioc.description:
                lines.append(f"      → {ioc.description}")

    lines += [
        "",
        "SECTION 7 — VICTIM SUMMARY",
        "─" * 60,
        f"  Total victims : {len(victims)}",
        f"  CRITICAL      : {sum(1 for v in victims if v.risk_level == 'CRITICAL')}",
        f"  HIGH          : {sum(1 for v in victims if v.risk_level == 'HIGH')}",
        f"  MEDIUM        : {sum(1 for v in victims if v.risk_level == 'MEDIUM')}",
        f"  LOW           : {sum(1 for v in victims if v.risk_level == 'LOW')}",
        f"  UPI PIN stolen: {sum(1 for v in victims if v.upi_pin_stolen)}",
        f"  Card details  : {sum(1 for v in victims if v.card_stolen)}",
        "",
        "SECTION 8 — CRIMINAL LEADS",
        "─" * 60,
    ]

    for lead in sorted(leads, key=lambda x: x.priority)[:20]:
        lines.append(f"\n  [PRIORITY {lead.priority}] {lead.lead_type}: {lead.value}")
        lines.append(f"  Victims affected : {lead.victim_count}")
        lines.append(f"  Description      : {lead.description[:200]}")
        lines.append(f"  Recommended action: {lead.action[:200]}")

    lines += [
        "",
        "SECTION 9 — SECTION 65B CERTIFICATE",
        "─" * 60,
        "  I, the undersigned, being the Investigating Officer / Authorized",
        "  Technical Expert, hereby certify that:",
        "",
        f"  1. The electronic record described in this report was produced by",
        f"     the TGCSB Malware Analysis System on {ts_str}.",
        f"  2. The electronic record contained in the computer output was",
        f"     produced during the period over which the computer was used",
        f"     regularly to store or process information for the purposes of",
        f"     activities regularly carried on over that period by TGCSB.",
        f"  3. During said period, information of the kind contained in the",
        f"     electronic record was regularly fed into the computer in the",
        f"     ordinary course of activities.",
        f"  4. The computer was operating properly, or if not, any respect",
        f"     in which it was not operating properly or was out of operation",
        f"     during that part of that period was not such as to affect the",
        f"     production of the document or the accuracy of its contents.",
        f"  5. The information contained in the electronic record reproduces",
        f"     or is derived from such information fed into the computer in",
        f"     the ordinary course of activities.",
        "",
        "  Signed : ____________________________",
        "  Name   : ____________________________",
        "  Rank   : ____________________________",
        "  Date   : ____________________________",
        "  Station: Telangana Cyber Security Bureau, Hyderabad",
        "",
        "=" * 80,
        "END OF REPORT",
        "=" * 80,
    ]

    report_text = "\n".join(lines)
    path = os.path.join(out_dir, f"forensic_report_{apk_row.id[:16]}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return path
