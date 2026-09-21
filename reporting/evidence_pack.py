"""
Evidence Pack — Multi-Agency Encrypted ZIP Export
Bundles all case evidence into a single password-protected ZIP with:
  - Chain-of-custody manifest (JSON + human-readable)
  - All forensic reports
  - Raw Firebase JSON dumps
  - Victim register (TXT + CSV)
  - Criminal leads report
  - Financial quantum report
  - Money flow graph (PNG)
  - Geo map (HTML)
  - SHA-256 hash manifest of every file included

Uses pyzipper for AES-256 encrypted ZIP.
Falls back to standard zipfile with a warning if pyzipper unavailable.
"""

import os
import io
import json
import hashlib
import zipfile
import sys
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.static.apk_parser import sha256_file as _sha256_file

try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate(apk_id: str, db_session, out_dir: str,
             password: Optional[str] = None,
             sharing_agency: str = "TGCSB",
             officer_name: str = "") -> dict:
    """
    Generate a complete evidence pack ZIP for the given APK.

    Returns dict with:
      zip_path    — path to the encrypted ZIP
      password    — password used (auto-generated if not supplied)
      file_count  — number of files bundled
      total_bytes — uncompressed size
      manifest    — dict summary of included files
    """
    from db.models import Apk, Finding, IoC, Victim, Lead, Transaction

    os.makedirs(out_dir, exist_ok=True)

    apk      = db_session.get(Apk, apk_id)
    findings = db_session.query(Finding    ).filter_by(apk_id=apk_id).all()
    iocs     = db_session.query(IoC        ).filter_by(apk_id=apk_id).all()
    victims  = db_session.query(Victim     ).filter_by(apk_id=apk_id).all()
    leads    = db_session.query(Lead       ).filter_by(apk_id=apk_id).all()
    txns     = db_session.query(Transaction).filter_by(apk_id=apk_id).all()

    if not apk:
        raise ValueError(f"APK {apk_id} not found in database")

    # Auto-generate password if not supplied
    if not password:
        import secrets
        password = "TGCSB-" + secrets.token_hex(8).upper()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    zip_name  = f"EVIDENCE_PACK_{apk_id[:16]}_{timestamp}.zip"
    zip_path  = os.path.join(out_dir, zip_name)

    # Build file list from evidence_output directory
    evidence_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "evidence_output",
        apk_id[:16],
    )

    collected_files: list[dict] = []  # {arc_name, src_path, sha256, size}

    def _add_file(src_path: str, arc_name: str):
        if os.path.exists(src_path):
            sha = _sha256_file(src_path)
            sz  = os.path.getsize(src_path)
            collected_files.append({
                "arc_name": arc_name,
                "src_path": src_path,
                "sha256"  : sha,
                "size"    : sz,
            })

    # ── Collect all evidence files ─────────────────────────────────────────
    for fname in [
        "FORENSIC_REPORT.txt",
        "VICTIM_NOTIFICATION_REGISTER.txt",
        "VICTIM_NOTIFICATION_LIST.csv",
        "CRIMINAL_LEADS_REPORT.txt",
        "FINANCIAL_QUANTUM_REPORT.txt",
        "MONEY_FLOW_SUMMARY.txt",
        "MONEY_FLOW_GRAPH.png",
        "GEO_VICTIM_MAP.html",
    ]:
        _add_file(os.path.join(evidence_dir, fname), f"reports/{fname}")

    # Raw Firebase dumps
    for fname in [
        "full_victim_dump.json",
        "attacker_phone.json",
        "victims_page_1.json",
        "victims_page_2.json",
    ]:
        _add_file(os.path.join(evidence_dir, fname), f"raw_evidence/{fname}")

    # ── Generate in-memory documents ──────────────────────────────────────
    # DB export as JSON
    db_export = _build_db_export(apk, findings, iocs, victims, leads, txns)
    db_export_bytes = json.dumps(db_export, indent=2, default=str).encode("utf-8")

    # Chain of custody manifest
    coc = _build_chain_of_custody(
        apk, collected_files, db_export_bytes,
        sharing_agency, officer_name, password
    )
    coc_txt_bytes  = _render_coc_text(coc).encode("utf-8")
    coc_json_bytes = json.dumps(coc, indent=2, default=str).encode("utf-8")

    # Hash manifest
    hash_manifest = _build_hash_manifest(collected_files, db_export_bytes,
                                          coc_txt_bytes, coc_json_bytes)
    hash_manifest_bytes = hash_manifest.encode("utf-8")

    total_bytes = sum(f["size"] for f in collected_files)
    total_bytes += len(db_export_bytes) + len(coc_txt_bytes) + len(coc_json_bytes) + len(hash_manifest_bytes)

    # ── Write ZIP ──────────────────────────────────────────────────────────
    pwd_bytes = password.encode("utf-8")

    if HAS_PYZIPPER:
        zf_cls = pyzipper.AESZipFile
        zf_kwargs = dict(mode="w", compression=pyzipper.ZIP_DEFLATED,
                         encryption=pyzipper.WZ_AES)
    else:
        zf_cls   = zipfile.ZipFile
        zf_kwargs = dict(mode="w", compression=zipfile.ZIP_DEFLATED)

    with zf_cls(zip_path, **zf_kwargs) as zf:
        if HAS_PYZIPPER:
            zf.setpassword(pwd_bytes)

        # Evidence files
        for item in collected_files:
            zf.write(item["src_path"], arcname=item["arc_name"])

        # In-memory files
        zf.writestr("database_export.json",     db_export_bytes)
        zf.writestr("CHAIN_OF_CUSTODY.txt",     coc_txt_bytes)
        zf.writestr("chain_of_custody.json",    coc_json_bytes)
        zf.writestr("SHA256_HASH_MANIFEST.txt", hash_manifest_bytes)

    return {
        "zip_path"    : zip_path,
        "password"    : password,
        "encrypted"   : HAS_PYZIPPER,
        "file_count"  : len(collected_files) + 4,
        "total_bytes" : total_bytes,
        "zip_size"    : os.path.getsize(zip_path),
        "manifest"    : coc,
    }


def _build_db_export(apk, findings, iocs, victims, leads, txns) -> dict:
    def victim_dict(v):
        return {
            "firebase_uid" : v.firebase_uid,
            "full_name"    : v.full_name,
            "mobile"       : v.mobile,
            "bank_name"    : v.bank_name,
            "risk_level"   : v.risk_level,
            "otp_count"    : v.otp_count,
            "upi_pin"      : v.upi_pin,
            "card_last4"   : v.card_last4,
            "total_debited": v.total_debited,
            "state"        : v.state,
            "infected_at"  : str(v.infected_at),
        }

    return {
        "apk": {
            "id"             : apk.id,
            "filename"       : apk.filename,
            "package_name"   : apk.package_name,
            "firebase_project": apk.firebase_project,
            "risk_score"     : apk.risk_score,
            "victim_count"   : apk.victim_count,
            "otp_count"      : apk.otp_count,
            "total_loss_inr" : apk.total_loss_inr,
            "attacker_phone" : apk.attacker_phone,
        },
        "findings"    : [{"severity": f.severity, "title": f.title, "detail": f.detail} for f in findings],
        "iocs"        : [{"type": i.ioc_type, "value": i.value} for i in iocs],
        "victims"     : [victim_dict(v) for v in victims],
        "leads"       : [{"priority": l.priority, "type": l.lead_type, "value": l.value,
                          "victim_count": l.victim_count, "action": l.action} for l in leads],
        "transactions": [{"amount": t.amount, "bank": t.bank_name, "upi_id": t.upi_id,
                          "date": str(t.txn_date)} for t in txns],
    }


def _build_chain_of_custody(apk, files, db_bytes, agency, officer, password) -> dict:
    return {
        "case_reference"    : f"TGCSB-{apk.case_id or 'N/A'}",
        "apk_sha256"        : apk.id,
        "firebase_project"  : apk.firebase_project,
        "package_name"      : apk.package_name,
        "generated_at"      : datetime.now(timezone.utc).isoformat(),
        "generated_by"      : officer or "TGCSB Investigation Team",
        "sharing_agency"    : agency,
        "classification"    : "RESTRICTED — LAW ENFORCEMENT USE ONLY",
        "encryption"        : "AES-256" if HAS_PYZIPPER else "NONE (install pyzipper)",
        "password_note"     : "Password shared via secure channel. Do NOT include in email.",
        "file_count"        : len(files) + 4,
        "total_victims"     : apk.victim_count,
        "total_loss_inr"    : apk.total_loss_inr,
        "files_included"    : [
            {"arc_name": f["arc_name"], "sha256": f["sha256"], "size_bytes": f["size"]}
            for f in files
        ],
        "db_export_sha256"  : _sha256_bytes(db_bytes),
        "legal_basis"       : [
            "Information Technology Act, 2000 — Sec 43, 66",
            "Bharatiya Nagarik Suraksha Sanhita, 2023 — Sec 91/94",
            "Indian Evidence Act — Sec 65B (Electronic Records)",
            "Prevention of Money Laundering Act — PMLA",
        ],
    }


def _render_coc_text(coc: dict) -> str:
    lines = [
        "=" * 72,
        "  CHAIN OF CUSTODY — EVIDENCE PACKAGE",
        "  Telangana Cyber Security Bureau",
        "=" * 72, "",
        f"  Case Reference   : {coc['case_reference']}",
        f"  APK SHA-256      : {coc['apk_sha256']}",
        f"  Firebase Project : {coc['firebase_project']}",
        f"  Package Name     : {coc['package_name']}",
        f"  Generated At     : {coc['generated_at']}",
        f"  Generated By     : {coc['generated_by']}",
        f"  Sharing With     : {coc['sharing_agency']}",
        f"  Classification   : {coc['classification']}",
        f"  Encryption       : {coc['encryption']}",
        "",
        "  CASE SUMMARY",
        f"  Total Victims    : {coc['total_victims']}",
        f"  Financial Loss   : Rs. {coc.get('total_loss_inr', 0):,.2f}",
        "",
        "  FILES INCLUDED",
        "  " + "-" * 68,
    ]
    for f in coc["files_included"]:
        lines.append(f"  {f['arc_name']:<45} {f['sha256'][:16]}... {f['size_bytes']:>8} B")

    lines += [
        "",
        "  LEGAL BASIS",
    ]
    for l in coc["legal_basis"]:
        lines.append(f"    • {l}")

    lines += [
        "",
        "  CHAIN OF CUSTODY CERTIFICATION",
        "  ─────────────────────────────────────────────────",
        "  I certify that this evidence package was generated by",
        "  TGCSB investigation systems and the contents are a true",
        "  and accurate copy of the digital evidence collected.",
        "",
        "  Examiner Name    : _________________________________",
        "  Badge Number     : _________________________________",
        "  Designation      : _________________________________",
        "  Date & Time      : _________________________________",
        "  Signature        : _________________________________",
        "",
        "=" * 72,
    ]
    return "\n".join(lines)


def _build_hash_manifest(files, *extra_bytes_list) -> str:
    lines = [
        "SHA-256 HASH MANIFEST",
        "Generated: " + datetime.now(timezone.utc).isoformat(),
        "=" * 72, "",
    ]
    for f in files:
        lines.append(f"{f['sha256']}  {f['arc_name']}")
    extra_names = ["database_export.json", "CHAIN_OF_CUSTODY.txt",
                   "chain_of_custody.json"]
    for name, data in zip(extra_names, extra_bytes_list):
        lines.append(f"{_sha256_bytes(data)}  {name}")
    lines += ["", "Verify with: sha256sum -c SHA256_HASH_MANIFEST.txt"]
    return "\n".join(lines)
