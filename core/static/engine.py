"""
Static Analysis Engine — orchestrates the full static pipeline for one APK.
Saves results to DB and returns a structured result dict.
"""

import os
from rich.console import Console
from rich.panel import Panel

from core.static.context        import AnalysisContext
from core.static.apk_parser      import parse_apk, extract_dex_strings, extract_resource_strings
from core.static.string_miner    import mine
from core.static.firebase_detector import detect as detect_firebase
from core.static.ioc_extractor   import extract as extract_iocs
from core.static.yara_scanner    import scan as yara_scan
from core.static                 import (manifest_audit, permission_intel,
                                         cert_analysis, tracker_detector, code_scanner,
                                         native_scan, sbom, behavior_detector)

console = Console()


def run(apk_path: str, case_id: str = None, db_session=None) -> dict:
    """
    Full static analysis pipeline.
    Returns result dict. Saves to DB if db_session provided.
    """
    console.print(Panel(
        f"[bold]STATIC ANALYSIS[/bold]\n"
        f"File: [yellow]{os.path.basename(apk_path)}[/yellow]",
        border_style="cyan"
    ))

    # ── Parse APK once (shared by every analyzer) ─────────────────────────────
    console.rule("[cyan]APK Metadata & Manifest[/cyan]")
    ctx = AnalysisContext(apk_path)
    apk_meta = parse_apk(ctx.apk_path, ctx.a, ctx.d, ctx.dx)

    # ── Extract all strings ───────────────────────────────────────────────────
    console.rule("[cyan]DEX String Extraction[/cyan]")
    dex_strings      = extract_dex_strings(ctx.apk_path, ctx.d)
    resource_strings = extract_resource_strings(ctx.apk_path)
    console.print(f"  Extracted [green]{len(dex_strings)}[/green] DEX strings, "
                  f"[green]{len(resource_strings)}[/green] resource strings")

    # ── String mining (credentials, phones, URLs) ─────────────────────────────
    console.rule("[cyan]String Mining[/cyan]")
    mined = mine(apk_path, dex_strings, resource_strings)

    # ── Firebase detection ────────────────────────────────────────────────────
    console.rule("[cyan]Firebase C2 Detection[/cyan]")
    firebase = detect_firebase(apk_path, dex_strings + resource_strings)

    # ── Permission intelligence + manifest security audit ─────────────────────
    console.rule("[cyan]Permission & Manifest Audit[/cyan]")
    perm_findings, perm_pts, malware_tags = permission_intel.analyse(apk_meta.get("permissions", []))
    manifest_findings, manifest_pts       = manifest_audit.audit(ctx.a)
    apk_meta["malware_tags"] = malware_tags
    console.print(f"  [green]{len(perm_findings)}[/green] scored permissions, "
                  f"[green]{len(manifest_findings)}[/green] manifest findings, "
                  f"tags: [yellow]{', '.join(malware_tags) or 'none'}[/yellow]")

    # ── Certificate deep analysis + tracker fingerprinting ────────────────────
    console.rule("[cyan]Certificate & Tracker Analysis[/cyan]")
    cert_findings, cert_info = cert_analysis.analyse(ctx.a)
    if cert_info.get("cert_sha256") and not apk_meta.get("cert_sha256"):
        apk_meta["cert_sha256"] = cert_info["cert_sha256"]
    tracker_findings, trackers = tracker_detector.detect(ctx.class_names)
    console.print(f"  Signing: [yellow]{'+'.join(cert_info.get('schemes')) or 'unsigned'}[/yellow], "
                  f"[green]{len(trackers)}[/green] trackers, "
                  f"[green]{len(cert_findings)}[/green] cert findings")

    # ── Decompile (jadx) + insecure-API code scan ─────────────────────────────
    console.rule("[cyan]Code Scan (jadx)[/cyan]")
    code_findings = code_scanner.scan(ctx.source_dir)
    console.print(f"  [green]{len(code_findings)}[/green] insecure-API findings"
                  f"{'' if ctx.source_dir else ' (jadx unavailable — skipped)'}")

    # ── Native library triage + SBOM ──────────────────────────────────────────
    console.rule("[cyan]Native Libraries & SBOM[/cyan]")
    native_findings, native_libs = native_scan.scan(ctx.apk_path)
    sbom_findings, libraries     = sbom.analyse(ctx.class_names, apk_meta.get("package_name"))
    console.print(f"  [green]{len(native_libs)}[/green] native libs "
                  f"({', '.join(sorted({l['arch'] for l in native_libs})) or 'none'}), "
                  f"[green]{len(libraries)}[/green] known libraries")

    # ── Banking-trojan behaviour detection (the moat) ─────────────────────────
    console.rule("[cyan]Behaviour Detection[/cyan]")
    behavior_findings, behavior = behavior_detector.detect(ctx, apk_meta, dex_strings)
    apk_meta["behaviors"] = behavior["behaviors"]
    console.print(f"  Behaviours: [yellow]{', '.join(behavior['behaviors']) or 'none'}[/yellow] | "
                  f"C2: [red]{(behavior['c2_channels'][0]['type'] if behavior['c2_channels'] else 'none')}[/red] | "
                  f"exfil: [red]{behavior['exfil_channel'] or 'none'}[/red]")

    # ── IoC extraction ────────────────────────────────────────────────────────
    console.rule("[cyan]IoC Extraction[/cyan]")
    iocs = extract_iocs(apk_path, apk_meta, mined, firebase)
    console.print(f"  [green]{len(iocs)}[/green] IoCs extracted")

    # ── YARA scan ─────────────────────────────────────────────────────────────
    console.rule("[cyan]YARA Scan[/cyan]")
    yara_hits = yara_scan(apk_path)

    # ── Risk scoring (explainable, auditable breakdown) ───────────────────────
    from core.intelligence.risk_score import compute as compute_risk
    risk_detail = compute_risk(firebase=firebase, yara_hits=yara_hits, perm_pts=perm_pts,
                               manifest_pts=manifest_pts, code_findings=code_findings,
                               behavior=behavior, mined=mined)
    risk = risk_detail["score"]

    # ── Build findings list ───────────────────────────────────────────────────
    findings = _build_findings(apk_meta, firebase, mined, yara_hits) \
             + perm_findings + manifest_findings + cert_findings \
             + tracker_findings + code_findings + native_findings + sbom_findings \
             + behavior_findings

    # ── Save to DB ────────────────────────────────────────────────────────────
    if db_session:
        _save_to_db(db_session, apk_path, apk_meta, firebase, iocs, findings, risk, case_id,
                    behavior=behavior, cert_info=cert_info, risk_detail=risk_detail)

    result = {
        "apk_meta"  : apk_meta,
        "firebase"  : firebase,
        "mined"     : mined,
        "iocs"      : iocs,
        "findings"  : findings,
        "yara_hits" : yara_hits,
        "malware_tags": malware_tags,
        "cert_info" : cert_info,
        "trackers"  : trackers,
        "native_libs": native_libs,
        "libraries" : libraries,
        "behavior"  : behavior,
        "risk_score": risk,
        "risk_detail": risk_detail,
    }

    _print_summary(result)
    return result


def _build_findings(apk_meta, firebase, mined, yara_hits) -> list[dict]:
    findings = []

    def add(category, severity, title, detail, found_at=""):
        findings.append({
            "category": category,
            "severity": severity,
            "title"   : title,
            "detail"  : detail,
            "found_at": found_at,
        })

    # Permissions
    for p in apk_meta.get("dangerous_perms", []):
        add("PERMISSION", "HIGH", f"Dangerous permission: {p.split('.')[-1]}",
            p, "AndroidManifest.xml")

    if "android.permission.RECEIVE_SMS" in apk_meta.get("permissions", []) and \
       "android.permission.REQUEST_INSTALL_PACKAGES" in apk_meta.get("permissions", []):
        add("BEHAVIOUR", "CRITICAL",
            "SMS stealer + dropper capability",
            "App can intercept ALL SMS and silently install additional APKs — "
            "classic banking trojan behaviour",
            "AndroidManifest.xml")

    # Firebase
    if firebase.get("firebase_api_key"):
        add("CREDENTIAL", "CRITICAL",
            "Firebase API key hardcoded",
            f"Project: {firebase.get('firebase_project')}  Key: {firebase.get('firebase_api_key')}",
            "APK strings / google-services.json")

    # YARA
    for hit in yara_hits:
        add("BEHAVIOUR", "CRITICAL",
            f"YARA rule match: {hit['rule']}",
            f"Tags: {hit['tags']}  Meta: {hit['meta']}",
            hit["source_file"])

    # Encryption
    for key in mined.get("aes_key", []):
        add("CREDENTIAL", "HIGH",
            "Hardcoded encryption key",
            f"Key: {key[:60]}",
            "DEX strings")

    # Phones
    for ph in mined.get("phone_in", [])[:5]:
        add("NETWORK", "MEDIUM",
            f"Hardcoded phone number: {ph}",
            "May be attacker contact / OTP forwarding destination",
            "DEX strings")

    return findings


def _save_to_db(session, apk_path, apk_meta, firebase, iocs, findings, risk, case_id,
                behavior=None, cert_info=None, risk_detail=None):
    from db.models import Apk, Finding, IoC

    behavior    = behavior or {}
    cert_info   = cert_info or {}
    risk_detail = risk_detail or {}
    apk_id = apk_meta["sha256"]

    # Intelligence columns (engine v2).
    intel = {
        "malware_tags"  : apk_meta.get("malware_tags"),
        "behaviors"     : behavior.get("behaviors"),
        "c2_channel"    : (behavior.get("c2_channels") or [{}])[0].get("type"),
        "c2_detail"     : behavior.get("c2_channels"),
        "risk_breakdown": risk_detail.get("breakdown"),
        "cert_schemes"  : "+".join(cert_info.get("schemes", [])) or None,
    }

    existing = session.get(Apk, apk_id)
    if not existing:
        session.add(Apk(
            id              = apk_id,
            case_id         = case_id,
            filename        = apk_meta["filename"],
            file_path       = apk_meta["file_path"],
            package_name    = apk_meta["package_name"],
            version_name    = apk_meta["version_name"],
            version_code    = apk_meta["version_code"],
            min_sdk         = apk_meta["min_sdk"],
            target_sdk      = apk_meta["target_sdk"],
            cert_serial     = apk_meta["cert_serial"],
            cert_subject    = apk_meta["cert_subject"],
            cert_sha256     = apk_meta["cert_sha256"],
            firebase_project= firebase.get("firebase_project"),
            firebase_api_key= firebase.get("firebase_api_key"),
            risk_score      = risk,
            static_done     = True,
            **intel,
        ))
    else:
        existing.firebase_project = firebase.get("firebase_project")
        existing.firebase_api_key = firebase.get("firebase_api_key")
        existing.risk_score       = risk
        existing.static_done      = True
        for k, v in intel.items():
            setattr(existing, k, v)
        # Re-analysis: clear prior findings/IoCs so they don't accumulate.
        session.query(Finding).filter_by(apk_id=apk_id).delete()
        session.query(IoC).filter_by(apk_id=apk_id).delete()

    for f in findings:
        session.add(Finding(apk_id=apk_id, **f))
    for ioc in iocs:
        session.add(IoC(apk_id=apk_id, **ioc))

    session.commit()


def _print_summary(result: dict):
    risk = result["risk_score"]
    color = "red" if risk >= 70 else "yellow" if risk >= 40 else "green"
    console.print(Panel(
        f"[bold]STATIC ANALYSIS COMPLETE[/bold]\n\n"
        f"Package     : [cyan]{result['apk_meta'].get('package_name', 'unknown')}[/cyan]\n"
        f"Firebase    : [{'red' if result['firebase'].get('firebase_project') else 'dim'}]"
                       f"{result['firebase'].get('firebase_project', 'not detected')}[/]\n"
        f"Risk Score  : [{color}]{risk}/100[/{color}]\n"
        f"IoCs        : [yellow]{len(result['iocs'])}[/yellow]\n"
        f"Findings    : [yellow]{len(result['findings'])}[/yellow]\n"
        f"YARA Hits   : [{'red' if result['yara_hits'] else 'dim'}]{len(result['yara_hits'])}[/]",
        border_style=color
    ))
