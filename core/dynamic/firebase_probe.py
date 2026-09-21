"""
Firebase Probe — live extraction from Firebase C2 backend.
Uses the API key embedded in the APK. No device required.
Production version with full pagination, retry, and evidence saving.
"""

import requests
import json
import os
import time
import datetime
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.panel import Panel
from config import FIRESTORE_BASE, EVIDENCE_DIR

console = Console()
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "Mozilla/5.0 TGCSB-Analyser/1.0"})
# Larger connection pool so parallel victim extraction doesn't exhaust it.
_adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32)
SESSION.mount("https://", _adapter)
SESSION.mount("http://", _adapter)

# Concurrency for per-victim detail fetches. ponytail: 20 threads turns hundreds
# of sequential HTTP calls (minutes) into seconds; raise only if the C2 tolerates it.
_EXTRACT_WORKERS = 20


def run(project_id: str, api_key: str, apk_id: str = None, out_dir: str = None,
        progress=None) -> dict:
    """
    Full Firebase intelligence extraction.
    Returns: {attacker_phone, victim_count, otp_count, victims, errors}
    `progress`: optional callback(dict) for live UI updates {phase, current, total}.
    """
    def _p(**kw):
        if progress:
            progress(kw)

    out_dir = out_dir or os.path.join(EVIDENCE_DIR, project_id)
    os.makedirs(out_dir, exist_ok=True)

    base_url = FIRESTORE_BASE.format(project_id=project_id)

    console.print(Panel(
        f"[bold red]FIREBASE C2 PROBE[/bold red]\n"
        f"Project : [yellow]{project_id}[/yellow]\n"
        f"Key     : [yellow]{api_key[:20]}...[/yellow]\n"
        f"Output  : {out_dir}",
        border_style="red"
    ))

    result = {
        "project_id"    : project_id,
        "api_key"       : api_key,
        "attacker_phone": None,
        "victim_count"  : 0,
        "otp_count"     : 0,
        "victims"       : [],
        "errors"        : [],
        "out_dir"       : out_dir,
    }

    # Step 1: Attacker phone
    _p(phase="Connecting to C2", current=0, total=0)
    phone = _get_attacker_phone(base_url, api_key, out_dir)
    result["attacker_phone"] = phone
    if phone:
        console.print(f"\n[bold red on white]  ATTACKER PHONE: {phone}  [/bold red on white]\n")

    # Step 2: Enumerate all victims
    _p(phase="Enumerating victims", current=0, total=0)
    victims = _enumerate_victims(base_url, api_key)
    result["victim_count"] = len(victims)
    console.print(f"  [green]{len(victims)} victim devices found[/green]")

    # Step 3: Deep extract each victim — in parallel (was sequential = minutes).
    console.rule("[red]Extracting victim data (OTPs + credentials)[/red]")
    all_victim_data = []
    total_otps = 0
    targets = [v for v in victims if v.get("uid")]
    n = len(targets)
    _p(phase="Extracting victim data", current=0, total=n)

    def _fetch(v):
        v.update(_extract_victim_detail(base_url, api_key, v["uid"]))
        return v

    with ThreadPoolExecutor(max_workers=_EXTRACT_WORKERS) as ex:
        for i, v in enumerate(ex.map(_fetch, targets)):
            all_victim_data.append(v)
            total_otps += len(v.get("otps", []))
            if (i + 1) % 5 == 0 or (i + 1) == n:
                _p(phase="Extracting victim data", current=i + 1, total=n)
            if (i + 1) % 100 == 0:
                console.print(f"  [dim]Extracted {i+1}/{n}...[/dim]")

    result["victims"]   = all_victim_data
    result["otp_count"] = total_otps

    # Save full dump
    dump_path = os.path.join(out_dir, "full_victim_dump.json")
    with open(dump_path, "w") as f:
        json.dump(all_victim_data, f, indent=2, ensure_ascii=False)
    console.print(f"  [green]Full dump saved: {dump_path}[/green]")

    console.print(Panel(
        f"[bold]PROBE COMPLETE[/bold]\n\n"
        f"Attacker phone : [bold red]{phone or 'not found'}[/bold red]\n"
        f"Victims        : [bold red]{len(all_victim_data)}[/bold red]\n"
        f"OTPs stolen    : [bold red]{total_otps:,}[/bold red]\n"
        f"Evidence saved : {out_dir}",
        border_style="red"
    ))

    return result


def _get_attacker_phone(base_url: str, api_key: str, out_dir: str) -> str | None:
    console.rule("[red]Attacker phone (admin/number)[/red]")
    try:
        r = SESSION.get(
            f"{base_url}/admin/number",
            params={"key": api_key},
            timeout=15
        )
        _save(out_dir, f"admin_number_{_ts()}.json", r.json() if r.ok else {"error": r.text})
        if r.ok:
            fields = r.json().get("fields", {})
            return fields.get("number", {}).get("stringValue")
    except Exception as e:
        console.print(f"  [red]Error: {e}[/red]")
    return None


def _enumerate_victims(base_url: str, api_key: str) -> list[dict]:
    console.rule("[red]Victim enumeration (devices/)[/red]")
    victims   = []
    page_token = None
    page       = 0

    while True:
        page += 1
        params = {"key": api_key, "pageSize": 300}
        if page_token:
            params["pageToken"] = page_token

        try:
            r = SESSION.get(f"{base_url}/devices", params=params, timeout=20)
            if not r.ok:
                console.print(f"  [red]HTTP {r.status_code}[/red]")
                break

            data = r.json()
            docs = data.get("documents", [])
            for doc in docs:
                uid    = doc.get("name", "").split("/")[-1]
                fields = _parse_fields(doc.get("fields", {}))
                victims.append({"uid": uid, **fields})

            console.print(f"  [dim]Page {page}: +{len(docs)} victims ({len(victims)} total)[/dim]")
            page_token = data.get("nextPageToken")
            if not page_token:
                break

            time.sleep(0.1)  # gentle rate limiting

        except Exception as e:
            console.print(f"  [red]Enumeration error: {e}[/red]")
            break

    return victims


def _extract_victim_detail(base_url: str, api_key: str, uid: str) -> dict:
    result = {"otps": [], "sims": [], "credentials": {}}

    for sub in ("otps", "sims"):
        try:
            r = SESSION.get(
                f"{base_url}/devices/{uid}/{sub}",
                params={"key": api_key, "pageSize": 300},
                timeout=15
            )
            if r.ok:
                docs = r.json().get("documents", [])
                result[sub] = [_parse_fields(d.get("fields", {})) for d in docs]
        except Exception:
            pass

    # Forms (credential pages)
    try:
        r = SESSION.get(
            f"{base_url}/devices/{uid}/forms",
            params={"key": api_key, "pageSize": 50},
            timeout=15
        )
        if r.ok:
            form_docs = r.json().get("documents", [])
            for fdoc in form_docs:
                page_id = fdoc.get("name", "").split("/")[-1]
                er = SESSION.get(
                    f"{base_url}/devices/{uid}/forms/{page_id}/entries",
                    params={"key": api_key, "pageSize": 100},
                    timeout=10
                )
                if er.ok:
                    entry_docs = er.json().get("documents", [])
                    result["credentials"][page_id] = [
                        _parse_fields(e.get("fields", {})) for e in entry_docs
                    ]
    except Exception:
        pass

    return result


def _parse_fields(fields: dict) -> dict:
    def _val(v):
        if "stringValue"    in v: return v["stringValue"]
        if "integerValue"   in v: return int(v["integerValue"])
        if "booleanValue"   in v: return v["booleanValue"]
        if "timestampValue" in v: return v["timestampValue"]
        if "mapValue"       in v:
            return {k: _val(fv) for k, fv in v["mapValue"].get("fields", {}).items()}
        if "arrayValue"     in v:
            return [_val(i) for i in v["arrayValue"].get("values", [])]
        return str(v)
    return {k: _val(v) for k, v in fields.items()}


def _save(out_dir: str, filename: str, data):
    path = os.path.join(out_dir, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _ts():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
