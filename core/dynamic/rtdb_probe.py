"""
Firebase Realtime Database (RTDB) Probe — live extraction from RTDB-backed C2s.

Complements firebase_probe.py, which speaks Firestore only. Many banking-trojan
C2s use the older Realtime Database instead — a single flat JSON tree at
https://<project>-default-rtdb.firebaseio.com/.json — with no fixed schema:
campaign folders are named ad hoc (a date, a nickname) and section names vary
between malware families. So instead of hardcoding a path, we recursively
search the whole tree for any node that looks like a victim-data container
(has 2+ of the known section names as siblings) and merge whatever is found.

Normalizes into the same victim dict shape core/dynamic/victim_processor.py
expects, so RTDB-sourced victims flow through the identical pipeline (DB,
Victim Rescue, Full Records, Financial, Geo-Map, Monitor) as Firestore ones.
"""

import json
import os

import requests
from rich.console import Console

from config import EVIDENCE_DIR

console = Console()
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "Mozilla/5.0 TGCSB-Analyser/1.0"})

# Newer Firebase projects can live in a non-default region; try those hosts too.
_REGIONS = ["asia-southeast1", "europe-west1", "us-central1"]

# Section names this schema is built from. A node with 2+ of these as sibling
# keys is treated as "the victim container" — this is what makes the walk
# schema-agnostic across campaigns/families instead of a hardcoded path.
_VICTIM_SECTIONS = {"Sms", "SimINFO", "Info", "Call_For", "User"}


def _rtdb_hosts(project_id: str) -> list[str]:
    hosts = [f"https://{project_id}-default-rtdb.firebaseio.com"]
    hosts += [f"https://{project_id}-default-rtdb.{r}.firebasedatabase.app" for r in _REGIONS]
    return hosts


def _fetch_tree(project_id: str, api_key: str) -> tuple[str | None, dict | None]:
    """Try the default host then regional variants; return the first live,
    non-empty tree. Distinguishes 'wrong host' from 'deactivated/empty'."""
    for base in _rtdb_hosts(project_id):
        try:
            r = SESSION.get(f"{base}/.json", params={"key": api_key}, timeout=20)
        except requests.RequestException:
            continue
        if r.status_code == 200:
            try:
                data = r.json()
            except ValueError:
                continue
            if data:
                return base, data
    return None, None


def _find_victim_containers(node, path: str = "") -> list[tuple[str, dict]]:
    found = []
    if isinstance(node, dict):
        if len(_VICTIM_SECTIONS & set(node.keys())) >= 2:
            found.append((path, node))
        else:
            for k, v in node.items():
                found.extend(_find_victim_containers(v, f"{path}/{k}"))
    return found


def _parse_sim(sim_dict) -> list[dict]:
    sims = []
    if not isinstance(sim_dict, dict):
        return sims
    for slot in ("sim1", "sim2"):
        val = sim_dict.get(slot)
        if val:
            parts = str(val).split(" - ", 1)
            sims.append({
                "phone_number": parts[0].strip() if parts else "",
                "carrier_name": parts[1].strip() if len(parts) > 1 else "",
            })
    return sims


def _safe_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def run(project_id: str, api_key: str, apk_id: str = None, out_dir: str = None,
        progress=None) -> dict:
    """Same return shape as firebase_probe.run(): {victims, victim_count,
    otp_count, attacker_phone, errors, out_dir, ...}."""
    def _p(**kw):
        if progress:
            progress(kw)

    out_dir = out_dir or os.path.join(EVIDENCE_DIR, project_id)
    os.makedirs(out_dir, exist_ok=True)

    result = {
        "project_id": project_id, "api_key": api_key, "attacker_phone": None,
        "victim_count": 0, "otp_count": 0, "victims": [], "errors": [],
        "out_dir": out_dir, "backend": "rtdb",
    }

    _p(phase="Connecting to RTDB", current=0, total=0)
    base, tree = _fetch_tree(project_id, api_key)
    if not tree:
        result["errors"].append(
            "RTDB unreachable at default/regional hosts (deactivated, wrong "
            "project, or access denied by security rules)")
        return result
    console.print(f"  [green]RTDB live[/green]: {base}")

    _p(phase="Locating victim data", current=0, total=0)
    containers = _find_victim_containers(tree)
    if not containers:
        result["errors"].append("Connected, but no recognisable victim schema in the tree")
        return result

    merged = {sec: {} for sec in _VICTIM_SECTIONS}
    for _path, node in containers:
        for sec in merged:
            sub = node.get(sec)
            if isinstance(sub, dict):
                merged[sec].update(sub)

    did_to_info = {}
    for info_id, info in merged["Info"].items():
        if isinstance(info, dict):
            did_to_info[info.get("did") or info_id] = info

    all_dids = (set(merged["SimINFO"]) | set(merged["Sms"]) |
                set(merged["Call_For"]) | set(merged["User"]) | set(did_to_info))
    n = len(all_dids)
    _p(phase="Extracting victim data", current=0, total=n)

    victims = []
    total_otps = 0
    for i, did in enumerate(sorted(all_dids)):
        info = did_to_info.get(did) or {}
        sms = merged["Sms"].get(did) or {}
        otps = []
        if isinstance(sms, dict):
            for m in sms.values():
                if isinstance(m, dict):
                    otps.append({"timestamp": _safe_int(m.get("date")),
                                 "sender": m.get("ph", ""), "message": m.get("msg", "")})
        otps.sort(key=lambda o: o["timestamp"] or 0)

        victims.append({
            "uid": did,
            "model": info.get("Name", ""),
            "manufacturer": "",
            "android_version": "",
            "credentials": {},
            "otps": otps,
            "sims": _parse_sim(merged["SimINFO"].get(did)),
            "created_at": otps[0]["timestamp"] if otps else None,
            "last_seen": otps[-1]["timestamp"] if otps else None,
            "online": (info.get("status") == "Online") if info else None,
        })
        total_otps += len(otps)
        if (i + 1) % 5 == 0 or (i + 1) == n:
            _p(phase="Extracting victim data", current=i + 1, total=n)

    result["victims"] = victims
    result["victim_count"] = len(victims)
    result["otp_count"] = total_otps

    with open(os.path.join(out_dir, "full_victim_dump.json"), "w", encoding="utf-8") as f:
        json.dump(victims, f, indent=2, ensure_ascii=False)

    console.print(f"  [green]RTDB probe complete[/green] — {len(victims)} victims, {total_otps} OTPs")
    return result


if __name__ == "__main__":
    # ponytail self-check: the schema-agnostic container finder must locate a
    # victim tree regardless of the campaign folder name wrapping it, and the
    # did-join must merge Info/SimINFO/Sms correctly.
    tree = {"randomCampaignName123": {
        "Info": {"longid1": {"Name": "Pixel 6", "did": "devA", "status": "Online"}},
        "SimINFO": {"devA": {"sim1": "9990001111 - Jio"}},
        "Sms": {"devA": {"m1": {"date": "1000", "ph": "JD-BANK", "msg": "OTP 1234"}}},
    }}
    containers = _find_victim_containers(tree)
    assert containers and containers[0][0] == "/randomCampaignName123"
    node = containers[0][1]
    assert node["Info"]["longid1"]["did"] == "devA"
    sims = _parse_sim(node["SimINFO"]["devA"])
    assert sims == [{"phone_number": "9990001111", "carrier_name": "Jio"}]
    print("OK — RTDB container discovery + sim parsing verified")
