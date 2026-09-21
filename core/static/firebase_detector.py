"""
Firebase Detector — extracts Firebase project ID and API key from APK.
Checks DEX strings, google-services.json, and resource XML.
"""

import re
import json
import zipfile
from rich.console import Console

console = Console()

_API_KEY_RE  = re.compile(r'AIza[0-9A-Za-z\-_]{35}')
_PROJECT_RE  = re.compile(r'"project_id"\s*:\s*"([^"]+)"')
_PROJ_ALT_RE = re.compile(r'([a-z][a-z0-9\-]+-[0-9a-f]{4,8})(?:\.firebaseio\.com|\.firebaseapp\.com)?')
_PROJ_URL_RE = re.compile(r'https://([a-z0-9\-]+-[0-9a-f]{4,8})(?:\.firebaseio\.com|\.firebaseapp\.com|\.web\.app)')


def detect(apk_path: str, dex_strings: list[str]) -> dict:
    result = {
        "firebase_project" : None,
        "firebase_api_key" : None,
        "google_app_id"    : None,
        "storage_bucket"   : None,
        "messaging_sender" : None,
        "rtdb_url"         : None,
        "source"           : None,
        "all_api_keys"     : [],   # all keys found — attacker may embed C2 key alongside analytics key
        "all_projects"     : [],   # all project IDs found
    }

    # Step 1: DEX strings — scan first to find ALL API keys (catches embedded C2 keys)
    all_text = "\n".join(dex_strings)

    api_keys = list(dict.fromkeys(_API_KEY_RE.findall(all_text)))  # deduplicated, order-preserved
    result["all_api_keys"] = api_keys

    # Step 2: google-services.json — identifies the app's own declared Firebase project
    json_data = _extract_google_services_json(apk_path)
    gs_project = None
    gs_key     = None
    if json_data:
        tmp = {}
        _parse_google_services(json_data, tmp)
        gs_project = tmp.get("firebase_project")
        gs_key     = tmp.get("firebase_api_key")
        if gs_project:
            result["all_projects"].append(gs_project)
        result.update({k: v for k, v in tmp.items() if v})
        result["source"] = "google-services.json"

    # Step 3: find project IDs from URL patterns in DEX strings
    for m in _PROJ_URL_RE.finditer(all_text):
        p = m.group(1)
        if p not in result["all_projects"]:
            result["all_projects"].append(p)
    for m in _PROJ_ALT_RE.finditer(all_text):
        p = m.group(1)
        if len(p) > 8 and p not in result["all_projects"]:
            result["all_projects"].append(p)

    # Step 4: select the C2 project — prefer project that is NOT the app's own declared project
    # Criminals embed a different Firebase project as C2 alongside the app's own analytics project
    c2_project = None
    c2_key     = None
    for proj in result["all_projects"]:
        if proj != gs_project:
            c2_project = proj
            break

    # If we found a C2 project, use the first API key that doesn't belong to the app's own project
    # (heuristic: if there are multiple keys, first one in DEX may be C2)
    if api_keys:
        c2_key = api_keys[0]
        # If google-services.json key exists and matches first DEX key, try the next
        if gs_key and len(api_keys) > 1 and api_keys[0] == gs_key:
            c2_key = api_keys[1]

    # Final assignment: prefer C2 over app's own analytics project
    result["firebase_project"] = c2_project or gs_project
    result["firebase_api_key"] = c2_key or gs_key
    result["source"]           = (result["source"] or "") + "+dex_strings"

    _log(result)
    return result


def _extract_google_services_json(apk_path: str) -> dict | None:
    candidates = [
        "assets/google-services.json",
        "google-services.json",
        "res/raw/google_services.json",
    ]
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if any(name.endswith(c.split("/")[-1]) for c in candidates):
                    data = z.read(name).decode("utf-8", errors="replace")
                    return json.loads(data)
    except Exception:
        pass
    return None


def _parse_google_services(data: dict, result: dict):
    try:
        result["firebase_project"]  = data.get("project_info", {}).get("project_id")
        result["storage_bucket"]    = data.get("project_info", {}).get("storage_bucket")
        result["rtdb_url"]          = data.get("project_info", {}).get("firebase_url")
        result["messaging_sender"]  = data.get("project_info", {}).get("project_number")

        clients = data.get("client", [])
        if clients:
            client = clients[0]
            result["google_app_id"] = client.get("client_info", {}).get("mobilesdk_app_id")
            api_keys = client.get("api_key", [])
            if api_keys:
                result["firebase_api_key"] = api_keys[0].get("current_key")
    except Exception:
        pass


def _log(result: dict):
    if result["firebase_project"]:
        console.print(f"  [bold red]FIREBASE PROJECT: {result['firebase_project']}[/bold red]")
    if result["firebase_api_key"]:
        console.print(f"  [bold red]FIREBASE API KEY: {result['firebase_api_key']}[/bold red]")
    if not result["firebase_project"] and not result["firebase_api_key"]:
        console.print("  [dim]No Firebase config detected.[/dim]")
