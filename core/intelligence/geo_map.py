"""
Geo-Intelligence Map
Extracts geographic clues from victim SMS messages and device data,
maps victim distribution across Indian states, generates Folium choropleth.

Detection methods (in priority order):
  1. Bank branch city/state mentioned in SMS ("SBI Branch, Hyderabad")
  2. IFSC code prefix → bank branch state
  3. Carrier name patterns ("Airtel Telangana", "Jio UP East")
  4. Mobile number series → TRAI circle → state (approximate)
"""

import os
import re
import json
from collections import defaultdict
from datetime import datetime
from typing import Optional

try:
    import folium
    from folium.plugins import MarkerCluster
    HAS_FOLIUM = True
except ImportError:
    HAS_FOLIUM = False


# ── India state coordinates (centroid) ────────────────────────────────────────
STATE_COORDS = {
    "Andhra Pradesh"      : (15.9129,  79.7400),
    "Arunachal Pradesh"   : (28.2180,  94.7278),
    "Assam"               : (26.2006,  92.9376),
    "Bihar"               : (25.0961,  85.3131),
    "Chhattisgarh"        : (21.2787,  81.8661),
    "Goa"                 : (15.2993,  74.1240),
    "Gujarat"             : (22.2587,  71.1924),
    "Haryana"             : (29.0588,  76.0856),
    "Himachal Pradesh"    : (31.1048,  77.1734),
    "Jharkhand"           : (23.6102,  85.2799),
    "Karnataka"           : (15.3173,  75.7139),
    "Kerala"              : (10.8505,  76.2711),
    "Madhya Pradesh"      : (22.9734,  78.6569),
    "Maharashtra"         : (19.7515,  75.7139),
    "Manipur"             : (24.6637,  93.9063),
    "Meghalaya"           : (25.4670,  91.3662),
    "Mizoram"             : (23.1645,  92.9376),
    "Nagaland"            : (26.1584,  94.5624),
    "Odisha"              : (20.9517,  85.0985),
    "Punjab"              : (31.1471,  75.3412),
    "Rajasthan"           : (27.0238,  74.2179),
    "Sikkim"              : (27.5330,  88.5122),
    "Tamil Nadu"          : (11.1271,  78.6569),
    "Telangana"           : (17.1232,  79.2089),
    "Tripura"             : (23.9408,  91.9882),
    "Uttar Pradesh"       : (26.8467,  80.9462),
    "Uttarakhand"         : (30.0668,  79.0193),
    "West Bengal"         : (22.9868,  87.8550),
    "Delhi"               : (28.7041,  77.1025),
    "Jammu and Kashmir"   : (33.7782,  76.5762),
    "Ladakh"              : (34.2996,  78.2932),
}

# ── City → State mapping (major cities) ───────────────────────────────────────
CITY_TO_STATE = {
    "hyderabad": "Telangana",   "secunderabad": "Telangana",
    "warangal": "Telangana",    "karimnagar": "Telangana",
    "nizamabad": "Telangana",   "khammam": "Telangana",
    "bengaluru": "Karnataka",   "bangalore": "Karnataka",
    "mysuru": "Karnataka",      "mysore": "Karnataka",
    "hubli": "Karnataka",       "mangaluru": "Karnataka",
    "mumbai": "Maharashtra",    "pune": "Maharashtra",
    "nagpur": "Maharashtra",    "nashik": "Maharashtra",
    "thane": "Maharashtra",     "aurangabad": "Maharashtra",
    "chennai": "Tamil Nadu",    "coimbatore": "Tamil Nadu",
    "madurai": "Tamil Nadu",    "tiruchirappalli": "Tamil Nadu",
    "delhi": "Delhi",           "new delhi": "Delhi",
    "noida": "Uttar Pradesh",   "ghaziabad": "Uttar Pradesh",
    "lucknow": "Uttar Pradesh", "kanpur": "Uttar Pradesh",
    "agra": "Uttar Pradesh",    "varanasi": "Uttar Pradesh",
    "kolkata": "West Bengal",   "howrah": "West Bengal",
    "durgapur": "West Bengal",  "asansol": "West Bengal",
    "ahmedabad": "Gujarat",     "surat": "Gujarat",
    "vadodara": "Gujarat",      "rajkot": "Gujarat",
    "jaipur": "Rajasthan",      "jodhpur": "Rajasthan",
    "udaipur": "Rajasthan",     "kota": "Rajasthan",
    "bhopal": "Madhya Pradesh", "indore": "Madhya Pradesh",
    "jabalpur": "Madhya Pradesh","gwalior": "Madhya Pradesh",
    "patna": "Bihar",           "gaya": "Bihar",
    "ranchi": "Jharkhand",      "jamshedpur": "Jharkhand",
    "bhubaneswar": "Odisha",    "cuttack": "Odisha",
    "guwahati": "Assam",        "dibrugarh": "Assam",
    "chandigarh": "Punjab",     "ludhiana": "Punjab",
    "amritsar": "Punjab",       "jalandhar": "Punjab",
    "gurugram": "Haryana",      "faridabad": "Haryana",
    "visakhapatnam": "Andhra Pradesh","vijayawada": "Andhra Pradesh",
    "vizag": "Andhra Pradesh",  "tirupati": "Andhra Pradesh",
    "kochi": "Kerala",          "thiruvananthapuram": "Kerala",
    "kozhikode": "Kerala",      "thrissur": "Kerala",
    "dehradun": "Uttarakhand",  "haridwar": "Uttarakhand",
    "shimla": "Himachal Pradesh","dharamsala": "Himachal Pradesh",
    "raipur": "Chhattisgarh",   "bhilai": "Chhattisgarh",
    "panaji": "Goa",            "margao": "Goa",
    "imphal": "Manipur",        "shillong": "Meghalaya",
    "aizawl": "Mizoram",        "kohima": "Nagaland",
    "agartala": "Tripura",      "gangtok": "Sikkim",
    "srinagar": "Jammu and Kashmir", "jammu": "Jammu and Kashmir",
}

# ── Carrier circle → State mapping (TRAI telecom circles) ─────────────────────
CARRIER_CIRCLE_TO_STATE = {
    "telangana": "Telangana",
    "andhra": "Andhra Pradesh",
    "karnataka": "Karnataka",
    "tamil": "Tamil Nadu",
    "kerala": "Kerala",
    "mumbai": "Maharashtra",
    "maharashtra": "Maharashtra",
    "gujarat": "Gujarat",
    "rajasthan": "Rajasthan",
    "madhya": "Madhya Pradesh",
    "up east": "Uttar Pradesh",
    "up west": "Uttar Pradesh",
    "uttar pradesh": "Uttar Pradesh",
    "delhi": "Delhi",
    "kolkata": "West Bengal",
    "west bengal": "West Bengal",
    "bihar": "Bihar",
    "jharkhand": "Jharkhand",
    "odisha": "Odisha",
    "assam": "Assam",
    "northeast": "Assam",
    "punjab": "Punjab",
    "haryana": "Haryana",
    "himachal": "Himachal Pradesh",
    "jammu": "Jammu and Kashmir",
    "uttarakhand": "Uttarakhand",
    "chhattisgarh": "Chhattisgarh",
    "orissa": "Odisha",
}

# Regex to find city mentions in SMS
_CITY_RE  = re.compile(r'\b(' + '|'.join(CITY_TO_STATE.keys()) + r')\b', re.I)
_STATE_RE = re.compile(r'\b(' + '|'.join(re.escape(s) for s in STATE_COORDS.keys()) + r')\b', re.I)


def detect_state(victim) -> Optional[str]:
    """
    Detect Indian state for a victim from multiple signals.
    Returns state name string or None.
    """
    # 1. Already have it in DB
    if victim.state and victim.state in STATE_COORDS:
        return victim.state

    # 2. Carrier field
    carrier = (victim.carrier or "").lower()
    for keyword, state in CARRIER_CIRCLE_TO_STATE.items():
        if keyword in carrier:
            return state

    return None


def detect_state_from_sms(sms_list: list) -> Optional[str]:
    """Scan a list of SMS texts to find state clues."""
    state_votes: dict[str, int] = defaultdict(int)

    for sms in sms_list:
        text = sms.get("message", "") or sms.get("text", "") or ""
        if not text:
            continue

        # City match
        for m in _CITY_RE.finditer(text):
            city  = m.group(1).lower()
            state = CITY_TO_STATE.get(city)
            if state:
                state_votes[state] += 2

        # State name match
        for m in _STATE_RE.finditer(text):
            state_votes[m.group(1)] += 1

        # Carrier circle pattern
        text_lower = text.lower()
        for keyword, state in CARRIER_CIRCLE_TO_STATE.items():
            if keyword in text_lower:
                state_votes[state] += 1

    if not state_votes:
        return None
    return max(state_votes, key=lambda x: state_votes[x])


def run(apk_id: str, victims_raw: list, db_session, out_dir: str) -> dict:
    """
    Detect states for all victims, update DB, generate Folium map.
    victims_raw: list of raw victim dicts (with 'otps' key from firebase_probe)
    """
    from db.models import Victim

    os.makedirs(out_dir, exist_ok=True)

    victim_map = {v.firebase_uid: v
                  for v in db_session.query(Victim).filter_by(apk_id=apk_id).all()}

    state_counts: dict[str, int]  = defaultdict(int)
    state_victims: dict[str, list] = defaultdict(list)

    for vraw in victims_raw:
        uid    = vraw.get("uid", "")
        sms    = vraw.get("otps", [])
        vobj   = victim_map.get(uid)
        if not vobj:
            continue

        state = detect_state(vobj)
        if not state:
            state = detect_state_from_sms(sms)
        if not state:
            state = "Unknown"

        vobj.state = state
        coords = STATE_COORDS.get(state)
        if coords:
            vobj.latitude  = coords[0]
            vobj.longitude = coords[1]

        state_counts[state] += 1
        state_victims[state].append({
            "name"  : vobj.full_name or "Unknown",
            "mobile": vobj.mobile or "",
            "risk"  : vobj.risk_level or "UNKNOWN",
        })

    db_session.commit()

    html_path = _generate_folium_map(apk_id, state_counts, state_victims, out_dir, db_session)
    json_path = _export_geo_json(state_counts, out_dir)

    return {
        "state_counts": dict(state_counts),
        "html_path"   : html_path,
        "json_path"   : json_path,
        "top_state"   : max(state_counts, key=lambda x: state_counts[x]) if state_counts else "Unknown",
        "states_hit"  : len([s for s in state_counts if s != "Unknown"]),
        "available"   : HAS_FOLIUM,
    }


def _generate_folium_map(apk_id: str, state_counts: dict,
                         state_victims: dict, out_dir: str, db_session) -> str:
    if not HAS_FOLIUM:
        return ""

    from db.models import Apk
    apk_row = db_session.get(Apk, apk_id)
    title   = apk_row.firebase_project if apk_row else apk_id[:16]

    m = folium.Map(
        location=[22.0, 80.0], zoom_start=5,
        tiles="CartoDB dark_matter",
    )

    # Title
    title_html = f"""
    <div style="position:fixed;top:10px;left:50%;transform:translateX(-50%);
                background:#161b22;color:#e6edf3;padding:8px 20px;
                border-radius:6px;border:1px solid #30363d;
                font-family:sans-serif;font-size:14px;font-weight:bold;z-index:9999">
      TGCSB — Victim Distribution Map | {title}
    </div>"""
    m.get_root().html.add_child(folium.Element(title_html))

    # State circles
    max_count = max(state_counts.values()) if state_counts else 1
    for state, count in state_counts.items():
        if state == "Unknown":
            continue
        coords = STATE_COORDS.get(state)
        if not coords:
            continue

        # Scale radius 8–40 by victim count
        radius  = 8 + int((count / max_count) * 32)
        opacity = 0.4 + (count / max_count) * 0.5

        victims_html = "<br>".join(
            f"• {v['name']} ({v['mobile']}) — <b style='color:{'red' if v['risk']=='CRITICAL' else 'orange'}'>{v['risk']}</b>"
            for v in state_victims[state][:10]
        )
        if count > 10:
            victims_html += f"<br>... and {count-10} more"

        popup_html = f"""
        <div style="font-family:sans-serif;min-width:220px">
          <b>{state}</b><br>
          <span style="color:#f85149">Victims: {count}</span><br><hr>
          {victims_html}
        </div>"""

        folium.CircleMarker(
            location  = coords,
            radius    = radius,
            color     = "#f85149",
            fill      = True,
            fill_color= "#f85149",
            fill_opacity = opacity,
            tooltip   = f"{state}: {count} victims",
            popup     = folium.Popup(popup_html, max_width=300),
        ).add_to(m)

        folium.Marker(
            location = [coords[0] + 0.3, coords[1]],
            icon     = folium.DivIcon(
                html=f'<div style="font-size:11px;color:white;font-weight:bold;'
                     f'text-shadow:1px 1px 2px black">{state[:10]}<br>{count}</div>',
                icon_size=(100, 30),
            )
        ).add_to(m)

    out_path = os.path.join(out_dir, "GEO_VICTIM_MAP.html")
    m.save(out_path)
    return out_path


def _export_geo_json(state_counts: dict, out_dir: str) -> str:
    data = {
        "generated_at": datetime.now().isoformat(),
        "states": [
            {
                "state" : state,
                "count" : count,
                "coords": STATE_COORDS.get(state),
            }
            for state, count in sorted(state_counts.items(), key=lambda x: -x[1])
        ]
    }
    path = os.path.join(out_dir, "geo_data.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path
