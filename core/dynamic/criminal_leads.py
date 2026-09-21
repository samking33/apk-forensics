"""
Criminal Leads Generator — mines victim data for all leads pointing to the attacker.
Covers: cross-victim phone numbers, money mule UPI IDs, infection timeline,
debit SMS recipients, distribution links.
"""

import re
import collections
import datetime
from rich.console import Console

console = Console()

_PHONE_RE     = re.compile(r'(?<!\d)(\+?91[-\s]?)?[6-9]\d{9}(?!\d)')
_UPI_RE       = re.compile(r'[a-z0-9._\-]+@(?:ybl|okhdfcbank|okaxis|okicici|paytm|ptyes|oksbi)', re.I)
_SHORT_URL_RE = re.compile(r'https?://(?:bit\.ly|tinyurl\.com|t\.co|ow\.ly|is\.gd|weurl\.co|1kx\.in)/\S+', re.I)
_DEBIT_RE     = re.compile(r'debited.*?(?:INR|Rs\.?)\s*([\d,]+)', re.I)
_RECV_RE      = re.compile(r'(?:trf to|To:|paid to|sent to)\s*([A-Za-z\s]{3,30})(?:[,.]|\s+Ref|\s+on)', re.I)
_RAW_NUM_RE   = re.compile(r'^\+?[0-9]{10,15}$')


def generate(victims: list[dict], apk_id: str = None, db_session=None) -> list[dict]:
    """
    Analyse all victim data and return a ranked leads list.
    Saves to DB if session provided.
    """
    leads = []

    # Lead 1: Phone numbers that contacted MULTIPLE victims
    leads += _cross_victim_phones(victims)

    # Lead 2: Money mule UPI IDs in debit SMS
    leads += _money_mule_upis(victims)

    # Lead 3: Named recipients across multiple victims
    leads += _named_recipients(victims)

    # Lead 4: Phishing/distribution short URLs
    leads += _distribution_urls(victims)

    # Lead 5: Infection timeline surge days
    leads += _infection_timeline(victims)

    # Save to DB
    if db_session and apk_id:
        for lead in leads:
            _save_to_db(db_session, apk_id, lead)
        db_session.commit()

    _print_summary(leads)
    return leads


def _cross_victim_phones(victims: list[dict]) -> list[dict]:
    sender_map = collections.defaultdict(set)

    for v in victims:
        uid  = v.get("uid", "")
        name = _victim_name(v)
        for otp in v.get("otps", []):
            sender = str(otp.get("sender", ""))
            if _RAW_NUM_RE.match(sender):
                clean = sender.lstrip("+").lstrip("91")[-10:]
                sender_map[clean].add(f"{name}|{uid[:8]}")

    leads = []
    for num, victim_set in sorted(sender_map.items(), key=lambda x: -len(x[1])):
        if len(victim_set) < 2:
            continue
        priority = 1 if len(victim_set) >= 8 else 2 if len(victim_set) >= 4 else 3
        leads.append({
            "lead_type"  : "PHONE",
            "priority"   : priority,
            "value"      : num,
            "victim_count": len(victim_set),
            "description": f"Raw phone number found in OTP inbox of {len(victim_set)} unrelated victims. "
                           f"Strong indicator of APK distribution or attacker contact.",
            "action"     : "CDR subpoena via Section 91 BNSS. WhatsApp KYC via Meta India. "
                           "Telecom subscriber identity lookup.",
        })

    return sorted(leads, key=lambda x: (-x["victim_count"], x["priority"]))


def _money_mule_upis(victims: list[dict]) -> list[dict]:
    upi_counts = collections.Counter()

    for v in victims:
        for otp in v.get("otps", []):
            msg = otp.get("message", "")
            if "debit" not in msg.lower():
                continue
            for uid in _UPI_RE.findall(msg):
                if uid.split("@")[0] not in ("2d67e578", "3228b47e"):  # skip hash-prefix
                    upi_counts[uid] += 1

    leads = []
    for upi_id, count in upi_counts.most_common(20):
        if count < 2:
            continue
        leads.append({
            "lead_type"   : "UPI_ID",
            "priority"    : 1 if count >= 10 else 2,
            "value"       : upi_id,
            "victim_count": count,
            "description" : f"UPI ID received debit transfers from {count} victim accounts.",
            "action"      : "File freeze request with relevant bank/UPI provider. "
                            "Account holder identity via Section 91 BNSS to payment provider.",
        })

    return leads


def _named_recipients(victims: list[dict]) -> list[dict]:
    name_counts = collections.Counter()

    for v in victims:
        for otp in v.get("otps", []):
            msg    = otp.get("message", "")
            sender = otp.get("sender",  "")
            if "debit" not in msg.lower():
                continue
            if not any(x in sender for x in ["SBI", "HDFC", "AXIS", "ICIC", "BOI", "BOB", "PNB"]):
                continue
            for m in _RECV_RE.finditer(msg):
                name = m.group(1).strip()
                if 3 < len(name) < 30:
                    name_counts[name.upper()] += 1

    leads = []
    for name, count in name_counts.most_common(15):
        if count < 2:
            continue
        leads.append({
            "lead_type"   : "NAME",
            "priority"    : 1 if count >= 5 else 2,
            "value"       : name,
            "victim_count": count,
            "description" : f"Account holder '{name}' received funds from {count} victims. "
                            f"Possible money mule.",
            "action"      : "Cross-reference with CCTNS / NCR for prior cyber fraud. "
                            "Bank KYC lookup. GST/ROC check if business name.",
        })

    return leads


def _distribution_urls(victims: list[dict]) -> list[dict]:
    url_map = collections.Counter()

    for v in victims:
        seen = set()
        for otp in v.get("otps", []):
            for url in _SHORT_URL_RE.findall(otp.get("message", "")):
                url = url.strip().rstrip(".")
                if url not in seen:
                    seen.add(url)
                    url_map[url] += 1

    leads = []
    for url, count in url_map.most_common(10):
        if count < 2:
            continue
        leads.append({
            "lead_type"   : "URL",
            "priority"    : 2,
            "value"       : url,
            "victim_count": count,
            "description" : f"Short URL found in OTP inbox of {count} victims. "
                            f"May be APK distribution link.",
            "action"      : "Resolve URL and check final destination. "
                            "Legal process to URL shortener for creator identity.",
        })

    return leads


def _infection_timeline(victims: list[dict]) -> list[dict]:
    daily = collections.Counter()

    for v in victims:
        ts = v.get("created_at")
        if not ts:
            continue
        try:
            if str(ts).isdigit():
                t = int(ts)
                if t > 1e12:
                    t //= 1000
                dt = datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc)
            else:
                dt = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            daily[dt.strftime("%Y-%m-%d")] += 1
        except Exception:
            pass

    if not daily:
        return []

    avg = sum(daily.values()) / len(daily)
    surge_days = {d: c for d, c in daily.items() if c >= max(avg * 2, 10)}

    if not surge_days:
        return []

    timeline_str = "\n".join(
        f"  {d}: {c} victims {'█' * min(c, 40)}"
        for d, c in sorted(daily.items())
    )

    return [{
        "lead_type"   : "TIMELINE",
        "priority"    : 3,
        "value"       : ",".join(surge_days.keys()),
        "victim_count": sum(surge_days.values()),
        "description" : f"Infection surge days (2x average): {', '.join(sorted(surge_days.keys()))}. "
                        f"Each surge = attacker broadcasting the APK link to a large audience. "
                        f"Full timeline:\n{timeline_str}",
        "action"      : "Interview victims infected on surge days — they will remember the "
                        "exact WhatsApp group / Telegram channel from which they received the link.",
    }]


def _victim_name(v: dict) -> str:
    creds = v.get("credentials", {})
    for e in creds.get("page1", []):
        if e.get("full_name"):
            return str(e["full_name"])
    return "Unknown"


def _save_to_db(session, apk_id: str, lead: dict):
    from db.models import Lead
    session.add(Lead(
        apk_id      = apk_id,
        lead_type   = lead["lead_type"],
        priority    = lead["priority"],
        value       = lead["value"],
        description = lead["description"],
        action      = lead["action"],
        victim_count= lead.get("victim_count", 0),
    ))


def _print_summary(leads: list[dict]):
    if not leads:
        console.print("  [dim]No criminal leads generated.[/dim]")
        return
    console.print(f"\n  [bold red]{len(leads)} criminal leads generated:[/bold red]")
    for lead in sorted(leads, key=lambda x: x["priority"])[:10]:
        sev = "bold red" if lead["priority"] == 1 else "yellow"
        console.print(
            f"  P{lead['priority']} [{sev}]{lead['lead_type']}[/{sev}]: "
            f"{lead['value'][:60]}  ({lead.get('victim_count', 0)} victims)"
        )
