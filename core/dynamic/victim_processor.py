"""
Victim Processor — parses raw Firebase victim dump, classifies risk,
and saves structured victim rows to DB.
"""

import datetime
from rich.console import Console

console = Console()


def process(victims_raw: list[dict], apk_id: str, db_session=None) -> list[dict]:
    processed = []

    for v in victims_raw:
        uid   = v.get("uid", "")
        creds = v.get("credentials", {})
        otps  = v.get("otps", [])
        sims  = v.get("sims", [])

        # Extract personal info from page1
        name  = ""
        phone = ""
        dob   = ""
        age   = ""
        for e in creds.get("page1", []):
            if not name  and e.get("full_name"):  name  = str(e["full_name"])
            if not phone and e.get("mobile"):     phone = str(e["mobile"])
            if not dob   and e.get("dob"):        dob   = str(e["dob"])
            if not age   and e.get("age"):        age   = str(e["age"])

        # Banking credentials
        upi_pin       = ""
        card_last4    = ""
        card_expiry   = ""
        card_cvv      = ""
        atm_pin       = ""
        bank_name     = ""
        bank_userid   = ""
        bank_password = ""

        for e in creds.get("page2", []):
            bank_name     = bank_name     or str(e.get("bank_name",    ""))
            bank_userid   = bank_userid   or str(e.get("userid",       ""))
            bank_password = bank_password or str(e.get("password",     ""))

        for e in creds.get("page4", []):
            upi_pin = upi_pin or str(e.get("upi_pin", ""))

        for e in creds.get("page6", []):
            card_last4  = card_last4  or str(e.get("card_number", ""))[-4:]
            card_expiry = card_expiry or str(e.get("expiry",      ""))
            card_cvv    = card_cvv    or str(e.get("cvv",         ""))
            atm_pin     = atm_pin     or str(e.get("atm_pin",     ""))

        # Device info
        device       = str(v.get("model",            ""))
        manufacturer = str(v.get("manufacturer",     ""))
        android_ver  = str(v.get("android_version",  ""))
        carrier      = ""
        if sims:
            carrier = str(sims[0].get("carrier_name", ""))

        # Timestamps
        infected_at = _parse_ts(v.get("created_at"))
        last_seen   = _parse_ts(v.get("last_seen"))

        # Risk classification
        upi_stolen  = bool(upi_pin)
        card_stolen = bool(card_last4 or card_cvv or atm_pin)
        risk = _classify_risk(upi_stolen, card_stolen, len(otps), bank_password)

        row = {
            "firebase_uid"   : uid,
            "full_name"      : name,
            "mobile"         : phone,
            "age"            : age,
            "dob"            : dob,
            "device"         : device,
            "manufacturer"   : manufacturer,
            "android_version": android_ver,
            "carrier"        : carrier,
            "risk_level"     : risk,
            "otp_count"      : len(otps),
            "upi_pin_stolen" : upi_stolen,
            "upi_pin"        : upi_pin,
            "card_stolen"    : card_stolen,
            "card_last4"     : card_last4,
            "card_expiry"    : card_expiry,
            "card_cvv"       : card_cvv,
            "atm_pin"        : atm_pin,
            "bank_name"      : bank_name,
            "bank_userid"    : bank_userid,
            "bank_password"  : bank_password,
            "infected_at"    : infected_at,
            "last_seen"      : last_seen,
        }
        processed.append(row)

        if db_session:
            _save_to_db(db_session, apk_id, row)

    if db_session:
        db_session.commit()

    stats = _summarise(processed)
    console.print(
        f"  Processed [green]{len(processed)}[/green] victims — "
        f"CRITICAL:[red]{stats['critical']}[/red] "
        f"HIGH:[yellow]{stats['high']}[/yellow] "
        f"UPI stolen:[red]{stats['upi']}[/red] "
        f"Card stolen:[red]{stats['card']}[/red]"
    )
    return processed


def _classify_risk(upi: bool, card: bool, otp_count: int, bank_pwd: str) -> str:
    if upi and card:           return "CRITICAL"
    if upi or bank_pwd:        return "HIGH"
    if card or otp_count > 10: return "MEDIUM"
    return "LOW"


def _parse_ts(val) -> datetime.datetime | None:
    if not val:
        return None
    try:
        if isinstance(val, (int, float)):
            ts = int(val)
            if ts > 1e12:
                ts //= 1000
            return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return datetime.datetime.fromisoformat(str(val).replace("Z", "+00:00"))
    except Exception:
        return None


def _save_to_db(session, apk_id: str, row: dict):
    from db.models import Victim
    v = Victim(apk_id=apk_id, **row)
    session.add(v)


def _summarise(rows: list[dict]) -> dict:
    return {
        "critical": sum(1 for r in rows if r["risk_level"] == "CRITICAL"),
        "high"    : sum(1 for r in rows if r["risk_level"] == "HIGH"),
        "medium"  : sum(1 for r in rows if r["risk_level"] == "MEDIUM"),
        "low"     : sum(1 for r in rows if r["risk_level"] == "LOW"),
        "upi"     : sum(1 for r in rows if r["upi_pin_stolen"]),
        "card"    : sum(1 for r in rows if r["card_stolen"]),
        "total_otp": sum(r["otp_count"] for r in rows),
    }
