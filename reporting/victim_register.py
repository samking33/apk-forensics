"""
Victim Register — generates TXT + CSV for field team operations.
"""

import os
import csv
import datetime
from config import EVIDENCE_DIR


def generate(victims, apk_id: str, out_dir: str = None) -> tuple[str, str]:
    out_dir = out_dir or os.path.join(EVIDENCE_DIR, apk_id[:16])
    os.makedirs(out_dir, exist_ok=True)

    now = (datetime.datetime.now(datetime.timezone.utc)
           + datetime.timedelta(hours=5, minutes=30))

    sorted_victims = sorted(
        victims,
        key=lambda v: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(v.risk_level, 4)
    )

    txt_path = _write_txt(sorted_victims, apk_id, out_dir, now)
    csv_path = _write_csv(sorted_victims, apk_id, out_dir)

    return txt_path, csv_path


def _write_txt(victims, apk_id: str, out_dir: str, now: datetime.datetime) -> str:
    lines = [
        "=" * 80,
        "TELANGANA CYBER SECURITY BUREAU — VICTIM NOTIFICATION REGISTER",
        f"Case APK    : {apk_id[:16]}...",
        f"Generated   : {now.strftime('%Y-%m-%d %H:%M IST')}",
        f"Total victims: {len(victims)}",
        f"CRITICAL    : {sum(1 for v in victims if v.risk_level == 'CRITICAL')}",
        f"HIGH        : {sum(1 for v in victims if v.risk_level == 'HIGH')}",
        "=" * 80,
        "",
        "FIELD TEAM INSTRUCTIONS:",
        "  1. Contact each victim immediately. Start with CRITICAL.",
        "  2. Ask victim to visit nearest bank branch to:",
        "     a) Change UPI PIN, ATM PIN, and net banking password",
        "     b) Block and replace any debit/credit cards",
        "     c) File a complaint if unauthorized transactions occurred",
        "  3. Collect victim's signed statement for court record.",
        "  4. Record this notification in FIR as victim-informed.",
        "",
        "=" * 80,
        "",
    ]

    for i, v in enumerate(victims, 1):
        infected = _fmt_dt(v.infected_at)
        last     = _fmt_dt(v.last_seen)

        lines += [
            f"SR {i:04d}  [{v.risk_level}]",
            f"  Name        : {v.full_name or 'Not provided'}",
            f"  Mobile      : {v.mobile or 'Not provided'}",
            f"  Age / DOB   : {v.age or '?'} / {v.dob or '?'}",
            f"  Device      : {v.manufacturer or ''} {v.device or ''} (Android {v.android_version or '?'})",
            f"  Carrier     : {v.carrier or '?'}",
            f"  Infected    : {infected}",
            f"  Last Seen   : {last}",
            f"  OTPs stolen : {v.otp_count}",
            "",
        ]

        stolen = []
        if v.upi_pin_stolen:
            stolen.append(f"UPI PIN: {v.upi_pin or '[captured]'}")
        if v.card_stolen:
            stolen.append(f"Card last4: {v.card_last4 or '?'}  Expiry: {v.card_expiry or '?'}  CVV: {v.card_cvv or '?'}")
        if v.atm_pin:
            stolen.append(f"ATM PIN: {v.atm_pin}")
        if v.bank_name:
            stolen.append(f"Net banking — Bank: {v.bank_name}  User: {v.bank_userid or '?'}  Pass: {v.bank_password or '?'}")

        if stolen:
            lines.append("  COMPROMISED DATA:")
            for item in stolen:
                lines.append(f"    !! {item}")
        else:
            lines.append("  COMPROMISED DATA: Personal info only (no financial credentials captured)")

        lines.append("")
        lines.append("─" * 60)
        lines.append("")

    path = os.path.join(out_dir, "VICTIM_NOTIFICATION_REGISTER.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def _write_csv(victims, apk_id: str, out_dir: str) -> str:
    path = os.path.join(out_dir, "VICTIM_NOTIFICATION_LIST.csv")
    fields = [
        "sr", "risk_level", "full_name", "mobile", "age", "dob",
        "device", "manufacturer", "android_version", "carrier",
        "otp_count", "upi_pin_stolen", "upi_pin",
        "card_stolen", "card_last4", "card_expiry", "card_cvv", "atm_pin",
        "bank_name", "bank_userid", "bank_password",
        "infected_at", "last_seen", "firebase_uid",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for i, v in enumerate(victims, 1):
            row = {f: getattr(v, f, "") for f in fields}
            row["sr"]           = i
            row["infected_at"]  = _fmt_dt(v.infected_at)
            row["last_seen"]    = _fmt_dt(v.last_seen)
            row["upi_pin_stolen"] = "YES" if v.upi_pin_stolen else "NO"
            row["card_stolen"]    = "YES" if v.card_stolen    else "NO"
            w.writerow(row)
    return path


def _fmt_dt(dt) -> str:
    if not dt:
        return ""
    try:
        ist = dt + datetime.timedelta(hours=5, minutes=30)
        return ist.strftime("%Y-%m-%d %H:%M IST")
    except Exception:
        return str(dt)
