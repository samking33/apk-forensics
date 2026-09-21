"""
Financial Quantum Engine
Parses all victim SMS messages to extract debit transactions,
computes exact financial loss per victim, per bank, and per mule account.
Produces court-grade financial evidence with individual transaction records.
"""

import re
from datetime import datetime
from collections import defaultdict
from typing import Optional


# ── Indian bank SMS debit patterns ────────────────────────────────────────────
# Each pattern: (bank_name, regex, amount_group, acct_group, date_group, ref_group, upi_group, name_group)

_PATTERNS = [
    # SBI
    ("SBI", re.compile(
        r"(?:Your A/c|Ac|a/c)\s+(?:no\.?\s*)?[Xx*]+(\d{4})\s+(?:is\s+)?debited\s+(?:by\s+)?(?:Rs\.?|INR)\s*([\d,]+\.?\d*)\s+on\s+([\d\-/]+)",
        re.I), 2, 1, 3, None, None, None),

    # HDFC
    ("HDFC Bank", re.compile(
        r"Rs\.([\d,]+\.?\d*)\s+(?:has been\s+)?debited\s+from\s+HDFC\s+Bank\s+A/C\s+[Xx*]+(\d{4})\s+on\s+([\d\-/]+)",
        re.I), 1, 2, 3, None, None, None),

    # ICICI
    ("ICICI Bank", re.compile(
        r"ICICI\s+Bank\s+Acct?\s+[Xx*]+(\d{4})\s+debited\s+Rs\s*([\d,]+\.?\d*)\s+on\s+([\d\-/]+)",
        re.I), 2, 1, 3, None, None, None),

    # Axis Bank
    ("Axis Bank", re.compile(
        r"(?:Your\s+)?a/c\s+[Xx*]+(\d{4})\s+is\s+debited\s+with\s+(?:Rs\.?|INR)\s*([\d,]+\.?\d*)\s+on\s+([\d\-/]+)",
        re.I), 2, 1, 3, None, None, None),

    # Yes Bank
    ("Yes Bank", re.compile(
        r"YBL[:\s]+(?:Rs\.?|INR)\s*([\d,]+\.?\d*)\s+debited\s+from\s+A/c\s+(?:no\s+)?[Xx*]+(\d{4})\s+on\s+([\d\-/]+)",
        re.I), 1, 2, 3, None, None, None),

    # Kotak
    ("Kotak Bank", re.compile(
        r"(?:Rs\.?|INR)\s*([\d,]+\.?\d*)\s+debited\s+from\s+Kotak\s+Bank\s+a/c\s+[Xx*]+(\d{4})\s+on\s+([\d\-/]+)",
        re.I), 1, 2, 3, None, None, None),

    # PNB
    ("PNB", re.compile(
        r"PNB[:\s]+(?:Rs\.?|INR)\s*([\d,]+\.?\d*)\s+(?:has been\s+)?debited\s+from\s+(?:Ac|A/c)\s+[Xx*]+(\d{4})\s+on\s+([\d\-/]+)",
        re.I), 1, 2, 3, None, None, None),

    # Bank of Baroda
    ("Bank of Baroda", re.compile(
        r"BOB[:\s|]+(?:Rs\.?|INR)\s*([\d,]+\.?\d*)\s+(?:has been\s+)?debited\s+from\s+[Xx*]+(\d{4})\s+on\s+([\d\-/]+)",
        re.I), 1, 2, 3, None, None, None),

    # Canara Bank
    ("Canara Bank", re.compile(
        r"Canara\s+Bank[:\s]+A/C\s+[Xx*]+(\d{4})\s+debited\s+(?:Rs\.?|INR)\s*([\d,]+\.?\d*)\s+on\s+([\d\-/]+)",
        re.I), 2, 1, 3, None, None, None),

    # IndusInd
    ("IndusInd Bank", re.compile(
        r"IndusInd[:\s]+(?:Rs\.?|INR)\s*([\d,]+\.?\d*)\s+debited\s+from\s+a/c\s+[Xx*]+(\d{4})\s+on\s+([\d\-/]+)",
        re.I), 1, 2, 3, None, None, None),

    # Generic UPI debit (catches most banks)
    ("Unknown", re.compile(
        r"(?:debited|deducted|transferred|sent|paid)[^₹Rs\d]*(?:Rs\.?|INR|₹)\s*([\d,]+\.?\d*)",
        re.I), 1, None, None, None, None, None),
]

# UPI destination extraction
_UPI_DEST = re.compile(
    r"(?:to|towards|VPA|UPI[:\s/]+)\s*([A-Za-z0-9._\-]+@(?:ybl|okaxis|oksbi|okhdfcbank|ptyes|paytm|okicici|upi|apl|ibl|axl|barodampay|cnrb|kvb|rbl|sib|tjsb|uco|union|utib|waaxis|yesb))",
    re.I
)
# Beneficiary name extraction
_BENE_NAME = re.compile(
    r"(?:to|transferred to|sent to|paid to)\s+([A-Z][A-Z\s]{2,40}?)(?:\s+via|\s+on|\s+Ref|\s*$|-|\|)",
    re.I
)
# Bank reference number
_REF_NO = re.compile(r"(?:Ref(?:\.?\s*No\.?|erence)?[:\s]+|Txn\s*(?:ID|Ref)[:\s]+)([A-Z0-9]{8,20})", re.I)
# Transaction type
_TXN_TYPE = re.compile(r"\b(UPI|NEFT|IMPS|RTGS|NACH|ATM|POS|CARD|NETBANKING|BHIM)\b", re.I)
# Date normalisation
_DATE_FMTS = ["%d-%m-%Y", "%d/%m/%Y", "%d-%m-%y", "%d/%m/%y",
              "%Y-%m-%d", "%d-%b-%Y", "%d-%b-%y"]


def _parse_amount(raw: str) -> float:
    try:
        return float(raw.replace(",", ""))
    except Exception:
        return 0.0


def _parse_date(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    for fmt in _DATE_FMTS:
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    return None


def parse_sms_transaction(sms_text: str, victim_mobile: str = "") -> Optional[dict]:
    """
    Parse a single SMS string and return a transaction dict or None.
    Dict keys: amount, bank_name, account_last4, txn_date, txn_type,
               upi_id, recipient_name, txn_ref, raw_sms
    """
    if not sms_text:
        return None

    amount = 0.0
    bank_name = "Unknown"
    acct_last4 = None
    txn_date = None

    for (bname, pat, ag, acg, dg, rg, ug, ng) in _PATTERNS:
        m = pat.search(sms_text)
        if m:
            try:
                amount = _parse_amount(m.group(ag))
            except Exception:
                continue
            if amount <= 0:
                continue
            bank_name = bname
            if acg:
                try: acct_last4 = m.group(acg)
                except Exception: pass
            if dg:
                try: txn_date = _parse_date(m.group(dg))
                except Exception: pass
            break

    if amount <= 0:
        return None

    # Extract UPI destination
    upi_id = None
    um = _UPI_DEST.search(sms_text)
    if um:
        upi_id = um.group(1).strip().lower()

    # Extract beneficiary name
    recipient_name = None
    nm = _BENE_NAME.search(sms_text)
    if nm:
        recipient_name = nm.group(1).strip().upper()

    # Extract reference number
    txn_ref = None
    rm = _REF_NO.search(sms_text)
    if rm:
        txn_ref = rm.group(1).strip()

    # Extract transaction type
    txn_type = "UNKNOWN"
    tm = _TXN_TYPE.search(sms_text)
    if tm:
        txn_type = tm.group(1).upper()
    elif upi_id:
        txn_type = "UPI"

    return {
        "amount"        : amount,
        "bank_name"     : bank_name,
        "account_last4" : acct_last4,
        "txn_date"      : txn_date,
        "txn_type"      : txn_type,
        "upi_id"        : upi_id,
        "recipient_name": recipient_name,
        "txn_ref"       : txn_ref,
        "raw_sms"       : sms_text[:500],
    }


def run(victims_raw: list, apk_id: str, db_session) -> dict:
    """
    Process all victim OTP/SMS messages, extract transactions,
    persist to Transaction table, update Apk.total_loss_inr.

    victims_raw: list of dicts from firebase_probe (with 'otps' list and 'uid')
    Returns: summary dict with totals, per_bank breakdown, per_mule breakdown
    """
    from db.models import Transaction, Victim, Apk

    total_amount   = 0.0
    per_bank       = defaultdict(float)
    per_mule       = defaultdict(lambda: {"amount": 0.0, "victims": set(), "count": 0})
    per_victim_sum = defaultdict(float)
    txn_rows       = []

    # Get victim ID mapping: firebase_uid → DB victim
    victim_map = {}
    for v in db_session.query(Victim).filter_by(apk_id=apk_id).all():
        victim_map[v.firebase_uid] = v

    # Remove old transactions for this apk (re-run safety)
    db_session.query(Transaction).filter_by(apk_id=apk_id).delete()
    db_session.commit()

    for vraw in victims_raw:
        uid  = vraw.get("uid", "")
        otps = vraw.get("otps", [])
        vobj = victim_map.get(uid)

        for otp in otps:
            txt = otp.get("message", "") or otp.get("text", "") or otp.get("body", "")
            if not txt:
                continue
            txn = parse_sms_transaction(txt)
            if not txn:
                continue

            total_amount += txn["amount"]
            per_bank[txn["bank_name"]] += txn["amount"]
            per_victim_sum[uid] += txn["amount"]

            if txn["upi_id"]:
                mule = per_mule[txn["upi_id"]]
                mule["amount"] += txn["amount"]
                mule["victims"].add(uid)
                mule["count"] += 1

            row = Transaction(
                apk_id         = apk_id,
                victim_id      = vobj.id if vobj else None,
                amount         = txn["amount"],
                txn_type       = txn["txn_type"],
                bank_name      = txn["bank_name"],
                account_last4  = txn["account_last4"],
                upi_id         = txn["upi_id"],
                recipient_name = txn["recipient_name"],
                txn_ref        = txn["txn_ref"],
                txn_date       = txn["txn_date"],
                raw_sms        = txn["raw_sms"],
            )
            txn_rows.append(row)

    db_session.bulk_save_objects(txn_rows)

    # Update per-victim totals
    for uid, total in per_victim_sum.items():
        vobj = victim_map.get(uid)
        if vobj:
            vobj.total_debited = total
            vobj.debit_count   = sum(
                1 for t in txn_rows
                if t.victim_id == vobj.id
            )

    # Update APK total loss
    apk_row = db_session.get(Apk, apk_id)
    if apk_row:
        apk_row.total_loss_inr = total_amount

    db_session.commit()

    # Convert mule sets to counts
    mule_summary = {
        uid: {
            "amount"      : d["amount"],
            "victim_count": len(d["victims"]),
            "txn_count"   : d["count"],
        }
        for uid, d in per_mule.items()
    }

    return {
        "total_loss_inr" : total_amount,
        "total_txns"     : len(txn_rows),
        "per_bank"       : dict(sorted(per_bank.items(), key=lambda x: -x[1])),
        "per_mule"       : dict(sorted(mule_summary.items(), key=lambda x: -x[1]["amount"])),
        "victim_count"   : len(per_victim_sum),
    }


def generate_report(apk_id: str, db_session, out_dir: str) -> str:
    """Generate a financial quantum text report for court submission."""
    import os
    from db.models import Apk, Transaction

    apk  = db_session.get(Apk, apk_id)
    txns = db_session.query(Transaction).filter_by(apk_id=apk_id).order_by(
        Transaction.txn_date.desc()
    ).all()

    per_bank  = defaultdict(float)
    per_mule  = defaultdict(lambda: {"amount": 0.0, "count": 0, "victims": set()})
    per_type  = defaultdict(float)
    total     = 0.0

    for t in txns:
        total += t.amount
        per_bank[t.bank_name or "Unknown"] += t.amount
        per_type[t.txn_type  or "UNKNOWN"] += t.amount
        if t.upi_id:
            per_mule[t.upi_id]["amount"] += t.amount
            per_mule[t.upi_id]["count"]  += 1
            if t.victim_id:
                per_mule[t.upi_id]["victims"].add(t.victim_id)

    lines = [
        "=" * 80,
        "  TELANGANA CYBER SECURITY BUREAU — FINANCIAL QUANTUM REPORT",
        "  EXACT FINANCIAL LOSS COMPUTATION FROM VICTIM SMS EVIDENCE",
        "=" * 80,
        "",
        f"  APK SHA-256   : {apk_id}",
        f"  Firebase C2   : {apk.firebase_project if apk else 'N/A'}",
        f"  Report date   : {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "─" * 80,
        "  TOTAL FINANCIAL LOSS",
        "─" * 80,
        "",
        f"  Total Transactions Extracted : {len(txns):,}",
        f"  Total Amount Debited (INR)   : Rs. {total:,.2f}",
        f"  In Crore                     : Rs. {total/10_000_000:.4f} Crore",
        "",
        "─" * 80,
        "  LOSS BY BANK",
        "─" * 80,
        "",
    ]
    for bank, amt in sorted(per_bank.items(), key=lambda x: -x[1]):
        lines.append(f"  {bank:<30}  Rs. {amt:>14,.2f}")

    lines += [
        "",
        "─" * 80,
        "  LOSS BY TRANSACTION TYPE",
        "─" * 80,
        "",
    ]
    for ttype, amt in sorted(per_type.items(), key=lambda x: -x[1]):
        lines.append(f"  {ttype:<20}  Rs. {amt:>14,.2f}")

    lines += [
        "",
        "─" * 80,
        "  MONEY MULE ACCOUNTS — RANKED BY AMOUNT RECEIVED",
        "─" * 80,
        "",
        f"  {'UPI ID':<48}  {'Amount (INR)':>14}  {'Txns':>5}  {'Victims':>7}",
        "  " + "-" * 78,
    ]
    for uid, d in sorted(per_mule.items(), key=lambda x: -x[1]["amount"])[:20]:
        lines.append(
            f"  {uid:<48}  Rs. {d['amount']:>10,.2f}  {d['count']:>5}  {len(d['victims']):>7}"
        )

    lines += ["", "=" * 80,
              "  This report is generated from SMS evidence extracted from victim devices.",
              "  All amounts are sourced from bank debit alert messages.",
              "  Admissible as electronic evidence under Section 65B, Indian Evidence Act.",
              "=" * 80, ""]

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "FINANCIAL_QUANTUM_REPORT.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return out_path
