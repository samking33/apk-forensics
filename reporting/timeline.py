"""
Timeline Reconstruction — a single chronological narrative of the campaign.

Stitches events from every evidence source into one ordered timeline an
investigator (and a court) can follow: when the malware was built, when it was
analysed, when each victim was infected, when money moved, and when the C2 last
showed activity. Answers "what happened, and in what order" without cross-
referencing five separate reports.
"""

from datetime import datetime, timezone


def _dt(v):
    """Coerce anything (datetime / ISO string / None) to a comparable datetime."""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    try:
        s = str(v).replace("Z", "+00:00")
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def reconstruct(*, cert_not_before=None, analysed_at=None, victims=None,
                transactions=None, alerts=None) -> list[dict]:
    """Returns events sorted oldest→newest: [{ts, category, detail}].
    Undated items are dropped (a timeline entry without a time is noise)."""
    events = []

    def add(ts, category, detail):
        d = _dt(ts)
        if d:
            events.append({"ts": d, "category": category, "detail": detail})

    add(cert_not_before, "BUILD", "APK signing certificate becomes valid (build/signing time)")

    for v in victims or []:
        add(v.get("infected_at"), "INFECTION",
            f"Victim infected: {v.get('mobile') or v.get('full_name') or v.get('id')}")
        add(v.get("last_seen"), "ACTIVITY",
            f"Last activity from victim {v.get('mobile') or v.get('id')}")

    for t in transactions or []:
        amt = t.get("amount")
        add(t.get("txn_date"), "MONEY",
            f"Debit ₹{amt:,.0f} → {t.get('upi_id') or t.get('recipient_name') or 'unknown'}"
            if amt else f"Transaction → {t.get('upi_id') or 'unknown'}")

    for a in alerts or []:
        add(a.get("created_at"), "C2",
            f"{a.get('alert_type', 'C2 activity')}: {a.get('message', '')}")

    add(analysed_at, "ANALYSIS", "Sample analysed by fSOC")

    return sorted(events, key=lambda e: e["ts"])


def render_text(events: list[dict]) -> str:
    lines = ["CAMPAIGN TIMELINE", "=" * 60]
    for e in events:
        lines.append(f"{e['ts'].strftime('%Y-%m-%d %H:%M:%S %Z'):<26} "
                     f"[{e['category']:<9}] {e['detail']}")
    if not events:
        lines.append("(no dated events)")
    return "\n".join(lines)


if __name__ == "__main__":
    events = reconstruct(
        cert_not_before="2026-01-01T00:00:00Z",
        analysed_at=datetime(2026, 7, 8, tzinfo=timezone.utc),
        victims=[{"id": 1, "mobile": "9876543210", "infected_at": "2026-03-15T10:00:00Z",
                  "last_seen": "2026-06-01T09:00:00Z"}],
        transactions=[{"amount": 50000, "upi_id": "mule@ybl", "txn_date": "2026-03-15T10:05:00Z"}],
        alerts=[{"alert_type": "NEW_VICTIM", "message": "new device",
                 "created_at": "2026-04-01T00:00:00Z"}],
    )
    cats = [e["category"] for e in events]
    assert cats == sorted(cats, key=lambda _: 0) and events[0]["category"] == "BUILD", cats
    assert events == sorted(events, key=lambda e: e["ts"]), "not chronologically ordered"
    assert "MONEY" in cats and "INFECTION" in cats and "C2" in cats
    print(render_text(events))
    print("OK — timeline reconstructed & ordered")
