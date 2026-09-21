"""
Case Assignment & Officer Management
Handles officer accounts, lead assignment, status workflow, audit trail.

Workflow:
  Lead created (OPEN) → assigned to officer (IN_PROGRESS)
  → subpoena sent (SUBPOENA_SENT) → response received (RESPONSE_RECEIVED)
  → suspect located (SUSPECT_LOCATED) → arrested (ARRESTED) / closed (CLOSED)
"""

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional


LEAD_STATUSES = [
    "OPEN",
    "IN_PROGRESS",
    "SUBPOENA_SENT",
    "RESPONSE_RECEIVED",
    "SUSPECT_LOCATED",
    "ARRESTED",
    "CLOSED",
    "ESCALATED",
]

OFFICER_ROLES = ["ADMIN", "DSP", "INSPECTOR", "SI", "ANALYST", "VIEWER"]


# ── Password hashing (SHA-256 + salt, no external dep) ────────────────────────

def _hash_password(password: str, salt: Optional[str] = None) -> str:
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return f"{salt}:{h}"


# ── Officer management ─────────────────────────────────────────────────────────

def create_officer(db_session, name: str, badge_number: str, designation: str,
                   username: str, password: str, role: str = "ANALYST",
                   unit: str = "TGCSB", email: str = "", phone: str = "") -> "Officer":
    from db.models import Officer

    existing = db_session.query(Officer).filter_by(username=username).first()
    if existing:
        raise ValueError(f"Username '{username}' already exists")

    officer = Officer(
        name          = name,
        badge_number  = badge_number,
        designation   = designation,
        username      = username,
        password_hash = _hash_password(password),
        role          = role.upper(),
        unit          = unit,
        email         = email,
        phone         = phone,
    )
    db_session.add(officer)
    db_session.commit()
    return officer


def list_officers(db_session) -> list:
    from db.models import Officer
    return db_session.query(Officer).filter_by(is_active=True).order_by(Officer.name).all()


# ── Lead assignment ────────────────────────────────────────────────────────────

def assign_lead(db_session, lead_id: int, officer_id: int,
                assigned_by_id: int, note: str = "",
                deadline: Optional[datetime] = None) -> dict:
    from db.models import Lead, Officer, LeadAssignment

    lead    = db_session.get(Lead, lead_id)
    officer = db_session.get(Officer, officer_id)
    if not lead:
        raise ValueError(f"Lead {lead_id} not found")
    if not officer:
        raise ValueError(f"Officer {officer_id} not found")

    old_status       = lead.status
    lead.assigned_to = officer_id
    lead.status      = "IN_PROGRESS"

    entry = LeadAssignment(
        lead_id    = lead_id,
        officer_id = assigned_by_id,
        action     = "ASSIGNED",
        old_status = old_status,
        new_status = "IN_PROGRESS",
        note       = f"Assigned to {officer.name} ({officer.badge_number}). {note}",
        deadline   = deadline,
    )
    db_session.add(entry)
    db_session.commit()

    return {
        "lead_id"    : lead_id,
        "assigned_to": officer.name,
        "status"     : lead.status,
        "deadline"   : deadline.isoformat() if deadline else None,
    }


def update_lead_status(db_session, lead_id: int, new_status: str,
                       officer_id: int, note: str = "") -> dict:
    from db.models import Lead, LeadAssignment

    if new_status not in LEAD_STATUSES:
        raise ValueError(f"Invalid status: {new_status}. Must be one of {LEAD_STATUSES}")

    lead = db_session.get(Lead, lead_id)
    if not lead:
        raise ValueError(f"Lead {lead_id} not found")

    old_status  = lead.status
    lead.status = new_status
    if new_status in ("ARRESTED", "CLOSED"):
        lead.closed_at = datetime.now(timezone.utc)

    entry = LeadAssignment(
        lead_id    = lead_id,
        officer_id = officer_id,
        action     = "STATUS_CHANGE",
        old_status = old_status,
        new_status = new_status,
        note       = note,
    )
    db_session.add(entry)
    db_session.commit()

    return {"lead_id": lead_id, "old_status": old_status, "new_status": new_status}


def add_note(db_session, lead_id: int, officer_id: int, note: str) -> dict:
    from db.models import Lead, LeadAssignment

    lead = db_session.get(Lead, lead_id)
    if not lead:
        raise ValueError(f"Lead {lead_id} not found")

    if lead.notes:
        lead.notes += f"\n\n[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}]\n{note}"
    else:
        lead.notes = f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}]\n{note}"

    entry = LeadAssignment(
        lead_id    = lead_id,
        officer_id = officer_id,
        action     = "NOTE",
        old_status = lead.status,
        new_status = lead.status,
        note       = note,
    )
    db_session.add(entry)
    db_session.commit()
    return {"lead_id": lead_id, "note_added": True}


def get_lead_history(db_session, lead_id: int) -> list:
    from db.models import LeadAssignment, Officer

    entries = (db_session.query(LeadAssignment)
               .filter_by(lead_id=lead_id)
               .order_by(LeadAssignment.created_at.desc())
               .all())
    result = []
    for e in entries:
        off = db_session.get(Officer, e.officer_id)
        result.append({
            "action"     : e.action,
            "old_status" : e.old_status,
            "new_status" : e.new_status,
            "note"       : e.note,
            "officer"    : off.name if off else "Unknown",
            "badge"      : off.badge_number if off else "",
            "timestamp"  : e.created_at.isoformat() if e.created_at else None,
            "deadline"   : e.deadline.isoformat() if e.deadline else None,
        })
    return result


def dashboard_summary(db_session) -> dict:
    """Summary for the officers dashboard page."""
    from db.models import Lead, Officer, LeadAssignment

    all_leads    = db_session.query(Lead).all()
    all_officers = db_session.query(Officer).filter_by(is_active=True).all()

    status_counts = {}
    for lead in all_leads:
        status_counts[lead.status] = status_counts.get(lead.status, 0) + 1

    p1_open = [l for l in all_leads if l.priority == 1 and l.status == "OPEN"]

    return {
        "total_leads"    : len(all_leads),
        "total_officers" : len(all_officers),
        "status_counts"  : status_counts,
        "p1_unassigned"  : len(p1_open),
        "officers"       : [
            {
                "id"         : o.id,
                "name"       : o.name,
                "badge"      : o.badge_number,
                "designation": o.designation,
                "role"       : o.role,
                "assigned"   : db_session.query(Lead).filter_by(assigned_to=o.id).count(),
                "last_login" : o.last_login.isoformat() if o.last_login else None,
            }
            for o in all_officers
        ],
    }


def seed_default_admin(db_session):
    """Create a default admin officer if none exists. Run on first startup."""
    from db.models import Officer

    if db_session.query(Officer).count() == 0:
        create_officer(
            db_session,
            name        = "TGCSB Admin",
            badge_number= "TGCSB-001",
            designation = "Admin",
            username    = "admin",
            password    = "tgcsb@2026",
            role        = "ADMIN",
            unit        = "TGCSB",
        )
