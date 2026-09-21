from sqlalchemy import Column, String, Integer, Boolean, Text, DateTime, ForeignKey, Float, JSON
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime, timezone

Base = declarative_base()


def _now():
    return datetime.now(timezone.utc)


class Apk(Base):
    __tablename__ = "apks"

    id               = Column(String, primary_key=True)   # sha256
    case_id          = Column(String, nullable=True)
    filename         = Column(String)
    file_path        = Column(String)
    package_name     = Column(String)
    version_name     = Column(String)
    version_code     = Column(String)
    min_sdk          = Column(Integer)
    target_sdk       = Column(Integer)
    cert_serial      = Column(String)
    cert_subject     = Column(String)
    cert_sha256      = Column(String)
    firebase_project = Column(String)
    firebase_api_key = Column(String)
    attacker_phone   = Column(String)
    victim_count     = Column(Integer, default=0)
    otp_count        = Column(Integer, default=0)
    risk_score       = Column(Integer, default=0)
    # Static-analysis intelligence (populated by the static engine v2)
    malware_tags     = Column(JSON)      # permission-derived tags
    behaviors        = Column(JSON)      # detected banking-trojan behaviours
    c2_channel       = Column(String)    # top C2 channel type (telegram/http/…)
    c2_detail        = Column(JSON)      # full classified C2 channel list
    risk_breakdown   = Column(JSON)      # explainable per-factor risk points
    cert_schemes     = Column(String)    # signing schemes, e.g. "v1+v2+v3"
    # Financial quantum (populated by FinancialQuantumEngine)
    total_loss_inr   = Column(Float, default=0.0)
    analysed_at      = Column(DateTime, default=_now)
    static_done      = Column(Boolean, default=False)
    dynamic_done     = Column(Boolean, default=False)
    # Monitor state
    monitor_active   = Column(Boolean, default=False)
    last_monitored   = Column(DateTime, nullable=True)

    findings     = relationship("Finding",     back_populates="apk", cascade="all, delete-orphan")
    iocs         = relationship("IoC",         back_populates="apk", cascade="all, delete-orphan")
    victims      = relationship("Victim",      back_populates="apk", cascade="all, delete-orphan")
    leads        = relationship("Lead",        back_populates="apk", cascade="all, delete-orphan")
    transactions = relationship("Transaction", back_populates="apk", cascade="all, delete-orphan")
    alerts       = relationship("MonitorAlert",back_populates="apk", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    apk_id     = Column(String, ForeignKey("apks.id"))
    category   = Column(String)    # PERMISSION | COMPONENT | CREDENTIAL | NETWORK | BEHAVIOUR
    severity   = Column(String)    # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title      = Column(String)
    detail     = Column(Text)
    found_at   = Column(String)    # file/class/method where found
    created_at = Column(DateTime, default=_now)

    apk        = relationship("Apk", back_populates="findings")


class IoC(Base):
    __tablename__ = "iocs"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    apk_id      = Column(String, ForeignKey("apks.id"))
    ioc_type    = Column(String)    # HASH | DOMAIN | IP | PHONE | EMAIL | PACKAGE | API_KEY | URL
    value       = Column(String)
    description = Column(String)
    created_at  = Column(DateTime, default=_now)

    apk         = relationship("Apk", back_populates="iocs")


class Victim(Base):
    __tablename__ = "victims"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    apk_id           = Column(String, ForeignKey("apks.id"))
    firebase_uid     = Column(String)
    full_name        = Column(String)
    mobile           = Column(String)
    age              = Column(String)
    dob              = Column(String)
    device           = Column(String)
    manufacturer     = Column(String)
    android_version  = Column(String)
    carrier          = Column(String)
    risk_level       = Column(String)    # CRITICAL | HIGH | MEDIUM | LOW
    otp_count        = Column(Integer, default=0)
    upi_pin_stolen   = Column(Boolean, default=False)
    upi_pin          = Column(String)
    card_stolen      = Column(Boolean, default=False)
    card_last4       = Column(String)
    card_expiry      = Column(String)
    card_cvv         = Column(String)
    atm_pin          = Column(String)
    bank_name        = Column(String)
    bank_userid      = Column(String)
    bank_password    = Column(String)
    infected_at      = Column(DateTime)
    last_seen        = Column(DateTime)
    created_at       = Column(DateTime, default=_now)
    # Financial quantum fields
    total_debited    = Column(Float, default=0.0)
    debit_count      = Column(Integer, default=0)
    state            = Column(String)    # Detected Indian state
    city             = Column(String)    # Detected city
    latitude         = Column(Float)
    longitude        = Column(Float)

    apk              = relationship("Apk", back_populates="victims")
    transactions     = relationship("Transaction", back_populates="victim", cascade="all, delete-orphan")


class Lead(Base):
    __tablename__ = "leads"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    apk_id       = Column(String, ForeignKey("apks.id"))
    lead_type    = Column(String)    # PHONE | UPI_ID | NAME | URL | CERT | FIREBASE
    priority     = Column(Integer)   # 1 = highest
    value        = Column(String)
    description  = Column(Text)
    action       = Column(Text)      # Recommended legal action
    victim_count = Column(Integer, default=0)
    created_at   = Column(DateTime, default=_now)
    # Case assignment
    assigned_to  = Column(Integer, ForeignKey("officers.id"), nullable=True)
    status       = Column(String, default="OPEN")   # OPEN | IN_PROGRESS | CLOSED | ARRESTED
    notes        = Column(Text)
    closed_at    = Column(DateTime, nullable=True)

    apk          = relationship("Apk", back_populates="leads")
    officer      = relationship("Officer", back_populates="leads")
    assignments  = relationship("LeadAssignment", back_populates="lead", cascade="all, delete-orphan")


class Transaction(Base):
    """Individual debit transaction extracted from victim SMS."""
    __tablename__ = "transactions"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    apk_id         = Column(String, ForeignKey("apks.id"))
    victim_id      = Column(Integer, ForeignKey("victims.id"))
    amount         = Column(Float)
    currency       = Column(String, default="INR")
    txn_type       = Column(String)    # UPI | NEFT | IMPS | RTGS | CARD | ATM
    bank_name      = Column(String)
    account_last4  = Column(String)
    upi_id         = Column(String)    # destination UPI if available
    recipient_name = Column(String)    # beneficiary name if available
    txn_ref        = Column(String)    # bank reference number
    txn_date       = Column(DateTime)
    raw_sms        = Column(Text)
    created_at     = Column(DateTime, default=_now)

    apk            = relationship("Apk",    back_populates="transactions")
    victim         = relationship("Victim", back_populates="transactions")


class MonitorAlert(Base):
    """Fired by Real-Time C2 Monitor when new activity is detected."""
    __tablename__ = "monitor_alerts"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    apk_id       = Column(String, ForeignKey("apks.id"))
    alert_type   = Column(String)    # NEW_VICTIM | NEW_OTP | NEW_CREDENTIAL | ATTACKER_CHANGE
    severity     = Column(String)    # CRITICAL | HIGH | INFO
    message      = Column(Text)
    detail       = Column(JSON)      # raw diff data
    seen         = Column(Boolean, default=False)
    created_at   = Column(DateTime, default=_now)

    apk          = relationship("Apk", back_populates="alerts")


class Officer(Base):
    """Law enforcement officer / analyst account."""
    __tablename__ = "officers"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String, nullable=False)
    badge_number = Column(String, unique=True)
    designation  = Column(String)    # DSP | Inspector | SI | Analyst | Admin
    unit         = Column(String)    # TGCSB | CID | Local PS | CBI
    email        = Column(String)
    phone        = Column(String)
    # Auth
    username     = Column(String, unique=True, nullable=False)
    password_hash= Column(String)
    role         = Column(String, default="ANALYST")  # ADMIN | DSP | ANALYST | VIEWER
    is_active    = Column(Boolean, default=True)
    created_at   = Column(DateTime, default=_now)
    last_login   = Column(DateTime)

    leads        = relationship("Lead",           back_populates="officer")
    assignments  = relationship("LeadAssignment", back_populates="officer")


class LeadAssignment(Base):
    """Audit trail for lead assignments and status changes."""
    __tablename__ = "lead_assignments"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    lead_id      = Column(Integer, ForeignKey("leads.id"))
    officer_id   = Column(Integer, ForeignKey("officers.id"))
    action       = Column(String)    # ASSIGNED | STATUS_CHANGE | NOTE | CLOSED
    old_status   = Column(String)
    new_status   = Column(String)
    note         = Column(Text)
    deadline     = Column(DateTime)
    created_at   = Column(DateTime, default=_now)

    lead         = relationship("Lead",    back_populates="assignments")
    officer      = relationship("Officer", back_populates="assignments")
