"""
Real-Time C2 Monitor
Polls the active Firebase C2 backend every N seconds.
Detects: new victims, new OTPs, credential additions, attacker phone changes.
Fires MonitorAlert DB records and optionally pushes SSE events to web clients.
Runs as a background daemon thread — started per-APK from web UI or CLI.
"""

import logging
import threading
from datetime import datetime, timezone
from typing import Callable, Optional

import requests
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import FIRESTORE_BASE

log = logging.getLogger("c2_monitor")

# Global registry: apk_id → MonitorThread
_monitors: dict[str, "MonitorThread"] = {}

POLL_INTERVAL = 300   # 5 minutes default — configurable per-apk


class MonitorThread(threading.Thread):
    """
    Background thread that polls Firebase C2 and fires alerts on changes.
    One thread per monitored APK.
    """

    def __init__(self, apk_id: str, project_id: str, api_key: str,
                 interval: int = POLL_INTERVAL,
                 alert_cb: Optional[Callable] = None):
        super().__init__(daemon=True, name=f"monitor-{apk_id[:12]}")
        self.apk_id     = apk_id
        self.project_id = project_id
        self.api_key    = api_key
        self.interval   = interval
        self.alert_cb   = alert_cb   # optional callback(alert_dict)
        self._stop_evt  = threading.Event()
        self._state     = {}         # last known snapshot

    def run(self):
        log.info(f"[MONITOR] Started for {self.apk_id[:16]} | project={self.project_id} | interval={self.interval}s")
        while not self._stop_evt.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"[MONITOR] Poll error: {e}")
            self._stop_evt.wait(self.interval)
        log.info(f"[MONITOR] Stopped for {self.apk_id[:16]}")

    def stop(self):
        self._stop_evt.set()

    def _poll(self):
        from db.session import get_session
        from db.models  import Apk, MonitorAlert

        session = get_session()
        try:
            base = FIRESTORE_BASE.format(project_id=self.project_id)
            key  = self.api_key
            now  = datetime.now(timezone.utc)

            alerts = []

            # ── 1. Attacker phone check ────────────────────────────────────
            phone = self._get_attacker_phone(base, key)
            prev_phone = self._state.get("attacker_phone")
            if phone and phone != prev_phone:
                if prev_phone is not None:
                    alerts.append({
                        "alert_type": "ATTACKER_CHANGE",
                        "severity"  : "CRITICAL",
                        "message"   : f"Attacker phone changed: {prev_phone} → {phone}",
                        "detail"    : {"old": prev_phone, "new": phone},
                    })
                self._state["attacker_phone"] = phone

            # ── 2. Victim count check ──────────────────────────────────────
            victim_uids = self._list_victim_uids(base, key)
            prev_uids   = set(self._state.get("victim_uids", []))
            new_uids    = set(victim_uids) - prev_uids

            if new_uids:
                alerts.append({
                    "alert_type": "NEW_VICTIM",
                    "severity"  : "HIGH",
                    "message"   : f"{len(new_uids)} new victim(s) infected since last check",
                    "detail"    : {
                        "new_uids"   : list(new_uids),
                        "total_now"  : len(victim_uids),
                        "total_prev" : len(prev_uids),
                    },
                })
                self._state["victim_uids"] = victim_uids

            # ── 3. OTP count spot-check on last 10 victims ─────────────────
            sample_uids = victim_uids[-10:] if victim_uids else []
            new_otp_count = 0
            for uid in sample_uids:
                count = self._count_otps(base, key, uid)
                prev  = self._state.get(f"otp_{uid}", 0)
                if count > prev:
                    new_otp_count += (count - prev)
                    self._state[f"otp_{uid}"] = count

            if new_otp_count > 0:
                alerts.append({
                    "alert_type": "NEW_OTP",
                    "severity"  : "HIGH",
                    "message"   : f"{new_otp_count} new OTP(s) forwarded in last 10 active victims",
                    "detail"    : {"new_otp_count": new_otp_count},
                })

            # ── 4. Persist alerts ──────────────────────────────────────────
            for a in alerts:
                row = MonitorAlert(
                    apk_id     = self.apk_id,
                    alert_type = a["alert_type"],
                    severity   = a["severity"],
                    message    = a["message"],
                    detail     = a["detail"],
                )
                session.add(row)
                if self.alert_cb:
                    self.alert_cb(a)

            # Update last_monitored on APK row
            apk_row = session.get(Apk, self.apk_id)
            if apk_row:
                apk_row.last_monitored = now

            session.commit()
            log.info(f"[MONITOR] Poll done — {len(alerts)} alert(s) fired — victims={len(victim_uids)}")

        finally:
            session.close()

    def _get_attacker_phone(self, base: str, key: str) -> Optional[str]:
        try:
            r = requests.get(f"{base}/admin/number", params={"key": key}, timeout=15)
            if r.status_code == 200:
                fields = r.json().get("fields", {})
                for fname in ("phone", "number", "Phone", "Number"):
                    if fname in fields:
                        return _extract_str(fields[fname])
        except Exception:
            pass
        return None

    def _list_victim_uids(self, base: str, key: str) -> list:
        uids = []
        page_token = None
        while True:
            params = {"key": key, "pageSize": 300}
            if page_token:
                params["pageToken"] = page_token
            try:
                r = requests.get(f"{base}/devices", params=params, timeout=30)
                data = r.json()
            except Exception:
                break
            for doc in data.get("documents", []):
                uids.append(doc["name"].split("/")[-1])
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        return uids

    def _count_otps(self, base: str, key: str, uid: str) -> int:
        try:
            r = requests.get(
                f"{base}/devices/{uid}/otps",
                params={"key": key, "pageSize": 1, "showMissing": "false"},
                timeout=10
            )
            data = r.json()
            return len(data.get("documents", []))
        except Exception:
            return 0


def _extract_str(field_val: dict) -> str:
    for k in ("stringValue", "integerValue", "doubleValue"):
        if k in field_val:
            return str(field_val[k])
    return ""


# ── Public API ─────────────────────────────────────────────────────────────────

def start(apk_id: str, project_id: str, api_key: str,
          interval: int = POLL_INTERVAL,
          alert_cb: Optional[Callable] = None) -> MonitorThread:
    """Start monitoring an APK's C2. Idempotent — safe to call twice."""
    if apk_id in _monitors and _monitors[apk_id].is_alive():
        log.warning(f"[MONITOR] Already running for {apk_id[:16]}")
        return _monitors[apk_id]

    t = MonitorThread(apk_id, project_id, api_key, interval, alert_cb)
    t.start()
    _monitors[apk_id] = t

    # Mark APK as monitored in DB
    from db.session import get_session
    from db.models  import Apk
    s = get_session()
    try:
        row = s.get(Apk, apk_id)
        if row:
            row.monitor_active = True
            s.commit()
    finally:
        s.close()

    return t


def stop(apk_id: str):
    """Stop monitoring an APK."""
    t = _monitors.pop(apk_id, None)
    if t:
        t.stop()
    from db.session import get_session
    from db.models  import Apk
    s = get_session()
    try:
        row = s.get(Apk, apk_id)
        if row:
            row.monitor_active = False
            s.commit()
    finally:
        s.close()


def list_active() -> list:
    return [apk_id for apk_id, t in _monitors.items() if t.is_alive()]


def get_alerts(apk_id: str, unseen_only: bool = False, limit: int = 50) -> list:
    from db.session import get_session
    from db.models  import MonitorAlert
    s = get_session()
    try:
        q = s.query(MonitorAlert).filter_by(apk_id=apk_id)
        if unseen_only:
            q = q.filter_by(seen=False)
        rows = q.order_by(MonitorAlert.created_at.desc()).limit(limit).all()
        result = []
        for r in rows:
            result.append({
                "id"        : r.id,
                "alert_type": r.alert_type,
                "severity"  : r.severity,
                "message"   : r.message,
                "detail"    : r.detail,
                "seen"      : r.seen,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            })
        return result
    finally:
        s.close()


def mark_seen(alert_id: int):
    from db.session import get_session
    from db.models  import MonitorAlert
    s = get_session()
    try:
        row = s.get(MonitorAlert, alert_id)
        if row:
            row.seen = True
            s.commit()
    finally:
        s.close()
