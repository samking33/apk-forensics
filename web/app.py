"""
TGCSB APK Analyser — Web Interface
FastAPI + Jinja2 templates

Run: python web/app.py
     (or: uvicorn web.app:app --host 0.0.0.0 --port 8888 --reload)
"""

import os
import sys
import uuid
import threading
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, PlainTextResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

from db.session import init_db, get_session
from db.models  import Apk, Finding, IoC, Victim, Lead, MonitorAlert, Transaction
from config     import EVIDENCE_DIR
from core.intelligence.cross_apk    import correlate as run_correlate
from core.intelligence              import financial_quantum, money_flow, geo_map
from core.monitor                   import c2_monitor
from reporting                      import evidence_pack

# ── App setup ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app):
    init_db()
    yield

app       = FastAPI(title="TGCSB APK Analyser", docs_url=None, redoc_url=None, lifespan=lifespan)
WEB_DIR   = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(WEB_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(WEB_DIR, "static")), name="static")

UPLOAD_TMP = os.path.join(WEB_DIR, "uploads")
os.makedirs(UPLOAD_TMP, exist_ok=True)

# In-memory job store {job_id: {status, log, apk_id, error}}
jobs: dict[str, dict] = {}


# ── Pages ─────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    session = get_session()
    try:
        apks = session.query(Apk).order_by(Apk.analysed_at.desc()).all()
        # attach lead counts
        for a in apks:
            a.lead_count = session.query(Lead).filter_by(apk_id=a.id).count()

        stats = {
            "total"           : len(apks),
            "victims"         : sum(a.victim_count or 0 for a in apks),
            "otps"            : sum(a.otp_count or 0 for a in apks),
            "leads"           : sum(a.lead_count for a in apks),
            "high_risk"       : sum(1 for a in apks if (a.risk_score or 0) >= 70),
            "firebase_projects": len(set(a.firebase_project for a in apks if a.firebase_project)),
        }
        return templates.TemplateResponse(request, "dashboard.html", {
            "apks": apks, "stats": stats, "active": "dashboard"
        })
    finally:
        session.close()


@app.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request):
    return templates.TemplateResponse(request, "upload.html", {"active": "static"})


# ── Unified analysis workspace (one agent, one chat, two modes) ───────────────
# Static and Dynamic are the same agent chat (shared session via a persistent
# client id); Dynamic adds the live sandbox mirror. /agent kept as an alias.

AGENT_UPLOAD_DIR = os.path.join(WEB_DIR, "uploads", "agent")
os.makedirs(AGENT_UPLOAD_DIR, exist_ok=True)


@app.get("/static-analysis", response_class=HTMLResponse)
def static_analysis_page(request: Request):
    return templates.TemplateResponse(request, "agent.html", {
        "active": "static", "dynamic_mode": False,
        "page_title": "Static Analysis",
        "page_subtitle": "Agent-driven deep static analysis · decompile · behaviours · IOCs",
    })


@app.get("/agent")
def agent_page():
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/static-analysis")


@app.get("/dynamic-analysis", response_class=HTMLResponse)
def dynamic_analysis_page(request: Request):
    return templates.TemplateResponse(request, "agent.html", {
        "active": "dynamic", "dynamic_mode": True,
        "page_title": "Dynamic Analysis",
        "page_subtitle": "Agent-driven sandbox detonation · live emulator mirror · behavioural evidence",
    })


_SESSION_APK: dict = {}   # agent sid -> apk sha256 (= Apk.id), for the results panel


@app.post("/api/agent/upload")
async def agent_upload(sid: str = Form(...), file: UploadFile = File(...)):
    from core.agent import claude_cli
    from core.static.apk_parser import sha256_file
    safe = os.path.basename(file.filename or "sample.apk")
    # Save into the agent's working directory so it can reach the APK by name.
    path = os.path.join(claude_cli.workspace(sid), safe)
    with open(path, "wb") as f:
        f.write(await file.read())
    try:
        _SESSION_APK[sid] = sha256_file(path)   # = Apk.id once the engine runs
    except OSError:
        pass
    return JSONResponse({"path": path, "name": safe, "apk_id": _SESSION_APK.get(sid)})


@app.get("/api/agent/analysis")
def agent_analysis(sid: str):
    """Structured static results for the session's APK — polled by the Static tab.
    Falls back to the most recently analysed sample if the session has none yet."""
    session = get_session()
    try:
        apk = None
        if _SESSION_APK.get(sid):
            apk = session.get(Apk, _SESSION_APK[sid])
        if not apk:
            apk = session.query(Apk).order_by(Apk.analysed_at.desc()).first()
        if not apk or not apk.static_done:
            return JSONResponse({"analyzed": False})

        findings = session.query(Finding).filter_by(apk_id=apk.id).all()
        iocs     = session.query(IoC).filter_by(apk_id=apk.id).all()
        sev: dict = {}
        for f in findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        findings.sort(key=lambda f: order.index(f.severity) if f.severity in order else 9)
        r = apk.risk_score or 0
        return JSONResponse({
            "analyzed": True, "apk_id": apk.id, "filename": apk.filename,
            "package": apk.package_name, "risk": r,
            "level": "CRITICAL" if r >= 70 else "HIGH" if r >= 40 else "MEDIUM" if r >= 20 else "LOW",
            "behaviors": apk.behaviors or [], "malware_tags": apk.malware_tags or [],
            "c2": apk.c2_detail or [], "cert_schemes": apk.cert_schemes,
            "sev_counts": sev,
            "findings": [{"severity": f.severity, "category": f.category, "title": f.title}
                         for f in findings[:14]],
            "iocs": [{"type": i.ioc_type, "value": i.value} for i in iocs[:14]],
            "case_url": f"/case/{apk.id}",
        })
    finally:
        session.close()


# ── Full Records — faithful, unmasked, schema-agnostic victim data (court) ─────
# Renders 100% of what the C2 probe pulled, straight from the evidence dump, with
# NO masking and columns/sections derived from whatever fields each APK's backend
# actually returned. Deterministic on purpose: court evidence must be an exact,
# complete copy — not an LLM's interpretation.

import json as _json_mod

_DUMP_CACHE: dict = {}


def _load_victim_dump(project: str):
    """Return (victims_list, uid_index), cached by file mtime."""
    path = os.path.join(EVIDENCE_DIR, project, "full_victim_dump.json")
    if not os.path.exists(path):
        return [], {}
    mtime = os.path.getmtime(path)
    cached = _DUMP_CACHE.get(path)
    if cached and cached[0] == mtime:
        return cached[1], cached[2]
    with open(path, encoding="utf-8") as f:
        data = _json_mod.load(f)
    by_uid = {v.get("uid"): v for v in data if isinstance(v, dict)}
    _DUMP_CACHE[path] = (mtime, data, by_uid)
    return data, by_uid


def _cred_find(creds, key):
    """First value of `key` anywhere in the nested credentials structure."""
    if isinstance(creds, dict):
        for k, v in creds.items():
            if k == key and not isinstance(v, (dict, list)):
                return v
            found = _cred_find(v, key)
            if found is not None:
                return found
    elif isinstance(creds, list):
        for item in creds:
            found = _cred_find(item, key)
            if found is not None:
                return found
    return None


@app.get("/case/{apk_id}/records", response_class=HTMLResponse)
def case_records(request: Request, apk_id: str):
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")
        project = apk.firebase_project
    finally:
        session.close()

    victims, _ = _load_victim_dump(project) if project else ([], {})
    index = []
    for v in victims:
        creds = v.get("credentials")
        index.append({
            "uid"    : v.get("uid"),
            "name"   : _cred_find(creds, "full_name") or "—",
            "mobile" : _cred_find(creds, "mobile") or "—",
            "device" : f"{v.get('manufacturer', '')} {v.get('model', '')}".strip() or "—",
            "otps"   : len(v.get("otps", []) or []),
            "sims"   : len(v.get("sims", []) or []),
            "online" : v.get("online"),
        })
    return templates.TemplateResponse(request, "records.html", {
        "apk": apk, "project": project, "index": index, "total": len(victims),
        "active": "dashboard",
    })


@app.get("/api/case/{apk_id}/victim/{uid}")
def api_victim_record(apk_id: str, uid: str):
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")
        project = apk.firebase_project
    finally:
        session.close()
    _, by_uid = _load_victim_dump(project) if project else ([], {})
    rec = by_uid.get(uid)
    if rec is None:
        raise HTTPException(status_code=404, detail="Victim record not found")
    return JSONResponse(rec)   # complete, unmasked


# ── Investigation Canvas — freeform case-data workbench ────────────────────────
# A fixed catalog of real, case-backed objects (no arbitrary query/formula
# builder — that has no equivalent in our data model). Each object declares a
# render `kind`; the frontend has one renderer per kind and dispatches on it,
# so adding a new object never touches the renderer code.

_CANVAS_CATALOG = [
    {"key": "victims",     "code": "VIC", "label": "Victims",              "icon": "fa-users",              "color": "danger",  "deps": []},
    {"key": "otp_timeline","code": "OTP", "label": "OTP Timeline",         "icon": "fa-comment-sms",        "color": "warning", "deps": ["victims"]},
    {"key": "otp_heatmap", "code": "HMA", "label": "OTP Activity Heatmap", "icon": "fa-table-cells",        "color": "purple",  "deps": ["victims"]},
    {"key": "transactions","code": "TXN", "label": "Transactions",         "icon": "fa-money-bill-transfer","color": "success", "deps": ["victims"]},
    {"key": "findings",    "code": "FND", "label": "Findings by Severity", "icon": "fa-triangle-exclamation","color": "danger",  "deps": []},
    {"key": "behaviors",   "code": "BEH", "label": "Behaviours Detected",  "icon": "fa-shield-virus",       "color": "danger",  "deps": []},
    {"key": "geo",         "code": "GEO", "label": "Geo Distribution",     "icon": "fa-map",                "color": "info",    "deps": ["victims"]},
    {"key": "c2_events",   "code": "C2E", "label": "C2 Events",            "icon": "fa-tower-broadcast",    "color": "teal",    "deps": []},
    {"key": "risk",        "code": "RSK", "label": "Risk Breakdown",       "icon": "fa-gauge-high",         "color": "warning", "deps": []},
]


@app.get("/case/{apk_id}/canvas", response_class=HTMLResponse)
def case_canvas(request: Request, apk_id: str):
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")
    finally:
        session.close()
    return templates.TemplateResponse(request, "canvas.html", {
        "apk": apk, "catalog": _CANVAS_CATALOG, "active": "dashboard",
    })


@app.get("/api/canvas/{apk_id}/objects")
def api_canvas_objects(apk_id: str):
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")
        counts = {
            "victims": session.query(Victim).filter_by(apk_id=apk.id).count(),
            "transactions": session.query(Transaction).filter_by(apk_id=apk.id).count(),
            "findings": session.query(Finding).filter_by(apk_id=apk.id).count(),
            "c2_events": session.query(MonitorAlert).filter_by(apk_id=apk.id).count(),
            "behaviors": len(apk.behaviors or []),
            "risk": len(apk.risk_breakdown or []),
        }
    finally:
        session.close()
    objs = []
    for o in _CANVAS_CATALOG:
        row = dict(o)
        if o["key"] in counts:
            row["count"] = counts[o["key"]]
        objs.append(row)
    return JSONResponse({"objects": objs})


def _bucket_otps(victims: list[dict]) -> list[dict]:
    """All OTP events across every victim's dump, flattened and timestamped."""
    events = []
    for v in victims:
        for o in (v.get("otps") or []):
            ts = o.get("timestamp")
            if ts:
                events.append({"ts": int(ts), "sender": o.get("sender", "")})
    events.sort(key=lambda e: e["ts"])
    return events


@app.get("/api/canvas/{apk_id}/data/{object_key}")
def api_canvas_data(apk_id: str, object_key: str):
    import datetime as _dt
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")

        if object_key == "victims":
            rows = session.query(Victim).filter_by(apk_id=apk.id).all()
            return JSONResponse({"kind": "table",
                "stat": {"value": len(rows), "label": "Victims"},
                "columns": ["Name", "Mobile", "Bank", "Risk", "OTPs"],
                "rows": [[v.full_name or "—", v.mobile or "—", v.bank_name or "—",
                          v.risk_level or "—", v.otp_count or 0] for v in rows[:500]]})

        if object_key in ("otp_timeline", "otp_heatmap"):
            victims, _ = _load_victim_dump(apk.firebase_project) if apk.firebase_project else ([], {})
            events = _bucket_otps(victims)
            if object_key == "otp_timeline":
                buckets: dict[str, int] = {}
                for e in events:
                    day = _dt.datetime.utcfromtimestamp(e["ts"] / 1000).strftime("%Y-%m-%d")
                    buckets[day] = buckets.get(day, 0) + 1
                points = [{"t": k, "v": v} for k, v in sorted(buckets.items())]
                return JSONResponse({"kind": "timeseries", "points": points,
                                     "stat": {"value": len(events), "label": "OTPs intercepted"}})
            grid = [[0] * 7 for _ in range(24)]
            for e in events:
                d = _dt.datetime.utcfromtimestamp(e["ts"] / 1000)
                grid[d.hour][d.weekday()] += 1
            return JSONResponse({"kind": "heatmap", "rows": list(range(24)),
                                 "cols": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], "matrix": grid})

        if object_key == "transactions":
            rows = session.query(Transaction).filter_by(apk_id=apk.id).order_by(Transaction.txn_date).all()
            buckets: dict[str, float] = {}
            total = 0.0
            for t in rows:
                if t.txn_date:
                    day = t.txn_date.strftime("%Y-%m-%d")
                    buckets[day] = buckets.get(day, 0.0) + (t.amount or 0.0)
                total += t.amount or 0.0
            points = [{"t": k, "v": round(v, 2)} for k, v in sorted(buckets.items())]
            return JSONResponse({"kind": "timeseries", "points": points,
                                 "stat": {"value": f"₹{total:,.0f}", "label": "Total loss"}})

        if object_key == "findings":
            rows = session.query(Finding).filter_by(apk_id=apk.id).all()
            order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            colors = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "success", "INFO": "dim"}
            counts: dict[str, int] = {}
            for f in rows:
                counts[f.severity] = counts.get(f.severity, 0) + 1
            bars = [{"label": s, "value": counts[s], "color": colors.get(s, "dim")}
                   for s in order if counts.get(s)]
            return JSONResponse({"kind": "bar", "bars": bars})

        if object_key == "behaviors":
            return JSONResponse({"kind": "chips", "items": apk.behaviors or []})

        if object_key == "geo":
            rows = (session.query(Victim.state, Victim.id).filter_by(apk_id=apk.id)
                   .filter(Victim.state.isnot(None)).all())
            counts: dict[str, int] = {}
            for state, _id in rows:
                counts[state] = counts.get(state, 0) + 1
            bars = [{"label": k, "value": v} for k, v in
                    sorted(counts.items(), key=lambda x: -x[1])[:15]]
            return JSONResponse({"kind": "bar", "bars": bars})

        if object_key == "c2_events":
            rows = session.query(MonitorAlert).filter_by(apk_id=apk.id).order_by(MonitorAlert.created_at).all()
            colors = {"CRITICAL": "danger", "HIGH": "warning", "INFO": "info"}
            counts: dict[str, int] = {}
            for a in rows:
                counts[a.alert_type] = counts.get(a.alert_type, 0) + 1
            bars = [{"label": k, "value": v} for k, v in
                    sorted(counts.items(), key=lambda x: -x[1])]
            return JSONResponse({"kind": "bar", "bars": bars,
                                 "stat": {"value": len(rows), "label": "C2 events"}})

        if object_key == "risk":
            breakdown = apk.risk_breakdown or []
            bars = [{"label": b.get("factor", "?"), "value": b.get("points", 0), "color": "warning"}
                   for b in breakdown]
            return JSONResponse({"kind": "bar", "bars": bars,
                                 "stat": {"value": apk.risk_score or 0, "label": "Risk score"}})

        raise HTTPException(status_code=404, detail=f"Unknown canvas object: {object_key}")
    finally:
        session.close()


@app.post("/api/agent/message")
def agent_message(sid: str = Form(...), message: str = Form(...)):
    # Enqueue and return immediately — the run is durable server-side; the browser
    # receives events over the separate /api/agent/stream connection.
    from core.agent import claude_cli
    claude_cli.post_message(sid, message)
    return JSONResponse({"ok": True})


@app.get("/api/agent/stream")
async def agent_stream(sid: str, from_index: int = 0):
    # Async so each open stream costs ZERO threadpool threads (a sync generator
    # held one thread per connection forever, starving the mirror polls and
    # freezing the UI). On disconnect the async gen is cancelled promptly.
    import asyncio
    import json as _json
    from fastapi.responses import StreamingResponse
    from core.agent import claude_cli

    sess = claude_cli._session(sid)

    async def gen():
        i = from_index
        idle = 0
        while True:
            events = sess["events"]
            if i < len(events):
                yield f"data: {_json.dumps(events[i])}\n\n"
                i += 1
                idle = 0
            else:
                idle += 1
                if idle >= 10:      # ~3s heartbeat keeps the connection detectable
                    yield f"data: {_json.dumps({'type': 'heartbeat', 'index': i})}\n\n"
                    idle = 0
                await asyncio.sleep(0.3)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/agent/reset")
def agent_reset(sid: str = Form(...)):
    from core.agent import claude_cli
    claude_cli.reset(sid)
    return JSONResponse({"ok": True})


# ── Live sandbox mirror (Dynamic Analysis) ────────────────────────────────────

_REPO_ROOT = os.path.dirname(WEB_DIR)


def _screencap() -> bytes | None:
    try:
        r = subprocess.run(["adb", "exec-out", "screencap", "-p"],
                           capture_output=True, timeout=15)
        if r.returncode == 0 and r.stdout[:8] == b"\x89PNG\r\n\x1a\n":
            return r.stdout
    except (subprocess.SubprocessError, OSError):
        pass
    return None


@app.get("/api/sandbox/screen")
async def sandbox_screen():
    """Current emulator screen as PNG for the live mirror. 204 if no device."""
    import asyncio
    data = await asyncio.to_thread(_screencap)
    if data:
        return Response(content=data, media_type="image/png",
                        headers={"Cache-Control": "no-store"})
    return Response(status_code=204)


def _sandbox_state() -> dict:
    from core.sandbox import sandbox_ctl
    online = sandbox_ctl._serial_online()
    frida = False
    if online:
        try:
            chk = subprocess.run(["adb", "shell", "pgrep", "-f", "frida-server"],
                                 capture_output=True, text=True, timeout=8)
            frida = bool(chk.stdout.strip())
        except (subprocess.SubprocessError, OSError):
            pass
    return {"booted": online, "frida": frida}


@app.get("/api/sandbox/status")
async def sandbox_status():
    import asyncio
    return JSONResponse(await asyncio.to_thread(_sandbox_state))


@app.post("/api/sandbox/boot")
def sandbox_boot():
    # Detached — boot takes minutes; the UI polls /status until ready.
    subprocess.Popen([sys.executable, "-m", "core.sandbox.sandbox_ctl", "boot"],
                     cwd=_REPO_ROOT, env=dict(os.environ, PYTHONPATH=_REPO_ROOT),
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return JSONResponse({"starting": True})


@app.post("/api/sandbox/stop")
def sandbox_stop():
    subprocess.run(["adb", "emu", "kill"], capture_output=True, timeout=15)
    return JSONResponse({"stopped": True})


@app.get("/case/{apk_id}", response_class=HTMLResponse)
def case_detail(request: Request, apk_id: str):
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")

        findings = session.query(Finding).filter_by(apk_id=apk.id).all()
        iocs     = session.query(IoC    ).filter_by(apk_id=apk.id).all()
        victims  = session.query(Victim ).filter_by(apk_id=apk.id).order_by(Victim.risk_level).all()
        leads    = session.query(Lead   ).filter_by(apk_id=apk.id).order_by(Lead.priority, Lead.victim_count.desc()).all()
        txns     = session.query(Transaction ).filter_by(apk_id=apk.id).all()
        alerts   = session.query(MonitorAlert).filter_by(apk_id=apk.id).all()

        victim_stats = {
            "CRITICAL": sum(1 for v in victims if v.risk_level == "CRITICAL"),
            "HIGH"    : sum(1 for v in victims if v.risk_level == "HIGH"),
            "MEDIUM"  : sum(1 for v in victims if v.risk_level == "MEDIUM"),
            "LOW"     : sum(1 for v in victims if v.risk_level == "LOW"),
        }

        # Findings grouped by category for the tabbed UI.
        by_cat: dict = {}
        for f in findings:
            by_cat.setdefault(f.category or "OTHER", []).append(f)

        # Threat-actor clusters that include this sample (shared C2/cert/phone).
        from core.intelligence import actor_graph
        clusters = [c for c in actor_graph.analyse(session)
                    if apk.id in c["apk_ids"] and c["size"] > 1]

        # Campaign timeline from all dated evidence.
        from reporting import timeline as tl
        events = tl.reconstruct(
            analysed_at=apk.analysed_at,
            victims=[{"id": v.id, "mobile": v.mobile, "full_name": v.full_name,
                      "infected_at": v.infected_at, "last_seen": v.last_seen} for v in victims],
            transactions=[{"amount": t.amount, "upi_id": t.upi_id,
                           "recipient_name": t.recipient_name, "txn_date": t.txn_date} for t in txns],
            alerts=[{"alert_type": a.alert_type, "message": a.message,
                     "created_at": a.created_at} for a in alerts],
        )

        return templates.TemplateResponse(request, "case.html", {
            "apk"         : apk,
            "findings"    : findings,
            "by_cat"      : by_cat,
            "iocs"        : iocs,
            "victims"     : victims,
            "leads"       : leads,
            "victim_stats": victim_stats,
            "clusters"    : clusters,
            "timeline"    : events,
            "active"      : "dashboard",
        })
    finally:
        session.close()


@app.get("/case/{apk_id}/report", response_class=HTMLResponse)
def reports_page(request: Request, apk_id: str):
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")

        findings = session.query(Finding).filter_by(apk_id=apk.id).all()
        iocs     = session.query(IoC    ).filter_by(apk_id=apk.id).all()
        victims  = session.query(Victim ).filter_by(apk_id=apk.id).all()
        leads    = session.query(Lead   ).filter_by(apk_id=apk.id).all()

        out_dir = os.path.join(EVIDENCE_DIR, apk.id[:16])
        os.makedirs(out_dir, exist_ok=True)

        from reporting.forensic_report import generate as gen_forensic
        from reporting.victim_register import generate as gen_victims
        from reporting.leads_report    import generate as gen_leads

        reports = []
        p = gen_forensic(apk, findings, iocs, victims, leads, out_dir)
        reports.append({"name": "Forensic Report (Section 65B)", "file": os.path.basename(p)})

        if victims:
            p2, p3 = gen_victims(victims, apk.id, out_dir)
            reports.append({"name": "Victim Register (TXT)", "file": os.path.basename(p2)})
            reports.append({"name": "Victim Register (CSV)", "file": os.path.basename(p3)})

        if leads:
            p4 = gen_leads(apk, leads, victims, out_dir)
            reports.append({"name": "Criminal Leads Report", "file": os.path.basename(p4)})

        return templates.TemplateResponse(request, "reports.html", {
            "apk"    : apk,
            "reports": reports,
            "active" : "dashboard",
        })
    finally:
        session.close()


def _db_result(apk, findings, iocs) -> dict:
    """Assemble a static-engine-style result dict from persisted rows, so the
    reporting modules (scorecard/STIX) can render straight from the DB."""
    return {
        "apk_meta": {
            "package_name": apk.package_name, "filename": apk.filename,
            "version_name": apk.version_name, "target_sdk": apk.target_sdk,
            "cert_sha256": apk.cert_sha256, "malware_tags": apk.malware_tags or [],
        },
        "risk_score": apk.risk_score or 0,
        "risk_detail": {"level": ("CRITICAL" if (apk.risk_score or 0) >= 70 else
                                  "HIGH" if (apk.risk_score or 0) >= 40 else
                                  "MEDIUM" if (apk.risk_score or 0) >= 20 else "LOW"),
                        "breakdown": apk.risk_breakdown or []},
        "behavior": {"behaviors": apk.behaviors or [], "c2_channels": apk.c2_detail or []},
        "findings": [{"severity": f.severity, "category": f.category, "title": f.title,
                      "detail": f.detail, "found_at": f.found_at} for f in findings],
        "cert_info": {"subject": apk.cert_subject, "cert_sha256": apk.cert_sha256,
                      "schemes": (apk.cert_schemes or "").split("+") if apk.cert_schemes else [],
                      "self_signed": None, "hash_algo": None,
                      "not_before": None, "not_after": None},
        "trackers": [], "libraries": [],
    }


def _load_case(session, apk_id):
    apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
    if not apk:
        raise HTTPException(status_code=404, detail="APK not found")
    findings = session.query(Finding).filter_by(apk_id=apk.id).all()
    iocs     = session.query(IoC).filter_by(apk_id=apk.id).all()
    return apk, findings, iocs


@app.get("/case/{apk_id}/scorecard", response_class=HTMLResponse)
def case_scorecard(apk_id: str):
    session = get_session()
    try:
        apk, findings, iocs = _load_case(session, apk_id)
        from reporting.scorecard import generate
        return HTMLResponse(generate(_db_result(apk, findings, iocs), apk.id))
    finally:
        session.close()


@app.get("/case/{apk_id}/65b", response_class=PlainTextResponse)
def case_65b(apk_id: str):
    session = get_session()
    try:
        apk, findings, iocs = _load_case(session, apk_id)
        from reporting.section65b import generate
        return PlainTextResponse(generate(_db_result(apk, findings, iocs)["apk_meta"],
                                          apk.id, case_ref=apk.case_id or ""))
    finally:
        session.close()


@app.get("/case/{apk_id}/stix")
def case_stix(apk_id: str):
    session = get_session()
    try:
        apk, findings, iocs = _load_case(session, apk_id)
        from reporting.stix_export import build_bundle
        bundle = build_bundle(_db_result(apk, findings, iocs)["apk_meta"], apk.id,
                              [{"ioc_type": i.ioc_type, "value": i.value,
                                "description": i.description} for i in iocs],
                              behaviors=apk.behaviors or [])
        return JSONResponse(bundle, headers={
            "Content-Disposition": f'attachment; filename="stix_{apk.id[:16]}.json"'})
    finally:
        session.close()


@app.get("/download/{apk_prefix}/{filename}")
def download_file(apk_prefix: str, filename: str):
    safe = os.path.basename(filename)
    path = os.path.join(EVIDENCE_DIR, apk_prefix, safe)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path, filename=safe, media_type="application/octet-stream")


@app.get("/correlate", response_class=HTMLResponse)
def correlate_page(request: Request):
    session = get_session()
    try:
        groups = run_correlate(session)
        return templates.TemplateResponse(request, "correlate.html", {
            "groups": groups, "active": "correlate"
        })
    finally:
        session.close()


# ── API ───────────────────────────────────────────────────────────────────────
@app.post("/api/upload")
async def api_upload(
    file:             UploadFile = File(...),
    case_id:          str = Form(""),
    firebase_project: str = Form(""),
    firebase_key:     str = Form(""),
    static_only:      str = Form("0"),
):
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files accepted")

    job_id  = str(uuid.uuid4())[:8]
    tmp_path = os.path.join(UPLOAD_TMP, f"{job_id}_{file.filename}")

    content = await file.read()
    with open(tmp_path, "wb") as f:
        f.write(content)

    jobs[job_id] = {"status": "queued", "log": [], "apk_id": None, "error": None}

    thread = threading.Thread(
        target=_run_analysis,
        args=(job_id, tmp_path, case_id.strip() or None,
              firebase_project.strip() or None,
              firebase_key.strip() or None,
              static_only == "1"),
        daemon=True
    )
    thread.start()

    return JSONResponse({"job_id": job_id})


@app.get("/api/job/{job_id}")
def api_job_status(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return JSONResponse(jobs[job_id])


# ── Victim Rescue — Firebase C2 victim extraction ─────────────────────────────
# Once static analysis recovers a sample's Firebase C2 credentials, we probe the
# attacker's (misconfigured) backend to enumerate the victims they are harvesting,
# so those people can be alerted before they are defrauded.

@app.get("/victims", response_class=HTMLResponse)
def victims_page(request: Request):
    session = get_session()
    try:
        c2_apks = (session.query(Apk)
                   .filter(Apk.firebase_project.isnot(None))
                   .order_by(Apk.victim_count.desc().nullslast()).all())
        stats = {
            "sources"  : len(c2_apks),
            "extracted": sum(1 for a in c2_apks if a.dynamic_done),
            "victims"  : sum(a.victim_count or 0 for a in c2_apks),
            "otps"     : sum(a.otp_count or 0 for a in c2_apks),
            "loss"     : sum(a.total_loss_inr or 0 for a in c2_apks),
        }
        return templates.TemplateResponse(request, "victims.html", {
            "active": "victims", "c2_apks": c2_apks, "stats": stats,
        })
    finally:
        session.close()


def _start_extraction(apk_id: str, project: str, api_key: str) -> str:
    """Kick off a background Firebase extraction job with live progress. Shared by
    the per-APK and manual-entry paths. Returns the job id."""
    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {"status": "running", "apk_id": apk_id, "victims": 0,
                    "phase": "Starting", "current": 0, "total": 0, "error": None}

    def _run():
        s = get_session()
        try:
            from core.dynamic import engine as dyn
            dyn.run(project, api_key, apk_id, s, progress=lambda d: jobs[job_id].update(d))
            row = s.get(Apk, apk_id)
            jobs[job_id]["victims"] = (row.victim_count or 0) if row else 0
            jobs[job_id]["status"] = "done"
        except Exception as e:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = str(e)
        finally:
            s.close()

    threading.Thread(target=_run, daemon=True).start()
    return job_id


@app.post("/api/victims/extract/{apk_id}")
def api_extract_victims(apk_id: str):
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")
        if not (apk.firebase_project and apk.firebase_api_key):
            raise HTTPException(status_code=400, detail="No Firebase C2 credentials on this sample")
        full_id, proj, key = apk.id, apk.firebase_project, apk.firebase_api_key
    finally:
        session.close()
    return JSONResponse({"job_id": _start_extraction(full_id, proj, key)})


@app.post("/api/victims/manual")
def api_victims_manual(project_id: str = Form(...), api_key: str = Form(...)):
    """Probe a Firebase C2 from manually-entered credentials (e.g. from prior
    investigations). Registers a lightweight case so results flow into records,
    financial, geo-map and monitor like any other sample."""
    project_id, api_key = project_id.strip(), api_key.strip()
    if not project_id or not api_key:
        raise HTTPException(status_code=400, detail="Both project ID and API key are required")

    apk_id = f"manual-{project_id}"
    session = get_session()
    try:
        apk = session.get(Apk, apk_id)
        if not apk:
            session.add(Apk(id=apk_id, filename=f"Manual C2 · {project_id}",
                            package_name="(manual C2 entry)", firebase_project=project_id,
                            firebase_api_key=api_key, static_done=True, risk_score=0))
        else:
            apk.firebase_api_key = api_key
        session.commit()
    finally:
        session.close()
    return JSONResponse({"job_id": _start_extraction(apk_id, project_id, api_key),
                         "apk_id": apk_id})


@app.post("/api/victims/telegram")
def api_telegram_probe(token: str = Form(...), chat_id: str = Form("")):
    """Attacker attribution via a recovered Telegram exfil-bot token (from
    static analysis or a prior report). Read-only Bot API calls."""
    from core.dynamic.telegram_probe import probe
    token = token.strip()
    if not token:
        raise HTTPException(status_code=400, detail="Bot token is required")
    return JSONResponse(probe(token, chat_id.strip() or None))


@app.post("/api/victims/infra")
def api_infra_pivot(domains: str = Form(...)):
    """Cluster custom (non-Firebase) C2 domains by shared hosting infrastructure."""
    from core.intelligence.infra_pivot import analyse
    domain_list = [d.strip() for d in domains.replace(",", "\n").splitlines() if d.strip()]
    if not domain_list:
        raise HTTPException(status_code=400, detail="Provide at least one domain")
    return JSONResponse(analyse(domain_list[:30]))


# ── Background analysis runner ────────────────────────────────────────────────
def _run_analysis(job_id: str, apk_path: str, case_id, fb_project, fb_key, static_only: bool):
    job = jobs[job_id]
    job["status"] = "running"

    def log(msg: str):
        job["log"].append(msg)

    try:
        from db.session           import get_session
        from core.static.engine   import run as static_run
        from core.dynamic.engine  import run as dynamic_run

        session = get_session()

        log("[INFO] Starting static analysis...")
        sr = static_run(apk_path, case_id=case_id, db_session=session)
        apk_id = sr["apk_meta"]["sha256"]
        job["apk_id"] = apk_id

        log(f"[INFO] Package    : {sr['apk_meta'].get('package_name','?')}")
        log(f"[INFO] Risk score : {sr['risk_score']}/100")
        log(f"[INFO] IoCs found : {len(sr['iocs'])}")
        log(f"[INFO] Findings   : {len(sr['findings'])}")

        fb_proj = fb_project or sr["firebase"].get("firebase_project")
        fb_api  = fb_key     or sr["firebase"].get("firebase_api_key")

        if fb_proj:
            log(f"[INFO] Firebase project: {fb_proj}")
        else:
            log("[WARN] No Firebase project detected")

        if fb_proj and fb_api and not static_only:
            # Update DB with overrides if supplied
            if fb_project or fb_key:
                from db.models import Apk
                row = session.get(Apk, apk_id)
                if row:
                    if fb_project: row.firebase_project = fb_project
                    if fb_key:     row.firebase_api_key = fb_key
                    session.commit()

            log("[INFO] Starting dynamic analysis (Firebase probe)...")
            dr = dynamic_run(fb_proj, fb_api, apk_id=apk_id, db_session=session)

            phone = dr.get("attacker_phone")
            if phone:
                log(f"[CRIT] ATTACKER PHONE: {phone}")

            log(f"[INFO] Victims extracted  : {dr.get('victim_count', 0)}")
            log(f"[INFO] OTPs stolen        : {dr.get('otp_count', 0):,}")
            log(f"[INFO] Criminal leads     : {len(dr.get('leads', []))}")
        elif static_only:
            log("[INFO] Static-only mode — skipping Firebase probe")
        else:
            log("[WARN] No Firebase credentials — skipping dynamic analysis")
            log("[WARN] Re-upload with --firebase-project and --firebase-key to enable")

        log("[INFO] Generating reports...")
        _generate_reports(apk_id, session)
        log("[INFO] ✓ All reports generated")

        session.close()

        # Cleanup temp file
        try: os.remove(apk_path)
        except Exception: pass

        log("[INFO] Analysis complete!")
        job["status"] = "done"

    except Exception as e:
        import traceback
        job["log"].append(f"[CRIT] ERROR: {e}")
        job["log"].append(traceback.format_exc())
        job["status"] = "error"
        job["error"]  = str(e)
        try: os.remove(apk_path)
        except Exception: pass


def _generate_reports(apk_id: str, session):
    from db.models import Apk, Finding, IoC, Victim, Lead
    from reporting.forensic_report import generate as gen_forensic
    from reporting.victim_register import generate as gen_victims
    from reporting.leads_report    import generate as gen_leads

    apk      = session.get(Apk, apk_id)
    findings = session.query(Finding).filter_by(apk_id=apk_id).all()
    iocs     = session.query(IoC    ).filter_by(apk_id=apk_id).all()
    victims  = session.query(Victim ).filter_by(apk_id=apk_id).all()
    leads    = session.query(Lead   ).filter_by(apk_id=apk_id).all()

    out_dir = os.path.join(EVIDENCE_DIR, apk_id[:16])
    gen_forensic(apk, findings, iocs, victims, leads, out_dir)
    if victims: gen_victims(victims, apk_id, out_dir)
    if leads:   gen_leads(apk, leads, victims, out_dir)



# ── Monitor routes ────────────────────────────────────────────────────────────

@app.get("/monitor/{apk_id}", response_class=HTMLResponse)
def monitor_page(request: Request, apk_id: str):
    session = get_session()
    try:
        apk    = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")
        alerts = c2_monitor.get_alerts(apk.id, limit=100)
        active = apk.id in c2_monitor.list_active()
        return templates.TemplateResponse(request, "monitor.html", {
            "apk": apk, "alerts": alerts,
            "active": active, "nav_active": "dashboard",
        })
    finally:
        session.close()


@app.post("/api/monitor/start")
def api_monitor_start(apk_id: str = Form(...), interval: int = Form(300)):
    session = get_session()
    try:
        apk = session.get(Apk, apk_id)
        if not apk or not apk.firebase_project or not apk.firebase_api_key:
            raise HTTPException(status_code=400, detail="APK missing Firebase credentials")
        c2_monitor.start(apk.id, apk.firebase_project, apk.firebase_api_key, interval)
    finally:
        session.close()
    # POST-redirect-GET: return to the monitor page, not a raw JSON body.
    return RedirectResponse(f"/monitor/{apk_id}", status_code=303)


@app.post("/api/monitor/stop")
def api_monitor_stop(apk_id: str = Form(...)):
    c2_monitor.stop(apk_id)
    return RedirectResponse(f"/monitor/{apk_id}", status_code=303)


@app.get("/api/monitor/alerts/{apk_id}")
def api_monitor_alerts(apk_id: str, unseen_only: bool = False):
    return JSONResponse(c2_monitor.get_alerts(apk_id, unseen_only))


@app.get("/api/monitor/alert/{alert_id}")
def api_monitor_alert_detail(alert_id: int):
    """Enriched detail behind a live alert — the actual OTP messages / new victims,
    pulled from the C2 dump (the alert record only stores counts/UIDs)."""
    session = get_session()
    try:
        alert = session.get(MonitorAlert, alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        apk = session.get(Apk, alert.apk_id)
        project = apk.firebase_project if apk else None
    finally:
        session.close()

    victims, by_uid = _load_victim_dump(project) if project else ([], {})
    out = {"type": alert.alert_type, "message": alert.message,
           "detail": alert.detail or {}, "items": []}

    if alert.alert_type == "NEW_VICTIM":
        for uid in (alert.detail or {}).get("new_uids", [])[:300]:
            v = by_uid.get(uid, {})
            creds = v.get("credentials")
            out["items"].append({
                "name"  : _cred_find(creds, "full_name") or "—",
                "mobile": _cred_find(creds, "mobile") or "—",
                "device": f"{v.get('manufacturer', '')} {v.get('model', '')}".strip() or "—",
                "otps"  : len(v.get("otps", []) or []),
                "uid"   : uid,
            })
        out["records_url"] = f"/case/{apk.id}/records" if apk else ""

    elif alert.alert_type == "NEW_OTP":
        rows = []
        for v in victims:
            name = _cred_find(v.get("credentials"), "full_name") or (v.get("uid", "")[:8])
            for o in (v.get("otps") or []):
                rows.append((o.get("timestamp") or 0, name, o.get("sender") or "", o.get("message") or ""))
        rows.sort(key=lambda x: x[0], reverse=True)
        out["items"] = [{"time": ts, "victim": nm, "sender": sd, "message": ms}
                        for ts, nm, sd, ms in rows[:80]]

    else:
        out["items"] = [{"key": k, "value": str(v)[:300]} for k, v in (alert.detail or {}).items()]

    return JSONResponse(out)


@app.post("/api/monitor/seen/{alert_id}")
def api_mark_seen(alert_id: int):
    c2_monitor.mark_seen(alert_id)
    return JSONResponse({"ok": True})


# ── Financial routes ──────────────────────────────────────────────────────────

@app.get("/financial/{apk_id}", response_class=HTMLResponse)
def financial_page(request: Request, apk_id: str):
    session = get_session()
    try:
        apk  = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")
        txns = session.query(Transaction).filter_by(apk_id=apk.id).all()

        from collections import defaultdict
        per_bank = defaultdict(float)
        per_mule = defaultdict(lambda: {"amount": 0.0, "count": 0, "victims": set()})
        per_type = defaultdict(float)
        total    = 0.0
        for t in txns:
            total += t.amount
            per_bank[t.bank_name or "Unknown"] += t.amount
            per_type[t.txn_type or "UNKNOWN"]  += t.amount
            if t.upi_id:
                per_mule[t.upi_id]["amount"] += t.amount
                per_mule[t.upi_id]["count"]  += 1
                if t.victim_id:
                    per_mule[t.upi_id]["victims"].add(t.victim_id)

        mule_rows = sorted(
            [{"upi_id": k, "amount": v["amount"], "count": v["count"],
              "victim_count": len(v["victims"])} for k, v in per_mule.items()],
            key=lambda x: -x["amount"]
        )

        return templates.TemplateResponse(request, "financial.html", {
            "apk"      : apk,
            "total"    : total,
            "per_bank" : sorted(per_bank.items(), key=lambda x: -x[1]),
            "per_type" : sorted(per_type.items(), key=lambda x: -x[1]),
            "mule_rows": mule_rows[:30],
            "txn_count": len(txns),
            "nav_active": "dashboard",
        })
    finally:
        session.close()


@app.post("/api/financial/run/{apk_id}")
def api_run_financial(apk_id: str):
    """Trigger financial quantum engine — parses SMS, populates Transaction table."""
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")

        # The victim dump lives under the Firebase project, not apk_id[:16].
        victims_raw = _load_victim_dump(apk.firebase_project)[0] if apk.firebase_project else []
        if not victims_raw:
            raise HTTPException(status_code=400,
                                detail="No extracted victim data — run Victim Rescue extraction first")

        result = financial_quantum.run(victims_raw, apk.id, session)
        return JSONResponse(result)
    finally:
        session.close()


# ── Money flow routes ─────────────────────────────────────────────────────────

@app.get("/moneyflow/{apk_id}", response_class=HTMLResponse)
def money_flow_page(request: Request, apk_id: str):
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")
        out_dir   = os.path.join(EVIDENCE_DIR, apk.id[:16])
        json_path = os.path.join(out_dir, "money_flow_data.json")
        graph_data = {}
        if os.path.exists(json_path):
            import json as json_mod
            with open(json_path) as f:
                graph_data = json_mod.load(f)
        return templates.TemplateResponse(request, "money_flow.html", {
            "apk"       : apk,
            "graph_data": graph_data,
            "has_graph" : bool(graph_data),
            "nav_active": "dashboard",
        })
    finally:
        session.close()


@app.post("/api/moneyflow/run/{apk_id}")
def api_run_money_flow(apk_id: str):
    session = get_session()
    try:
        apk = session.get(Apk, apk_id)
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")
        out_dir = os.path.join(EVIDENCE_DIR, apk_id[:16])
        result  = money_flow.run(apk_id, session, out_dir)
        return JSONResponse({k: v for k, v in result.items() if k != "png_path" or True})
    finally:
        session.close()


@app.get("/moneyflow/{apk_id}/png")
def money_flow_png(apk_id: str):
    path = os.path.join(EVIDENCE_DIR, apk_id[:16], "MONEY_FLOW_GRAPH.png")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Graph not generated yet")
    return FileResponse(path, media_type="image/png")


# ── Geo map routes ────────────────────────────────────────────────────────────

@app.get("/geomap/{apk_id}", response_class=HTMLResponse)
def geo_map_page(request: Request, apk_id: str):
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")
        map_path = os.path.join(EVIDENCE_DIR, apk.id[:16], "GEO_VICTIM_MAP.html")
        has_map  = os.path.exists(map_path)
        geo_json_path = os.path.join(EVIDENCE_DIR, apk.id[:16], "geo_data.json")
        geo_data = {}
        if os.path.exists(geo_json_path):
            import json as jm
            with open(geo_json_path) as f:
                geo_data = jm.load(f)
        return templates.TemplateResponse(request, "geo_map.html", {
            "apk"      : apk,
            "has_map"  : has_map,
            "geo_data" : geo_data,
            "nav_active": "dashboard",
        })
    finally:
        session.close()


@app.post("/api/geomap/run/{apk_id}")
def api_run_geomap(apk_id: str):
    session = get_session()
    try:
        apk = session.query(Apk).filter(Apk.id.startswith(apk_id)).first()
        if not apk:
            raise HTTPException(status_code=404, detail="APK not found")
        out_dir = os.path.join(EVIDENCE_DIR, apk.id[:16])
        os.makedirs(out_dir, exist_ok=True)
        victims_raw = _load_victim_dump(apk.firebase_project)[0] if apk.firebase_project else []
        result = geo_map.run(apk.id, victims_raw, session, out_dir)
        # Persist geo_data.json in the shape the geo map page reads.
        states = [{"name": s, "count": c}
                  for s, c in sorted(result["state_counts"].items(), key=lambda x: -x[1])]
        with open(os.path.join(out_dir, "geo_data.json"), "w") as f:
            _json_mod.dump({"states": states, "top_state": result.get("top_state")}, f)
        return JSONResponse({"ok": True, "states_hit": result.get("states_hit", 0),
                             "top_state": result.get("top_state")})
    finally:
        session.close()


@app.get("/geomap/{apk_id}/view", response_class=HTMLResponse)
def geo_map_view(apk_id: str):
    path = os.path.join(EVIDENCE_DIR, apk_id[:16], "GEO_VICTIM_MAP.html")
    if not os.path.exists(path):
        # Graceful placeholder instead of a raw 404 inside the iframe.
        return HTMLResponse(
            "<body style='margin:0;display:flex;align-items:center;justify-content:center;"
            "height:100vh;background:#111318;color:#8892a4;font-family:sans-serif;font-size:14px'>"
            "Map not generated yet — geo-locate victims first.</body>")
    return FileResponse(path, media_type="text/html")


# ── Evidence pack routes ──────────────────────────────────────────────────────

@app.post("/api/evidence_pack/{apk_id}")
def api_generate_evidence_pack(
    apk_id: str,
    password: str = Form(""),
    agency: str = Form("TGCSB"),
    officer_name: str = Form(""),
):
    session = get_session()
    try:
        out_dir = os.path.join(EVIDENCE_DIR, apk_id[:16])
        result  = evidence_pack.generate(
            apk_id, session, out_dir,
            password=password or None,
            sharing_agency=agency,
            officer_name=officer_name,
        )
        return JSONResponse({
            "zip_path" : result["zip_path"],
            "filename" : os.path.basename(result["zip_path"]),
            "password" : result["password"],
            "encrypted": result["encrypted"],
            "file_count": result["file_count"],
            "zip_size" : result["zip_size"],
        })
    finally:
        session.close()


@app.get("/api/evidence_pack/download/{apk_prefix}/{filename}")
def api_download_pack(apk_prefix: str, filename: str):
    safe = os.path.basename(filename)
    path = os.path.join(EVIDENCE_DIR, apk_prefix, safe)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Pack not found")
    return FileResponse(path, filename=safe, media_type="application/zip")


# ── Sandbox routes ────────────────────────────────────────────────────────────

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  TGCSB APK Analyser — Web Interface")
    print("  ────────────────────────────────────")
    print("  URL: http://localhost:8888\n")
    uvicorn.run("web.app:app", host="0.0.0.0", port=8888, reload=False,
                app_dir=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
