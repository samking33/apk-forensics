"""
HTML Scorecard Report — the familiar MobSF-style visual scorecard analysts
expect, plus the victim/financial/behaviour intelligence no generic scanner has.

Self-contained single HTML file (inline CSS, no external assets) so it drops
straight into an evidence pack and opens anywhere. Renders from the static
engine's result dict — risk gauge + auditable breakdown, detected behaviours,
C2 channels, findings by severity, certificate, trackers, IOCs.
"""

import html
import os

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEV_COLOR = {"CRITICAL": "#e05151", "HIGH": "#e09b20", "MEDIUM": "#4d8fe8",
              "LOW": "#3db87a", "INFO": "#8892a4"}


def _e(v):
    return html.escape(str(v if v is not None else ""))


def generate(result: dict, sha256: str, out_dir: str | None = None) -> str:
    meta = result.get("apk_meta", {})
    risk = result.get("risk_score", 0)
    detail = result.get("risk_detail", {})
    level = detail.get("level", "LOW")
    behavior = result.get("behavior", {})
    findings = result.get("findings", [])
    cert = result.get("cert_info", {})

    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in _SEV_ORDER}
    ring = _SEV_COLOR.get(level, "#8892a4")

    def rows(items):
        return "".join(items)

    breakdown_rows = rows(
        f"<tr><td>{_e(b['factor'])}</td><td class='num'>+{_e(b['points'])}</td>"
        f"<td class='dim'>{_e(b['detail'])}</td></tr>"
        for b in detail.get("breakdown", [])
    ) or "<tr><td colspan='3' class='dim'>No risk factors triggered.</td></tr>"

    behavior_chips = rows(
        f"<span class='chip crit'>{_e(b.replace('_', ' '))}</span>"
        for b in behavior.get("behaviors", [])
    ) or "<span class='dim'>None detected</span>"

    c2_rows = rows(
        f"<tr><td>{_e(c['type'])}</td><td class='mono'>{_e(c['value'])}</td></tr>"
        for c in behavior.get("c2_channels", [])
    ) or "<tr><td colspan='2' class='dim'>No C2 channel identified.</td></tr>"

    finding_rows = rows(
        f"<tr class='sev-{f.get('severity','INFO').lower()}'>"
        f"<td><span class='badge' style='color:{_SEV_COLOR.get(f.get('severity'),'#888')};"
        f"border-color:{_SEV_COLOR.get(f.get('severity'),'#888')}'>{_e(f.get('severity'))}</span></td>"
        f"<td>{_e(f.get('category'))}</td><td>{_e(f.get('title'))}</td>"
        f"<td class='dim'>{_e((f.get('detail') or '')[:160])}</td>"
        f"<td class='mono dim'>{_e(f.get('found_at'))}</td></tr>"
        for f in sorted(findings, key=lambda x: _SEV_ORDER.index(x.get("severity", "INFO"))
                        if x.get("severity") in _SEV_ORDER else 99)
    ) or "<tr><td colspan='5' class='dim'>No findings.</td></tr>"

    sev_pills = rows(
        f"<span class='pill' style='background:{_SEV_COLOR[s]}22;color:{_SEV_COLOR[s]};"
        f"border-color:{_SEV_COLOR[s]}55'>{counts[s]} {s}</span>"
        for s in _SEV_ORDER if counts[s]
    )

    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>fSOC Scorecard — {_e(meta.get('package_name') or sha256[:16])}</title>
<style>
:root{{--bg:#111318;--card:#16191f;--bd:#2b303c;--tx:#e2e8f0;--dim:#8892a4;--mut:#4a5168}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--tx);
font:13px/1.5 -apple-system,Segoe UI,sans-serif;padding:28px}}
h1{{font-size:20px;margin:0 0 4px}}h2{{font-size:13px;text-transform:uppercase;
letter-spacing:1px;color:var(--dim);margin:26px 0 10px;border-bottom:1px solid var(--bd);
padding-bottom:6px}}.mono{{font-family:ui-monospace,Menlo,monospace;font-size:11px}}
.dim{{color:var(--dim)}}.num{{font-family:ui-monospace,monospace;text-align:right}}
.wrap{{max-width:1100px;margin:0 auto}}
.hero{{display:flex;gap:24px;align-items:center;background:var(--card);
border:1px solid var(--bd);border-radius:8px;padding:22px}}
.gauge{{width:120px;height:120px;border-radius:50%;display:flex;flex-direction:column;
align-items:center;justify-content:center;flex-shrink:0;
background:conic-gradient({ring} {risk*3.6}deg,#21252e 0)}}
.gauge .inner{{width:96px;height:96px;border-radius:50%;background:var(--card);
display:flex;flex-direction:column;align-items:center;justify-content:center}}
.gauge .score{{font-size:30px;font-weight:700}}.gauge .lvl{{font-size:10px;color:{ring};
text-transform:uppercase;letter-spacing:1px}}
table{{width:100%;border-collapse:collapse}}td,th{{padding:7px 10px;text-align:left;
border-bottom:1px solid #222631;vertical-align:top}}th{{color:var(--mut);font-size:10px;
text-transform:uppercase;letter-spacing:.5px}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:8px;overflow:hidden}}
.chip{{display:inline-block;padding:2px 9px;border-radius:4px;margin:2px;font-size:11px;
background:#e0515122;color:#e05151;border:1px solid #e0515155}}
.badge{{border:1px solid;border-radius:3px;padding:1px 6px;font-size:10px;font-weight:600}}
.pill{{display:inline-block;padding:3px 10px;border-radius:20px;border:1px solid;
margin:2px;font-size:11px;font-weight:600}}
.kv{{color:var(--dim);width:150px}}
</style></head><body><div class="wrap">
<h1>{_e(meta.get('package_name') or 'Unknown package')}</h1>
<div class="dim mono">{_e(meta.get('filename'))} · SHA-256 {_e(sha256)}</div>

<h2>Risk Assessment</h2>
<div class="hero">
  <div class="gauge"><div class="inner"><div class="score">{risk}</div>
    <div class="lvl">{_e(level)}</div></div></div>
  <div style="flex:1">
    <div style="margin-bottom:10px">{sev_pills or '<span class="dim">No findings</span>'}</div>
    <div style="margin-bottom:6px">{behavior_chips}</div>
    <div class="dim">Version {_e(meta.get('version_name'))} · target SDK {_e(meta.get('target_sdk'))}
    · signing {_e('+'.join(cert.get('schemes', [])) or 'unsigned')}</div>
  </div>
</div>

<h2>Risk Breakdown</h2>
<div class="card"><table><thead><tr><th>Factor</th><th class="num">Points</th>
<th>Detail</th></tr></thead><tbody>{breakdown_rows}</tbody></table></div>

<h2>C2 Channels</h2>
<div class="card"><table><thead><tr><th>Type</th><th>Value</th></tr></thead>
<tbody>{c2_rows}</tbody></table></div>

<h2>Findings ({len(findings)})</h2>
<div class="card"><table><thead><tr><th>Severity</th><th>Category</th><th>Title</th>
<th>Detail</th><th>Location</th></tr></thead><tbody>{finding_rows}</tbody></table></div>

<h2>Certificate</h2>
<div class="card"><table>
<tr><td class="kv">Subject</td><td class="mono">{_e(cert.get('subject'))}</td></tr>
<tr><td class="kv">Self-signed</td><td>{_e(cert.get('self_signed'))}</td></tr>
<tr><td class="kv">Hash algo</td><td>{_e(cert.get('hash_algo'))}</td></tr>
<tr><td class="kv">Cert SHA-256</td><td class="mono">{_e(cert.get('cert_sha256'))}</td></tr>
<tr><td class="kv">Validity</td><td>{_e(cert.get('not_before'))} → {_e(cert.get('not_after'))}</td></tr>
</table></div>

<p class="dim" style="margin-top:24px">Generated by fSOC static analysis engine.
Trackers: {_e(', '.join(t['name'] for t in result.get('trackers', [])) or 'none')}.
Libraries: {_e(', '.join(result.get('libraries', [])) or 'none')}.</p>
</div></body></html>"""

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, "SCORECARD.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(doc)
    return doc


if __name__ == "__main__":
    result = {
        "apk_meta": {"package_name": "com.evil.app", "filename": "evil.apk",
                     "version_name": "1.0", "target_sdk": 33},
        "risk_score": 88, "risk_detail": {"level": "CRITICAL", "breakdown": [
            {"factor": "Banking-trojan behaviours", "points": 55, "detail": "otp_interception"},
            {"factor": "Firebase C2 backend", "points": 35, "detail": "evil-1234"}]},
        "behavior": {"behaviors": ["otp_interception", "accessibility_abuse"],
                     "c2_channels": [{"type": "telegram", "value": "bot123:AA"}]},
        "findings": [{"severity": "CRITICAL", "category": "BEHAVIOUR",
                      "title": "SMS/OTP interception", "detail": "reads PDUs",
                      "found_at": "Payload.java:12"}],
        "cert_info": {"subject": "CN=Evil", "self_signed": True, "hash_algo": "sha256",
                      "schemes": ["v1", "v2"]},
        "trackers": [], "libraries": ["OkHttp"],
    }
    doc = generate(result, "a" * 64)
    for token in ("com.evil.app", "CRITICAL", "otp interception", "telegram",
                  "SMS/OTP interception", "Risk Breakdown"):
        assert token in doc, f"missing: {token}"
    assert doc.strip().startswith("<!doctype html>")
    print(f"OK — scorecard HTML generated ({len(doc)} bytes)")
