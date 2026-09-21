"""
IOC Enrichment Fan-out — VirusTotal, MalwareBazaar, URLhaus.

Turns raw IOCs into context: is this hash already known malware, is this URL in a
threat feed, what family/tags do other agencies attach to it. Every source is
optional and fails soft — missing API key or no network yields a 'skipped'
result, never an exception, so enrichment never breaks an offline analysis run.

Keys via env: VT_API_KEY (VirusTotal), ABUSECH_API_KEY (abuse.ch MalwareBazaar).
URLhaus is keyless. ponytail: stdlib urllib, no requests dependency; response
parsing is split into pure functions so it is unit-tested without the network.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request

_TIMEOUT = 15


def _post(url: str, data: dict, headers: dict | None = None) -> dict | None:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


def _get(url: str, headers: dict) -> dict | None:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


# ── Pure response parsers (unit-tested without network) ───────────────────────

def parse_vt(resp: dict) -> dict:
    attr = (resp or {}).get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    return {
        "source": "virustotal", "found": bool(attr),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": sum(stats.values()) if stats else 0,
        "names": (attr.get("names") or [])[:5],
        "labels": [s.get("value") for s in (attr.get("popular_threat_classification", {})
                   .get("suggested_threat_label") and
                   [{"value": attr["popular_threat_classification"]["suggested_threat_label"]}] or [])],
    }


def parse_malwarebazaar(resp: dict) -> dict:
    if not resp or resp.get("query_status") != "ok":
        return {"source": "malwarebazaar", "found": False}
    d = (resp.get("data") or [{}])[0]
    return {
        "source": "malwarebazaar", "found": True,
        "signature": d.get("signature"), "file_type": d.get("file_type"),
        "tags": d.get("tags") or [], "first_seen": d.get("first_seen"),
    }


def parse_urlhaus(resp: dict) -> dict:
    if not resp or resp.get("query_status") != "ok":
        return {"source": "urlhaus", "found": False}
    return {
        "source": "urlhaus", "found": True,
        "threat": resp.get("threat"), "status": resp.get("url_status"),
        "tags": resp.get("tags") or [],
    }


# ── Network-backed enrichers (fail soft) ──────────────────────────────────────

def enrich_hash(sha256: str) -> dict:
    vt_key = os.environ.get("VT_API_KEY")
    mb_key = os.environ.get("ABUSECH_API_KEY")
    out = {}
    if vt_key:
        resp = _get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                    {"x-apikey": vt_key})
        out["virustotal"] = parse_vt(resp) if resp else {"source": "virustotal", "skipped": "no response"}
    else:
        out["virustotal"] = {"source": "virustotal", "skipped": "no VT_API_KEY"}

    if mb_key:
        resp = _post("https://mb-api.abuse.ch/api/v1/",
                     {"query": "get_info", "hash": sha256}, {"Auth-Key": mb_key})
        out["malwarebazaar"] = parse_malwarebazaar(resp) if resp else \
            {"source": "malwarebazaar", "skipped": "no response"}
    else:
        out["malwarebazaar"] = {"source": "malwarebazaar", "skipped": "no ABUSECH_API_KEY"}
    return out


def enrich_url(url: str) -> dict:
    resp = _post("https://urlhaus-api.abuse.ch/v1/url/", {"url": url})
    return parse_urlhaus(resp) if resp else {"source": "urlhaus", "skipped": "no response"}


def enrich_iocs(iocs: list[dict], apk_sha256: str | None = None) -> dict:
    """Fan out over an IOC list. Only hits network for enrichable types."""
    result = {"hashes": {}, "urls": {}}
    if apk_sha256:
        result["hashes"][apk_sha256] = enrich_hash(apk_sha256)
    for ioc in iocs:
        t, v = ioc.get("ioc_type"), ioc.get("value")
        if t in ("URL",) and v:
            result["urls"][v] = enrich_url(v)
    return result


if __name__ == "__main__":
    # ponytail self-check: parsers handle real-shaped payloads + empty/miss cases.
    vt = parse_vt({"data": {"attributes": {
        "last_analysis_stats": {"malicious": 42, "harmless": 10, "suspicious": 3},
        "names": ["evil.apk", "bank.apk"]}}})
    assert vt["found"] and vt["malicious"] == 42 and vt["total"] == 55, vt

    mb = parse_malwarebazaar({"query_status": "ok", "data": [
        {"signature": "Hydra", "file_type": "apk", "tags": ["android", "banker"]}]})
    assert mb["found"] and mb["signature"] == "Hydra", mb
    assert parse_malwarebazaar({"query_status": "hash_not_found"})["found"] is False

    uh = parse_urlhaus({"query_status": "ok", "threat": "malware_download",
                        "url_status": "online", "tags": ["apk"]})
    assert uh["found"] and uh["threat"] == "malware_download", uh

    # No keys → skipped, never raises.
    h = enrich_hash("a" * 64)
    assert "skipped" in h["virustotal"] or "found" in h["virustotal"]
    print("OK — enrichment parsers + graceful-skip verified")
