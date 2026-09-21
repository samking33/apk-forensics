"""
GitHub Firebase-credential dork runner — paced batch OSINT sweep.

Runs a set of GitHub code-search dorks (via `gh search code`) looking for
leaked Firebase project IDs / API keys — the kind of thing a careless malware
operator commits when they push their whole Android Studio project (or a
shared "builder kit") to a public repo. Paces itself under GitHub's code-search
rate limit (~10 req/min) so a full sweep can just be kicked off and left to run.

Extracts every AIzaSy… key and firebaseio.com/project_id string from each
hit's text-match fragment, filters out obvious placeholders/examples, and
prints candidate (project_id, api_key) pairs ready to paste into fSOC's
Victim Rescue → Manual C2 Probe.

Usage:
    python3 tools/gh_dork.py                 # run the built-in dork list
    python3 tools/gh_dork.py "custom query"   # run one ad-hoc query
    python3 tools/gh_dork.py --json out.json  # also save full results

Requires: `gh` CLI, authenticated (`gh auth status`).
"""

import argparse
import base64
import json
import re
import shutil
import subprocess
import sys
import time

_GH = shutil.which("gh")
_PACE_SECONDS = 7  # keeps us comfortably under GitHub's ~10 req/min code-search limit

_KEY_RE = re.compile(r"AIzaSy[0-9A-Za-z_-]{33}")
_PROJECT_RE = re.compile(r"([a-z0-9][a-z0-9-]{3,30})(?:-default-rtdb)?\.(?:firebaseio|firebaseapp)\.com")
_PROJECT_FIELD_RE = re.compile(r'"project_id"\s*:\s*"([a-z0-9][a-z0-9-]{3,30})"')

# Placeholder/example markers — a hit containing these is almost certainly not
# a real leaked credential, and there are enough of them in template configs
# to make raw dorking noisy without this filter.
_JUNK_MARKERS = re.compile(
    r"your[-_]?(project|api)|example|placeholder|xxxxx|dummy|test-project|"
    r"YOUR_PROJECT_ID|\.\.\.|<[A-Za-z_]+>|\$\{|demo-", re.I)
_JUNK_FILE_SUFFIXES = (".example", ".template", ".dist", ".sample", ".dev", ".default")

# Built-in dork list: generic Firebase-leak dorks + malware-specific combos
# (the class/field names our own static engine's detectors already look for —
# a hit combining these with a Firebase string is almost certainly banking-
# trojan source, not a legitimate app).
DEFAULT_DORKS = [
    {"query": "project_id", "filename": "google-services.json"},
    {"query": "apiKey AIzaSy authDomain", "extension": "json"},
    {"query": "AIzaSy SmsForwarder"},
    {"query": "AIzaSy AdminNumberManager"},
    {"query": "admin/number devices AIzaSy"},
    {"query": "OtpReceiver firebaseio.com"},
    {"query": "sendTextMessage AIzaSy RECEIVE_SMS"},
    {"query": "default-rtdb.firebaseio.com apiKey"},
]


def _require_gh():
    if not _GH:
        sys.exit("gh CLI not found on PATH. Install: https://cli.github.com")
    r = subprocess.run([_GH, "auth", "status"], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("gh CLI not authenticated. Run: gh auth login")


def run_dork(dork: dict) -> list[dict]:
    cmd = [_GH, "search", "code", dork["query"],
           "--json", "path,repository,textMatches,url", "--limit", "30"]
    if dork.get("filename"):
        cmd += ["--filename", dork["filename"]]
    if dork.get("extension"):
        cmd += ["--extension", dork["extension"]]
    if dork.get("language"):
        cmd += ["--language", dork["language"]]

    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        print(f"  ! query failed: {r.stderr.strip()[:200]}", file=sys.stderr)
        return []
    try:
        return json.loads(r.stdout) if r.stdout.strip() else []
    except json.JSONDecodeError:
        return []


def fetch_full_file(repo: str, path: str) -> str | None:
    """Fetch a file's full content via the Contents REST API (separate, much
    higher rate limit than code search — ~5000/hr authenticated). Used as a
    fallback when a search hit's text-match fragment is empty/too small to
    extract from, which happens often for filename-targeted dorks since
    GitHub doesn't always return a highlighted fragment for path-based hits."""
    r = subprocess.run(
        [_GH, "api", f"repos/{repo}/contents/{path}", "--jq", ".content"],
        capture_output=True, text=True, timeout=20)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        return base64.b64decode(r.stdout.strip().replace("\n", "")).decode("utf-8", "replace")
    except (ValueError, UnicodeDecodeError):
        return None


def _is_junk(fragment: str, path: str) -> bool:
    if _JUNK_MARKERS.search(fragment):
        return True
    return any(path.endswith(suf) or f"{suf}." in path for suf in _JUNK_FILE_SUFFIXES)


def extract_candidates(hits: list[dict], fetch_fallback: bool = True) -> list[dict]:
    """Pull (repo, path, key, project_id) candidates out of raw search hits,
    filtering placeholders. If a hit's fragment yields nothing (common for
    filename-targeted dorks — GitHub doesn't always highlight a fragment for
    path matches), fall back to fetching the full file, since these are
    exactly the small config files where the whole thing is the target."""
    out = []
    for hit in hits:
        repo = hit.get("repository", {}).get("nameWithOwner", "?")
        path = hit.get("path", "?")
        url = hit.get("url", "")

        texts = [tm.get("fragment", "") for tm in hit.get("textMatches", [])]
        found_any = False
        for frag in texts:
            if _is_junk(frag, path):
                continue
            keys = _KEY_RE.findall(frag)
            projects = _PROJECT_RE.findall(frag) + _PROJECT_FIELD_RE.findall(frag)
            if not keys and not projects:
                continue
            found_any = True
            out.append({
                "repo": repo, "path": path, "url": url,
                "api_keys": sorted(set(keys)), "project_ids": sorted(set(projects)),
                "fragment": frag[:300], "source": "fragment",
            })

        if found_any or not fetch_fallback:
            continue
        content = fetch_full_file(repo, path)
        if not content or _is_junk(content, path):
            continue
        keys = _KEY_RE.findall(content)
        projects = _PROJECT_RE.findall(content) + _PROJECT_FIELD_RE.findall(content)
        if keys or projects:
            out.append({
                "repo": repo, "path": path, "url": url,
                "api_keys": sorted(set(keys)), "project_ids": sorted(set(projects)),
                "fragment": content[:300], "source": "full_file",
            })
    return out


def sweep(dorks: list[dict], save_json: str | None = None) -> list[dict]:
    _require_gh()
    all_candidates = []
    for i, dork in enumerate(dorks):
        label = dork["query"] + (f" (filename:{dork['filename']})" if dork.get("filename") else "")
        print(f"[{i+1}/{len(dorks)}] {label}")
        hits = run_dork(dork)
        cands = extract_candidates(hits)
        for c in cands:
            keys = ", ".join(c["api_keys"]) or "-"
            projs = ", ".join(c["project_ids"]) or "-"
            print(f"    -> {c['repo']}:{c['path']}")
            print(f"       keys={keys}  projects={projs}")
        all_candidates.extend(cands)
        if i < len(dorks) - 1:
            time.sleep(_PACE_SECONDS)

    print(f"\n{len(all_candidates)} candidate hit(s) with recoverable creds/projects "
          f"across {len(dorks)} dork(s).")
    if save_json:
        with open(save_json, "w") as f:
            json.dump(all_candidates, f, indent=2)
        print(f"Saved full results to {save_json}")
    return all_candidates


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("query", nargs="?", help="Run a single ad-hoc query instead of the built-in dork list")
    p.add_argument("--json", dest="save_json", help="Save full candidate list to this JSON file")
    args = p.parse_args()

    dorks = [{"query": args.query}] if args.query else DEFAULT_DORKS
    sweep(dorks, save_json=args.save_json)


if __name__ == "__main__":
    main()
