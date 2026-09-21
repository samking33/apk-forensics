"""
C2 Infrastructure Pivot — cluster non-Firebase C2 domains by shared hosting.

Firebase C2s cluster by project/cert (actor_graph.py). Custom HTTP/PHP C2s
(the other common backend) don't have that — but attackers routinely reuse
the same VPS or hosting account across campaigns. Resolving each C2 domain's
IP and WHOIS registrant and grouping by shared IP surfaces the same
"these belong to one operator" signal actor_graph gives for Firebase.

Read-only: DNS resolution + WHOIS lookups only. No contact with the C2 itself.
"""

import ipaddress
import re
import socket
import subprocess


def resolve(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, UnicodeError):
        return None


def whois_summary(domain: str, timeout: int = 10) -> dict:
    """A few high-signal WHOIS fields, when the registrar doesn't privacy-mask them."""
    out = {"registrar": None, "creation_date": None, "country": None, "org": None}
    try:
        r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=timeout)
        text = r.stdout
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return out

    def grab(*patterns):
        for p in patterns:
            m = re.search(p, text, re.I)
            if m:
                v = m.group(1).strip()
                if v and "not available" not in v.lower() and "redacted" not in v.lower():
                    return v
        return None

    out["registrar"] = grab(r"Registrar:\s*(.+)")
    out["creation_date"] = grab(r"Creation Date:\s*(.+)")
    out["country"] = grab(r"Registrant Country:\s*(.+)")
    out["org"] = grab(r"Registrant Organization:\s*(.+)", r"Registrant Name:\s*(.+)")
    return out


def analyse(domains: list[str]) -> dict:
    """Resolve + WHOIS every domain, cluster by shared IP. Returns per-domain
    intel plus IP-based actor clusters (2+ domains sharing an IP)."""
    intel = {}
    for d in domains:
        ip = resolve(d)
        intel[d] = {"domain": d, "ip": ip, "alive": ip is not None,
                    **(whois_summary(d) if ip else {})}

    by_ip: dict[str, list[str]] = {}
    by_subnet: dict[str, list[str]] = {}
    for d, info in intel.items():
        ip = info["ip"]
        if ip:
            by_ip.setdefault(ip, []).append(d)
            try:
                net = ipaddress.ip_network(f"{ip}/23", strict=False)
                by_subnet.setdefault(str(net), []).append(d)
            except ValueError:
                pass

    clusters = [{"confidence": "high", "signal": "same IP", "ip": ip, "domains": sorted(ds)}
               for ip, ds in by_ip.items() if len(ds) > 1]
    seen = {tuple(c["domains"]) for c in clusters}
    for subnet, ds in by_subnet.items():
        if len(ds) > 1 and tuple(sorted(ds)) not in seen:
            clusters.append({"confidence": "medium", "signal": "same /23 block (likely shared hosting provider)",
                             "ip": subnet, "domains": sorted(ds)})

    return {"domains": intel, "clusters": sorted(clusters, key=lambda c: -len(c["domains"]))}


if __name__ == "__main__":
    # ponytail self-check: two hostnames on the same IP must cluster; a dead
    # domain must report alive=False without raising.
    import unittest.mock as mock
    fake_resolve = {"a.example-test-fsoc.invalid": "9.9.9.9",
                    "b.example-test-fsoc.invalid": "9.9.9.9",
                    "dead.example-test-fsoc.invalid": None}
    with mock.patch(__name__ + ".resolve", side_effect=lambda d: fake_resolve.get(d)), \
         mock.patch(__name__ + ".whois_summary", return_value={"registrar": None, "creation_date": None, "country": None, "org": None}):
        r = analyse(list(fake_resolve))
    assert r["clusters"] and set(r["clusters"][0]["domains"]) == {"a.example-test-fsoc.invalid", "b.example-test-fsoc.invalid"}
    assert r["domains"]["dead.example-test-fsoc.invalid"]["alive"] is False
    print(f"OK — clustering + dead-domain handling verified: {r['clusters']}")
