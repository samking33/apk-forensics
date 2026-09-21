"""
Certificate Deep Analysis — signing scheme, weak algorithms, validity, and the
signer identity used for cross-case developer attribution.

Every Android app is self-signed, so self-signing itself is not a finding; what
matters forensically is: weak signature/hash algorithms, v1-only signing (Janus
CVE-2017-13156 surface), expired/absurd validity, and the certificate SHA-256 —
the strongest single pivot for clustering samples to one actor.
"""

import hashlib


def analyse(a) -> tuple[list[dict], dict]:
    """Returns (findings, cert_info). cert_info feeds actor clustering / IoCs."""
    findings: list[dict] = []
    info = {
        "schemes": [], "self_signed": None, "hash_algo": None,
        "signature_algo": None, "subject": None, "issuer": None,
        "not_before": None, "not_after": None, "cert_sha256": None,
    }

    def add(sev, title, detail):
        findings.append({"category": "CERTIFICATE", "severity": sev,
                         "title": title, "detail": detail, "found_at": "APK signature"})

    # ── Signing schemes ───────────────────────────────────────────────────────
    schemes = []
    for label, fn in (("v1", a.is_signed_v1), ("v2", a.is_signed_v2),
                      ("v3", a.is_signed_v3), ("v31", getattr(a, "is_signed_v31", None))):
        try:
            if fn and fn():
                schemes.append(label)
        except Exception:
            pass
    info["schemes"] = schemes

    if not schemes:
        add("HIGH", "APK is unsigned", "No valid signature block found — cannot attribute.")
    elif schemes == ["v1"]:
        add("MEDIUM", "v1-only signing (Janus surface)",
            "Signed only with the legacy v1 (JAR) scheme — vulnerable to Janus "
            "(CVE-2017-13156) payload injection on Android < 7.0.")

    # ── Certificate contents ──────────────────────────────────────────────────
    try:
        certs = a.get_certificates()
    except Exception as e:
        add("INFO", "Certificate parse failed", str(e))
        return findings, info

    if not certs:
        return findings, info

    c = certs[0]
    try:
        der = c.dump()
        info["cert_sha256"] = hashlib.sha256(der).hexdigest()
    except Exception:
        pass

    try:
        info["subject"] = c.subject.human_friendly
        info["issuer"]  = c.issuer.human_friendly
        info["self_signed"] = (c.subject == c.issuer)
        info["hash_algo"] = c.hash_algo
        info["signature_algo"] = c.signature_algo
    except Exception:
        pass

    # Weak hash in the signature — real integrity weakness.
    if info["hash_algo"] in ("md5", "md2", "sha1"):
        add("HIGH", f"Weak certificate hash ({info['hash_algo'].upper()})",
            "Signature uses a broken/deprecated hash algorithm — forgeable integrity.")

    # Validity window.
    try:
        validity = c["tbs_certificate"]["validity"]
        nb = validity["not_before"].native
        na = validity["not_after"].native
        info["not_before"] = str(nb)
        info["not_after"]  = str(na)
        years = (na - nb).days / 365.25
        if years > 60:
            add("INFO", "Unusually long certificate validity",
                f"Certificate valid ~{years:.0f} years ({nb.date()} → {na.date()}) — "
                "common in throwaway malware signing certs.")
    except Exception:
        pass

    return findings, info
