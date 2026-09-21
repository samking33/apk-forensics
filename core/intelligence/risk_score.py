"""
Explainable Risk Score — transparent, court-defensible 0-100 verdict.

A black-box ML classifier is a poor fit for evidence: an analyst on the stand
must explain *why* a sample scored 85. This produces the same number as a model
would approximate, but every point is attributed to a named factor, so the score
is fully auditable.

`ml_probability` is an optional hook: if a trained model is later added, pass its
0-1 output and it is reported alongside (never silently overriding) the
explainable score. ponytail: no model until there's a labelled corpus to train
and validate one — an unexplainable guess is worse than none in court.
"""

_BEHAVIOR_WEIGHTS = {
    "otp_interception": 30, "accessibility_abuse": 25, "overlay_phishing": 25,
    "dropper": 20, "device_admin": 10, "packed": 10, "obfuscation": 5,
    "anti_analysis": 5,
}
_CODE_PTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


def compute(*, firebase=None, yara_hits=None, perm_pts=0, manifest_pts=0,
            code_findings=None, behavior=None, mined=None,
            ml_probability: float | None = None) -> dict:
    """Returns {score, level, breakdown:[{factor, points, detail}], ml_probability}."""
    firebase = firebase or {}
    behavior = behavior or {}
    mined = mined or {}
    breakdown = []

    def factor(name, points, detail):
        if points:
            breakdown.append({"factor": name, "points": points, "detail": detail})

    # Behaviours — the real malware verdict, weighted highest (cap 60).
    beh = behavior.get("behaviors", [])
    beh_pts = min(sum(_BEHAVIOR_WEIGHTS.get(b, 0) for b in beh), 60)
    if beh_pts:
        factor("Banking-trojan behaviours", beh_pts, ", ".join(beh))

    if any(c["type"] in ("telegram", "firebase") for c in behavior.get("c2_channels", [])):
        factor("Attributable C2 channel", 10, "Telegram/Firebase C2 present")

    if firebase.get("firebase_api_key"):
        factor("Firebase C2 backend", 35, f"project {firebase.get('firebase_project')}")
    if yara_hits:
        factor("YARA malware signature", 25, f"{len(yara_hits)} rule match(es)")

    factor("Dangerous permissions", perm_pts, "scored permission set")
    factor("Manifest misconfiguration", manifest_pts, "exported/debuggable/cleartext")

    code_pts = min(sum(_CODE_PTS.get(f["severity"], 0) for f in (code_findings or [])), 20)
    factor("Insecure code patterns", code_pts, f"{len(code_findings or [])} finding(s)")

    if mined.get("aes_key"):
        factor("Hardcoded encryption key", 8, "static key material")
    if mined.get("phone_in"):
        factor("Hardcoded phone number", 4, "possible attacker contact")

    score = min(sum(b["points"] for b in breakdown), 100)
    level = ("CRITICAL" if score >= 70 else "HIGH" if score >= 40
             else "MEDIUM" if score >= 20 else "LOW")

    return {
        "score": score,
        "level": level,
        "breakdown": sorted(breakdown, key=lambda b: -b["points"]),
        "ml_probability": ml_probability,
    }


if __name__ == "__main__":
    # ponytail self-check: an OTP-stealer with Firebase must land CRITICAL with an
    # auditable breakdown; an empty sample scores 0/LOW.
    r = compute(
        firebase={"firebase_api_key": "AIza...", "firebase_project": "evil-1234"},
        behavior={"behaviors": ["otp_interception", "accessibility_abuse"],
                  "c2_channels": [{"type": "firebase", "value": "x"}]},
        perm_pts=40, manifest_pts=10,
    )
    assert r["score"] >= 70 and r["level"] == "CRITICAL", r
    assert r["breakdown"][0]["points"] >= r["breakdown"][-1]["points"]
    assert compute()["score"] == 0
    print(f"OK — score={r['score']} level={r['level']} "
          f"top_factor={r['breakdown'][0]['factor']}")
