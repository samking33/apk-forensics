"""
STIX 2.1 Export — share IOCs with CERT-In, MISP, and partner agencies.

STIX 2.1 is plain JSON with a fixed schema, so we emit it with the stdlib (no
`stix2` dependency). IOC values map to STIX Indicator SDOs with proper patterning;
a Malware SDO ties them together and `indicates` relationships link them. MISP
ingests STIX 2.1 bundles directly.

Object IDs are deterministic (uuid5 over type+value) so re-exporting the same
case yields stable IDs — deduplicates cleanly on the receiving MISP instance.
"""

import json
import uuid
from datetime import datetime, timezone

# Fixed namespace so uuid5 IDs are reproducible across runs/machines.
_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")

# IOC type → (STIX observable path). Types absent here become descriptive notes.
_PATTERN = {
    "HASH_SHA256": "file:hashes.'SHA-256'",
    "HASH_MD5":    "file:hashes.'MD5'",
    "DOMAIN":      "domain-name:value",
    "IP":          "ipv4-addr:value",
    "URL":         "url:value",
    "EMAIL":       "email-addr:value",
}


def _id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + ':' + seed)}"


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def build_bundle(apk_meta: dict, sha256: str, iocs: list[dict],
                 behaviors: list[str] | None = None) -> dict:
    ts = _now()
    objects = []

    malware_id = _id("malware", sha256)
    objects.append({
        "type": "malware", "spec_version": "2.1", "id": malware_id,
        "created": ts, "modified": ts,
        "name": apk_meta.get("package_name") or apk_meta.get("filename") or sha256[:16],
        "is_family": False,
        "malware_types": ["trojan"],
        "labels": behaviors or [],
    })

    notes = []
    for ioc in iocs:
        path = _PATTERN.get(ioc.get("ioc_type"))
        value = (ioc.get("value") or "").replace("'", "\\'")
        if not value:
            continue
        if path:
            ind_id = _id("indicator", f"{ioc['ioc_type']}:{value}")
            objects.append({
                "type": "indicator", "spec_version": "2.1", "id": ind_id,
                "created": ts, "modified": ts,
                "name": ioc.get("description") or ioc["ioc_type"],
                "pattern": f"[{path} = '{value}']",
                "pattern_type": "stix", "valid_from": ts,
                "labels": ["malicious-activity"],
            })
            objects.append({
                "type": "relationship", "spec_version": "2.1",
                "id": _id("relationship", ind_id + malware_id),
                "created": ts, "modified": ts,
                "relationship_type": "indicates",
                "source_ref": ind_id, "target_ref": malware_id,
            })
        else:
            # No native STIX pattern (phone, UPI, package, Firebase project, key) —
            # keep it as a labelled note so nothing is silently dropped.
            notes.append(f"{ioc.get('ioc_type')}: {ioc.get('value')}")

    if notes:
        objects.append({
            "type": "note", "spec_version": "2.1", "id": _id("note", sha256),
            "created": ts, "modified": ts,
            "abstract": "Non-STIX-native indicators",
            "content": "\n".join(notes),
            "object_refs": [malware_id],
        })

    return {"type": "bundle", "id": _id("bundle", sha256), "objects": objects}


def to_json(apk_meta, sha256, iocs, behaviors=None) -> str:
    return json.dumps(build_bundle(apk_meta, sha256, iocs, behaviors), indent=2)


if __name__ == "__main__":
    iocs = [
        {"ioc_type": "HASH_SHA256", "value": "a" * 64, "description": "APK hash"},
        {"ioc_type": "DOMAIN", "value": "evil-c2.example", "description": "C2 domain"},
        {"ioc_type": "PHONE", "value": "+919876543210", "description": "attacker phone"},
    ]
    bundle = build_bundle({"package_name": "com.evil.app"}, "a" * 64, iocs,
                          behaviors=["otp_interception"])
    types = [o["type"] for o in bundle["objects"]]
    assert bundle["type"] == "bundle"
    assert "malware" in types and "indicator" in types and "relationship" in types
    assert "note" in types  # phone kept as a note, not dropped
    # Determinism: same input → identical IDs.
    assert build_bundle({"package_name": "com.evil.app"}, "a" * 64, iocs)["id"] == \
           build_bundle({"package_name": "com.evil.app"}, "a" * 64, iocs)["id"]
    json.loads(to_json({"package_name": "x"}, "a" * 64, iocs))  # valid JSON
    print(f"OK — bundle with {len(bundle['objects'])} objects, types={sorted(set(types))}")
