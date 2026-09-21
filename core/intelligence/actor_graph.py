"""
Threat-Actor Graph — cluster APKs into operators via shared infrastructure.

cross_apk.correlate() reports pairwise shared attributes. This goes further:
it builds a graph (APKs = nodes, shared indicator = edge) and takes connected
components as *actors*. Two samples that share no single attribute directly can
still land in one actor cluster through a chain (A shares a cert with B, B shares
a Firebase project with C) — which is exactly how "this belongs to the same
operator as the March batch" gets established.

Edges today: Firebase project, signing certificate, attacker phone, C2 value.
Code-similarity edges (similarity.fingerprint) plug in once fingerprints are
persisted per APK (roadmap §6).
"""

import networkx as nx

# (record attribute, human label) pairs that bind two APKs to one operator.
_LINK_ATTRS = [
    ("firebase_project", "Firebase C2 project"),
    ("cert_sha256",      "signing certificate"),
    ("attacker_phone",   "attacker phone"),
]


def build_graph(records: list[dict]) -> nx.Graph:
    """records: dicts with id, filename + the _LINK_ATTRS fields. Returns a graph
    with an edge for every shared indicator (edge 'reasons' list the indicators)."""
    g = nx.Graph()
    for r in records:
        g.add_node(r["id"], filename=r.get("filename", r["id"][:12]))

    # Index apk-ids by each attribute value, then connect co-members.
    for attr, label in _LINK_ATTRS:
        buckets: dict = {}
        for r in records:
            val = r.get(attr)
            if val:
                buckets.setdefault((attr, val), []).append(r["id"])
        for (attr_, val), ids in buckets.items():
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    if g.has_edge(ids[i], ids[j]):
                        g[ids[i]][ids[j]]["reasons"].append(f"{label}={val}")
                    else:
                        g.add_edge(ids[i], ids[j], reasons=[f"{label}={val}"])
    return g


def actor_clusters(records: list[dict]) -> list[dict]:
    """Connected components with ≥2 APKs = distinct actors. Each cluster lists
    members and the shared indicators binding them."""
    g = build_graph(records)
    by_id = {r["id"]: r for r in records}
    clusters = []
    for comp in nx.connected_components(g):
        if len(comp) < 2:
            continue
        reasons = set()
        for u, v, data in g.subgraph(comp).edges(data=True):
            reasons.update(data.get("reasons", []))
        clusters.append({
            "apk_ids"   : sorted(comp),
            "filenames" : [by_id[i].get("filename", i[:12]) for i in sorted(comp)],
            "size"      : len(comp),
            "indicators": sorted(reasons),
        })
    return sorted(clusters, key=lambda c: -c["size"])


def _records_from_db(db_session) -> list[dict]:
    from db.models import Apk
    rows = db_session.query(Apk).all()
    return [{
        "id": a.id, "filename": a.filename,
        "firebase_project": a.firebase_project,
        "cert_sha256": a.cert_sha256,
        "attacker_phone": a.attacker_phone,
    } for a in rows]


def analyse(db_session) -> list[dict]:
    return actor_clusters(_records_from_db(db_session))


if __name__ == "__main__":
    # ponytail self-check: transitive linkage (A–B via cert, B–C via firebase)
    # must collapse A,B,C into one actor; an unrelated D stays out.
    recs = [
        {"id": "A" * 64, "filename": "a.apk", "cert_sha256": "CERT1", "firebase_project": None,   "attacker_phone": None},
        {"id": "B" * 64, "filename": "b.apk", "cert_sha256": "CERT1", "firebase_project": "projX", "attacker_phone": None},
        {"id": "C" * 64, "filename": "c.apk", "cert_sha256": None,    "firebase_project": "projX", "attacker_phone": None},
        {"id": "D" * 64, "filename": "d.apk", "cert_sha256": "CERT9", "firebase_project": None,    "attacker_phone": None},
    ]
    clusters = actor_clusters(recs)
    assert len(clusters) == 1, clusters
    assert clusters[0]["size"] == 3, clusters
    assert set(clusters[0]["apk_ids"]) == {"A" * 64, "B" * 64, "C" * 64}
    print(f"OK — 1 actor of 3 via transitive link; indicators={clusters[0]['indicators']}")
