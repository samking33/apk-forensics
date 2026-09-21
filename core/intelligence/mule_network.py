"""
Mule-Network Analysis & Cross-Campaign Victim Dedup.

Two investigative outputs law enforcement acts on directly:

  1. Victim dedup — the same person is re-victimised across campaigns; dedup by
     normalised mobile number so notifications and loss totals aren't double-counted.

  2. Mule ranking — build a victim→beneficiary money graph and rank mule accounts
     by PageRank centrality. The top mules (those pulling from the most victims
     across the most campaigns) are where an arrest/freeze has maximum impact —
     far more actionable than a flat list of transactions.
"""

import re

import networkx as nx

_DIGITS = re.compile(r"\D+")


def _pagerank(g, alpha: float = 0.85, iters: int = 100, tol: float = 1.0e-6) -> dict:
    """Weighted PageRank via power iteration. Pure-Python so we avoid a scipy
    dependency (networkx.pagerank requires it). ponytail: power iteration with a
    fixed cap; swap in networkx/scipy only if graphs reach millions of edges."""
    nodes = list(g.nodes())
    n = len(nodes)
    if n == 0:
        return {}
    pr = {v: 1.0 / n for v in nodes}
    out = {v: sum(g[v][w].get("weight", 1.0) for w in g.successors(v)) for v in nodes}
    dangling = [v for v in nodes if out[v] == 0]

    for _ in range(iters):
        prev = pr
        pr = {v: (1.0 - alpha) / n for v in nodes}
        redistributed = alpha * sum(prev[v] for v in dangling) / n
        for v in nodes:
            pr[v] += redistributed
        for v in nodes:
            if out[v] == 0:
                continue
            share = alpha * prev[v] / out[v]
            for w in g.successors(v):
                pr[w] += share * g[v][w].get("weight", 1.0)
        if sum(abs(pr[v] - prev[v]) for v in nodes) < tol:
            break

    total = sum(pr.values())
    return {v: pr[v] / total for v in nodes} if total else pr


def _norm_mobile(mobile: str | None) -> str | None:
    if not mobile:
        return None
    d = _DIGITS.sub("", mobile)
    return d[-10:] if len(d) >= 10 else None


def dedupe_victims(victims: list[dict]) -> dict:
    """victims: dicts with id + mobile. Returns {canonical_mobile: [victim_ids]}.
    Victims with no usable mobile are keyed individually so they aren't merged."""
    groups: dict = {}
    for v in victims:
        key = _norm_mobile(v.get("mobile")) or f"_id:{v['id']}"
        groups.setdefault(key, []).append(v["id"])
    return groups


def _mule_id(txn: dict) -> str | None:
    """Resolve a beneficiary identity from a transaction, best signal first."""
    if txn.get("upi_id"):
        return f"upi:{txn['upi_id']}"
    if txn.get("recipient_name"):
        return f"name:{txn['recipient_name']}"
    if txn.get("account_last4"):
        return f"acct:{txn['account_last4']}"
    return None


def rank_mules(transactions: list[dict]) -> list[dict]:
    """transactions: dicts with victim_id, amount, and one of upi_id/recipient_name/
    account_last4 (+ optional apk_id for campaign spread). Returns mules ranked by
    PageRank centrality with received total, victim reach, and campaign spread."""
    g = nx.DiGraph()
    received: dict = {}
    victims_of: dict = {}
    campaigns_of: dict = {}

    for t in transactions:
        mule = _mule_id(t)
        if not mule:
            continue
        victim = f"v:{t.get('victim_id', '?')}"
        amount = float(t.get("amount") or 0.0)
        g.add_edge(victim, mule, weight=amount + 1.0)   # +1 so zero-amount edges still count
        received[mule] = received.get(mule, 0.0) + amount
        victims_of.setdefault(mule, set()).add(t.get("victim_id"))
        if t.get("apk_id"):
            campaigns_of.setdefault(mule, set()).add(t["apk_id"])

    if g.number_of_nodes() == 0:
        return []

    pr = _pagerank(g) if g.number_of_edges() else {}

    mules = []
    for mule in received:
        mules.append({
            "mule"          : mule,
            "total_received": round(received[mule], 2),
            "victim_count"  : len(victims_of.get(mule, set())),
            "campaign_count": len(campaigns_of.get(mule, set())),
            "centrality"    : round(pr.get(mule, 0.0), 6),
        })
    # Rank by centrality, then victim reach, then amount.
    return sorted(mules, key=lambda m: (-m["centrality"], -m["victim_count"],
                                        -m["total_received"]))


def analyse(db_session) -> dict:
    from db.models import Victim, Transaction
    victims = [{"id": v.id, "mobile": v.mobile}
               for v in db_session.query(Victim).all()]
    txns = [{"victim_id": t.victim_id, "amount": t.amount, "upi_id": t.upi_id,
             "recipient_name": t.recipient_name, "account_last4": t.account_last4,
             "apk_id": t.apk_id} for t in db_session.query(Transaction).all()]

    dedup = dedupe_victims(victims)
    return {
        "unique_victims": len(dedup),
        "total_victim_rows": len(victims),
        "mules": rank_mules(txns),
    }


if __name__ == "__main__":
    # ponytail self-check: the mule pulling from the most victims ranks first;
    # duplicate victim mobiles collapse.
    victims = [{"id": 1, "mobile": "+91 98765 43210"}, {"id": 2, "mobile": "9876543210"},
               {"id": 3, "mobile": "9000000000"}]
    assert len(dedupe_victims(victims)) == 2, "duplicate mobiles must merge"

    txns = [
        {"victim_id": 1, "amount": 5000, "upi_id": "mule1@ybl", "apk_id": "X"},
        {"victim_id": 2, "amount": 8000, "upi_id": "mule1@ybl", "apk_id": "Y"},
        {"victim_id": 3, "amount": 3000, "upi_id": "mule1@ybl", "apk_id": "X"},
        {"victim_id": 1, "amount": 2000, "upi_id": "mule2@ybl", "apk_id": "X"},
    ]
    ranked = rank_mules(txns)
    assert ranked[0]["mule"] == "upi:mule1@ybl", ranked
    assert ranked[0]["victim_count"] == 3 and ranked[0]["campaign_count"] == 2, ranked
    print(f"OK — top mule={ranked[0]['mule']} victims={ranked[0]['victim_count']} "
          f"campaigns={ranked[0]['campaign_count']} centrality={ranked[0]['centrality']}")
