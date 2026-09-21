"""
Money Flow Graph
Builds a directed graph of financial transactions:
  Victims → UPI Mule Accounts → Named Recipients (layering chain)

Outputs:
  1. PNG court exhibit (matplotlib)
  2. JSON graph data for D3.js interactive web view
  3. Text summary of all paths
"""

import os
import json
from collections import defaultdict
from datetime import datetime
from typing import Optional

try:
    import networkx as nx
    HAS_NX = True
except ImportError:
    HAS_NX = False

try:
    import matplotlib
    matplotlib.use("Agg")   # headless
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MPL = True
except ImportError:
    HAS_MPL = False


# Node type constants
NODE_VICTIM    = "victim"
NODE_MULE      = "mule"
NODE_RECIPIENT = "recipient"
NODE_ATTACKER  = "attacker"


def build_graph(apk_id: str, db_session) -> Optional["nx.DiGraph"]:
    """
    Build the money flow directed graph from Transaction table.
    Returns a NetworkX DiGraph or None if networkx not installed.
    """
    if not HAS_NX:
        return None

    from db.models import Transaction, Victim, Lead

    txns    = db_session.query(Transaction).filter_by(apk_id=apk_id).all()
    victims = {v.id: v for v in db_session.query(Victim).filter_by(apk_id=apk_id).all()}

    G = nx.DiGraph()

    # Edge weight accumulator: (src, dst) → total amount
    edge_amounts: dict[tuple, float] = defaultdict(float)
    edge_counts:  dict[tuple, int]   = defaultdict(int)

    for txn in txns:
        # Victim node
        v = victims.get(txn.victim_id)
        v_label = v.mobile or v.full_name or f"victim_{txn.victim_id}" if v else f"victim_{txn.victim_id}"
        v_node  = f"V:{v_label}"
        if not G.has_node(v_node):
            G.add_node(v_node,
                       node_type   = NODE_VICTIM,
                       label       = v_label,
                       risk_level  = v.risk_level if v else "UNKNOWN",
                       total_lost  = 0.0)
        G.nodes[v_node]["total_lost"] = G.nodes[v_node].get("total_lost", 0) + txn.amount

        # Destination: UPI mule or named recipient
        if txn.upi_id:
            dst_node  = f"UPI:{txn.upi_id}"
            dst_label = txn.upi_id
            if not G.has_node(dst_node):
                G.add_node(dst_node,
                           node_type    = NODE_MULE,
                           label        = dst_label,
                           total_recv   = 0.0,
                           victim_count = 0)
            G.nodes[dst_node]["total_recv"] = G.nodes[dst_node].get("total_recv", 0) + txn.amount
        elif txn.recipient_name:
            dst_node  = f"NAME:{txn.recipient_name.upper()}"
            dst_label = txn.recipient_name.upper()
            if not G.has_node(dst_node):
                G.add_node(dst_node,
                           node_type    = NODE_RECIPIENT,
                           label        = dst_label,
                           total_recv   = 0.0)
            G.nodes[dst_node]["total_recv"] = G.nodes[dst_node].get("total_recv", 0) + txn.amount
        else:
            continue

        edge_amounts[(v_node, dst_node)] += txn.amount
        edge_counts [(v_node, dst_node)] += 1

    # Add edges with weights
    for (src, dst), amt in edge_amounts.items():
        G.add_edge(src, dst,
                   weight    = amt,
                   txn_count = edge_counts[(src, dst)])

    # Compute victim_count per mule node
    for dst_node in G.nodes:
        if G.nodes[dst_node].get("node_type") == NODE_MULE:
            G.nodes[dst_node]["victim_count"] = len(list(G.predecessors(dst_node)))

    return G


def export_png(G, out_path: str, title: str = "Money Flow Graph") -> str:
    """Render the graph to a PNG court exhibit."""
    if not HAS_MPL or not HAS_NX or G is None:
        return ""

    fig, ax = plt.subplots(figsize=(20, 14))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#0d1117")
    ax.set_title(title, color="white", fontsize=14, fontweight="bold", pad=16)

    # Layout: victims on left, mules in middle, recipients on right
    victims    = [n for n, d in G.nodes(data=True) if d.get("node_type") == NODE_VICTIM]
    mules      = [n for n, d in G.nodes(data=True) if d.get("node_type") == NODE_MULE]
    recipients = [n for n, d in G.nodes(data=True) if d.get("node_type") == NODE_RECIPIENT]

    pos = {}
    for i, n in enumerate(victims):
        pos[n] = (0, i - len(victims)/2)
    for i, n in enumerate(mules):
        pos[n] = (2, i - len(mules)/2)
    for i, n in enumerate(recipients):
        pos[n] = (4, i - len(recipients)/2)

    color_map = {NODE_VICTIM: "#f85149", NODE_MULE: "#d29922", NODE_RECIPIENT: "#58a6ff"}
    node_colors = [color_map.get(G.nodes[n].get("node_type"), "#8b949e") for n in G.nodes]
    node_sizes  = []
    for n in G.nodes:
        ntype = G.nodes[n].get("node_type")
        if ntype == NODE_VICTIM:
            node_sizes.append(300)
        elif ntype == NODE_MULE:
            amt = G.nodes[n].get("total_recv", 0) / 10_000
            node_sizes.append(min(3000, max(500, amt)))
        else:
            node_sizes.append(700)

    # Edge weights for line thickness
    edges      = list(G.edges(data=True))
    max_weight = max((d.get("weight", 1) for _, _, d in edges), default=1)
    widths     = [max(0.5, (d.get("weight", 1) / max_weight) * 5) for _, _, d in edges]

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.9, ax=ax)
    nx.draw_networkx_edges(G, pos, width=widths, edge_color="#30363d",
                           arrows=True, arrowsize=15, ax=ax,
                           connectionstyle="arc3,rad=0.1")

    # Labels — only for mule/recipient nodes (too many victims)
    label_nodes = {n: G.nodes[n].get("label", n)[:30]
                   for n in G.nodes
                   if G.nodes[n].get("node_type") in (NODE_MULE, NODE_RECIPIENT)}
    nx.draw_networkx_labels(G, pos, labels=label_nodes, font_size=7,
                            font_color="white", ax=ax)

    legend = [
        mpatches.Patch(color="#f85149", label=f"Victims ({len(victims)})"),
        mpatches.Patch(color="#d29922", label=f"UPI Mule Accounts ({len(mules)})"),
        mpatches.Patch(color="#58a6ff", label=f"Named Recipients ({len(recipients)})"),
    ]
    ax.legend(handles=legend, loc="lower right", facecolor="#161b22",
              labelcolor="white", fontsize=9)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, facecolor="#0d1117", bbox_inches="tight")
    plt.close(fig)
    return out_path


def export_json(G, out_path: str) -> str:
    """Export graph as D3.js compatible JSON for interactive web view."""
    if G is None:
        return ""

    nodes = []
    for node_id, data in G.nodes(data=True):
        nodes.append({
            "id"          : node_id,
            "label"       : data.get("label", node_id)[:40],
            "type"        : data.get("node_type", "unknown"),
            "total_recv"  : round(data.get("total_recv", 0), 2),
            "total_lost"  : round(data.get("total_lost", 0), 2),
            "victim_count": data.get("victim_count", 0),
            "risk_level"  : data.get("risk_level", ""),
        })

    links = []
    for src, dst, data in G.edges(data=True):
        links.append({
            "source"   : src,
            "target"   : dst,
            "amount"   : round(data.get("weight", 0), 2),
            "txn_count": data.get("txn_count", 0),
        })

    graph_data = {
        "generated_at": datetime.now().isoformat(),
        "node_count"  : G.number_of_nodes(),
        "edge_count"  : G.number_of_edges(),
        "total_flow"  : round(sum(d.get("weight", 0) for _, _, d in G.edges(data=True)), 2),
        "nodes"       : nodes,
        "links"       : links,
    }

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(graph_data, f, indent=2)
    return out_path


def generate_text_summary(G, out_path: str) -> str:
    """Write a text summary of top money flows for court report."""
    if G is None:
        return ""

    mules = [(n, d) for n, d in G.nodes(data=True) if d.get("node_type") == NODE_MULE]
    mules.sort(key=lambda x: -x[1].get("total_recv", 0))

    lines = [
        "=" * 72,
        "  MONEY FLOW ANALYSIS — TOP MULE ACCOUNTS",
        "=" * 72, "",
    ]
    for mule_id, mdata in mules[:20]:
        victims_in = list(G.predecessors(mule_id))
        lines += [
            f"  MULE : {mdata.get('label', mule_id)}",
            f"  Received : Rs. {mdata.get('total_recv', 0):,.2f}",
            f"  From     : {len(victims_in)} victim(s)",
            f"  Top victims:",
        ]
        for v in victims_in[:5]:
            amt = G.edges[v, mule_id].get("weight", 0)
            lines.append(f"    • {G.nodes[v].get('label', v)[:30]}  →  Rs. {amt:,.2f}")
        lines.append("")

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out_path


def run(apk_id: str, db_session, out_dir: str) -> dict:
    """Full pipeline: build graph → export PNG + JSON + text summary."""
    os.makedirs(out_dir, exist_ok=True)

    G = build_graph(apk_id, db_session)

    results = {
        "node_count"  : G.number_of_nodes() if G else 0,
        "edge_count"  : G.number_of_edges() if G else 0,
        "total_flow"  : 0.0,
        "png_path"    : "",
        "json_path"   : "",
        "txt_path"    : "",
        "available"   : HAS_NX,
    }

    if G is None or G.number_of_nodes() == 0:
        return results

    total = sum(d.get("weight", 0) for _, _, d in G.edges(data=True))
    results["total_flow"] = round(total, 2)

    from db.models import Apk
    apk_row = db_session.get(Apk, apk_id)
    title = f"TGCSB Money Flow — {apk_row.firebase_project if apk_row else apk_id[:16]}"

    png_path  = os.path.join(out_dir, "MONEY_FLOW_GRAPH.png")
    json_path = os.path.join(out_dir, "money_flow_data.json")
    txt_path  = os.path.join(out_dir, "MONEY_FLOW_SUMMARY.txt")

    results["png_path"]  = export_png(G, png_path, title)
    results["json_path"] = export_json(G, json_path)
    results["txt_path"]  = generate_text_summary(G, txt_path)

    return results
