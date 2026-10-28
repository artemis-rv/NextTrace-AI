"""Graph construction: one temporal state -> GraphSnapshotV1 (owner: Person 1, data from the central repository).

Nodes are hosts (pseudonymised), edges are aggregated host->host traffic in the window with EDGE_FEATURES_V1.
Node features are degree-based by default; Person 1 may extend them under a new node feature schema.
"""
from __future__ import annotations

from collections import defaultdict
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.contracts.temporal import GraphEdgeV1, GraphNodeV1, GraphSnapshotV1
from nextrace.contracts.v1 import FlowRecordV1, TemporalStateV1
from nextrace.services.security import pseudonymize_ip


class DbGraphBuilder:
    """Reads state_edges + hosts for a persisted state."""

    def __init__(self, conn: Connection, edge_feature_schema_id: UUID):
        self.conn = conn
        self.edge_schema = edge_feature_schema_id

    def build(self, state: TemporalStateV1) -> GraphSnapshotV1:
        rows = self.conn.execute(text(
            "SELECT e.src_host_id, e.dst_host_id, e.features, hs.pseudonym AS sp, hs.zone AS sz, hs.asset_tag AS sa, "
            "hd.pseudonym AS dp, hd.zone AS dz, hd.asset_tag AS da FROM state_edges e "
            "JOIN hosts hs ON hs.host_id = e.src_host_id JOIN hosts hd ON hd.host_id = e.dst_host_id "
            "WHERE e.state_id = :s AND e.window_start = :w"), {"s": state.state_id, "w": state.window_start}).mappings().all()
        return _assemble(state, [(r["src_host_id"], bytes(r["sp"]).hex(), r["sz"], r["sa"], r["dst_host_id"], bytes(r["dp"]).hex(), r["dz"], r["da"],
                                  [float(x) for x in r["features"]]) for r in rows], self.edge_schema)


class InMemoryGraphBuilder:
    """Builds the graph from the flows of a window without the database (replay/tests). Host ids are derived
    deterministically from the pseudonym so they are stable across runs; the DB assigns real host ids on persist."""

    def __init__(self, edge_feature_schema_id: UUID, pepper: str | None = None):
        self.edge_schema = edge_feature_schema_id
        self.pepper = pepper

    def build_from_flows(self, state: TemporalStateV1, flows: list[FlowRecordV1]) -> GraphSnapshotV1:
        agg: dict[tuple[str, str], dict] = defaultdict(lambda: {"n": 0, "bytes": 0, "pkts": 0, "ports": set(), "dur": 0.0, "durn": 0})
        for f in flows:
            a = agg[(str(f.src_ip), str(f.dst_ip))]
            a["n"] += 1; a["bytes"] += f.orig_bytes + f.resp_bytes; a["pkts"] += f.orig_pkts + f.resp_pkts
            if f.dst_port is not None:
                a["ports"].add(f.dst_port)
            if f.duration_ms is not None:
                a["dur"] += f.duration_ms; a["durn"] += 1
        rows = []
        for (s, d), a in agg.items():
            sp, dp = pseudonymize_ip(s, self.pepper).hex(), pseudonymize_ip(d, self.pepper).hex()
            rows.append((UUID(sp[:32]), sp, None, None, UUID(dp[:32]), dp, None, None,
                         [float(a["n"]), float(a["bytes"]), float(a["pkts"]), float(len(a["ports"])), a["dur"] / a["durn"] if a["durn"] else 0.0]))
        return _assemble(state, rows, self.edge_schema)


def _assemble(state: TemporalStateV1, rows, edge_schema: UUID) -> GraphSnapshotV1:
    index: dict[UUID, int] = {}
    nodes: list[GraphNodeV1] = []
    deg_out: dict[int, float] = defaultdict(float)
    deg_in: dict[int, float] = defaultdict(float)
    edges: list[GraphEdgeV1] = []

    def node(hid: UUID, pseud: str, zone, tag) -> int:
        if hid not in index:
            index[hid] = len(nodes)
            nodes.append(GraphNodeV1(host_id=hid, pseudonym=pseud, zone=zone, asset_tag=tag))
        return index[hid]

    for sid, sp, sz, sa, did, dp, dz, da, feats in rows:
        s, d = node(sid, sp, sz, sa), node(did, dp, dz, da)
        edges.append(GraphEdgeV1(src=s, dst=d, features=feats))
        deg_out[s] += feats[0]; deg_in[d] += feats[0]
    nodes = [n.model_copy(update={"features": [deg_out[i], deg_in[i]]}) for i, n in enumerate(nodes)]
    return GraphSnapshotV1(state_id=state.state_id, sensor_id=state.sensor_id, window_start=state.window_start,
                           window_seconds=state.window_seconds, edge_feature_schema_id=edge_schema, nodes=nodes, edges=edges)
