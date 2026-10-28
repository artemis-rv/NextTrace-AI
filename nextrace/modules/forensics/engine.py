"""Forensic job engine implementing contracts.ports.ForensicEngine (owner: Person 3).

Separate from live capture: it reads only uploads and evidence objects from the object store, runs bounded
rule-based analyses, writes findings and a report object, and links results to investigations only through the
authorized investigations service. Rules are heuristics with stated parameters, not detections of record.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import statistics
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Callable, ContextManager
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.contracts.errors import ContractViolation, Forbidden, NotFound, PayloadTooLarge
from nextrace.contracts.forensics import ForensicArtifactV1, ForensicFindingV1, ForensicJobRequestV1, ForensicJobStatusV1, ForensicReportV1
from nextrace.contracts.v1 import FlowRecordV1
from nextrace.parsing.decode import decode
from nextrace.parsing.flows import FlowAssembler
from nextrace.services import audit, investigations
from nextrace.services.security import safe_filename
from nextrace.storage import pcap as pcapmod
from nextrace.storage.object_store import LocalObjectStore, ObjectRef

PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
TOOL, TOOL_VERSION = "nextrace-forensics", "0.2.0"
ConnFactory = Callable[[], ContextManager[Connection]]


# -- uploads --------------------------------------------------------------------------------------
def register_upload(conn: Connection, store: LocalObjectStore, user_id: UUID, filename: str, stream: BinaryIO, declared_media_type: str,
                    max_bytes: int, investigation_id: UUID | None = None) -> UUID:
    """Size-bounded, signature-checked upload (OWASP File Upload Cheat Sheet). The stored name is the hash, never the filename."""
    name = safe_filename(filename)
    if investigation_id is not None:
        investigations.require_access(conn, user_id, investigation_id, "metadata")
    head = stream.read(4)
    if head in PCAP_MAGICS:
        media = "application/vnd.tcpdump.pcap"
    elif head == PCAPNG_MAGIC:
        media = "application/x-pcapng"
    else:
        raise ContractViolation("file signature is not pcap/pcapng")
    if declared_media_type != media:
        raise ContractViolation("declared media type does not match file signature")
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(head)
        size = 4
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                tmp.close(); Path(tmp.name).unlink(missing_ok=True)
                raise PayloadTooLarge("upload exceeds the configured limit")
            tmp.write(chunk)
        path = Path(tmp.name)
    try:
        info = pcapmod.scan(path)  # also rejects files that do not parse at all
        ref = store.put_path(path, "upload")
    except Exception as e:
        path.unlink(missing_ok=True)
        raise ContractViolation(f"capture file rejected: {type(e).__name__}") from e
    path.unlink(missing_ok=True)
    investigations.register_object(conn, ref, "upload", media)
    uid = conn.execute(text(
        "INSERT INTO uploads (user_id, investigation_id, original_filename, media_type, size_bytes, object_sha256, status) "
        "VALUES (:u, :i, :n, :m, :s, :h, 'validated') RETURNING upload_id"),
        {"u": user_id, "i": investigation_id, "n": name, "m": media, "s": ref.size_bytes, "h": ref.sha256}).scalar_one()
    audit.record(conn, "upload.accept", object_type="upload", object_id=uid, actor_id=user_id,
                 details={"sha256": ref.hex, "size": ref.size_bytes, "packets": info.packet_count})
    return uid


# -- analyses -------------------------------------------------------------------------------------
def _flows_from_pcap(path: Path, sensor_id: UUID, budget_packets: int = 5_000_000) -> tuple[list[FlowRecordV1], dict[str, int]]:
    asm = FlowAssembler()
    flows: list[FlowRecordV1] = []
    n = 0
    info = pcapmod.scan(path)
    for ts, data, wirelen, link in pcapmod.iter_packets(path):
        n += 1
        if n > budget_packets:
            break
        flows.extend(asm.feed(decode(ts, data, wirelen, link if link is not None else (info.link_type or 1), sensor_id)))
    flows.extend(asm.flush())
    flows.sort(key=lambda f: f.ts_start)
    return flows, {"packets": n, "malformed": asm.stats.skipped_malformed, "non_ip": asm.stats.skipped_non_ip, "truncated_at_budget": int(n > budget_packets)}


def rule_scan_detection(flows: list[FlowRecordV1], params: dict[str, Any]) -> list[ForensicFindingV1]:
    """Per source: many distinct destination ports or hosts with mostly failed connections. Heuristic (RESEARCH REQUIRED)."""
    min_ports = int(params.get("min_ports", 20)); min_hosts = int(params.get("min_hosts", 20))
    by_src: dict[str, dict] = defaultdict(lambda: {"ports": set(), "hosts": set(), "failed": 0, "n": 0, "first": None, "last": None})
    for f in flows:
        a = by_src[str(f.src_ip)]
        a["ports"].add(f.dst_port); a["hosts"].add(str(f.dst_ip)); a["n"] += 1
        a["failed"] += f.conn_state in ("S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR")
        a["first"] = f.ts_start if a["first"] is None else min(a["first"], f.ts_start)
        a["last"] = f.ts_end or f.ts_start if a["last"] is None else max(a["last"], f.ts_end or f.ts_start)
    out = []
    for src, a in by_src.items():
        if len(a["ports"]) >= min_ports or len(a["hosts"]) >= min_hosts:
            fail_ratio = a["failed"] / a["n"]
            kind = "port scan" if len(a["ports"]) >= min_ports else "host sweep"
            out.append(ForensicFindingV1(seq=1, ts=a["first"], src_ip=src, technique_id="T1046", rule_id="scan_detection.v1",
                                         description=f"{kind} from {src}: {len(a['ports'])} ports, {len(a['hosts'])} hosts, {a['n']} flows, "
                                                     f"failed ratio {fail_ratio:.2f}, until {a['last'].isoformat()}",
                                         confidence=round(min(1.0, 0.5 + 0.5 * fail_ratio), 3)))
    return out


def rule_beacon_detection(flows: list[FlowRecordV1], params: dict[str, Any]) -> list[ForensicFindingV1]:
    """Periodic connections to the same (dst, port): low inter-arrival jitter. Heuristic (RESEARCH REQUIRED)."""
    min_flows = int(params.get("min_flows", 10)); max_cv = float(params.get("max_cv", 0.2))
    groups: dict[tuple, list[datetime]] = defaultdict(list)
    for f in flows:
        groups[(str(f.src_ip), str(f.dst_ip), f.dst_port, f.proto)].append(f.ts_start)
    out = []
    for (s, d, port, proto), ts in groups.items():
        if len(ts) < min_flows:
            continue
        ts.sort()
        gaps = [(b - a).total_seconds() for a, b in zip(ts, ts[1:]) if (b - a).total_seconds() > 0]
        if len(gaps) < min_flows - 1:
            continue
        mean = statistics.fmean(gaps); cv = statistics.pstdev(gaps) / mean if mean else 1.0
        if cv <= max_cv:
            out.append(ForensicFindingV1(seq=1, ts=ts[0], src_ip=s, dst_ip=d, technique_id="T1071", rule_id="beacon_detection.v1",
                                         description=f"periodic connections {s} -> {d}:{port}/{proto}: {len(ts)} flows, period {mean:.1f}s, cv {cv:.2f}",
                                         confidence=round(max(0.0, 1.0 - cv / max_cv) * 0.8, 3)))
    return out


def rule_timeline(flows: list[FlowRecordV1], params: dict[str, Any]) -> list[ForensicFindingV1]:
    first: dict[str, FlowRecordV1] = {}
    for f in flows:
        for ip in (str(f.src_ip), str(f.dst_ip)):
            if ip not in first:
                first[ip] = f
    return [ForensicFindingV1(seq=1, ts=f.ts_start, src_ip=ip, rule_id="timeline.v1", description=f"first activity of {ip}") for ip, f in
            sorted(first.items(), key=lambda kv: kv[1].ts_start)[: int(params.get("max_hosts", 500))]]


RULES = {"scan_detection": rule_scan_detection, "beacon_detection": rule_beacon_detection, "timeline": rule_timeline}


class DbForensicEngine:
    def __init__(self, conn_factory: ConnFactory, store: LocalObjectStore, packet_budget: int = 5_000_000):
        self.conn_factory = conn_factory
        self.store = store
        self.packet_budget = packet_budget

    # -- port -----------------------------------------------------------------------------------
    def submit(self, request: ForensicJobRequestV1) -> UUID:
        with self.conn_factory() as conn:
            if request.investigation_id is not None:
                investigations.require_access(conn, request.requested_by, request.investigation_id, "metadata")
            if request.upload_id is not None:
                up = conn.execute(text("SELECT user_id, investigation_id, status FROM uploads WHERE upload_id = :u"), {"u": request.upload_id}).first()
                if up is None:
                    raise NotFound("upload not found")
                if up.status not in ("validated", "processed"):
                    raise ContractViolation("upload is not validated")
                if up.user_id != request.requested_by and not (up.investigation_id and investigations.has_access(conn, request.requested_by, up.investigation_id, "metadata")):
                    raise Forbidden("not your upload and no case access")
            if request.evidence_id is not None:
                ev = conn.execute(text("SELECT investigation_id, kind FROM evidence_items WHERE evidence_id = :e"), {"e": request.evidence_id}).first()
                if ev is None:
                    raise NotFound("evidence not found")
                investigations.require_access(conn, request.requested_by, ev.investigation_id, "full_pcap" if ev.kind in ("pcap_slice", "upload") else "metadata")
            aid = conn.execute(text(
                "INSERT INTO forensic_analyses (investigation_id, upload_id, evidence_id, requested_by, params) VALUES (:i, :u, :e, :r, CAST(:p AS jsonb)) RETURNING analysis_id"),
                {"i": request.investigation_id, "u": request.upload_id, "e": request.evidence_id, "r": request.requested_by,
                 "p": json.dumps({"analyses": request.analyses, "params": request.params, "time_budget_s": request.time_budget_s})}).scalar_one()
            audit.record(conn, "forensics.submit", object_type="forensic_analysis", object_id=aid, actor_id=request.requested_by, details={"analyses": request.analyses})
            return aid

    def run_next(self) -> ForensicJobStatusV1 | None:
        with self.conn_factory() as conn:
            row = conn.execute(text("SELECT * FROM forensic_analyses WHERE status = 'queued' ORDER BY analysis_id FOR UPDATE SKIP LOCKED LIMIT 1")).mappings().first()
            if row is None:
                return None
            aid = row["analysis_id"]
            conn.execute(text("UPDATE forensic_analyses SET status = 'running', started_at = now() WHERE analysis_id = :a"), {"a": aid})
            try:
                status = self._run(conn, dict(row))
            except Exception as e:  # noqa: BLE001 - record the failure, never leave the row 'running'
                conn.execute(text("UPDATE forensic_analyses SET status = 'failed', completed_at = now(), error = :e WHERE analysis_id = :a"),
                             {"e": f"{type(e).__name__}: {str(e)[:500]}", "a": aid})
                audit.record(conn, "forensics.fail", object_type="forensic_analysis", object_id=aid, details={"error": type(e).__name__})
                return self.status(aid, conn)
            return status

    def _source_ref(self, conn: Connection, row: dict) -> tuple[ObjectRef, str]:
        if row["upload_id"] is not None:
            r = conn.execute(text("SELECT o.sha256, o.size_bytes, o.storage_path, o.deleted_at FROM uploads u JOIN objects o ON o.sha256 = u.object_sha256 "
                                  "WHERE u.upload_id = :u"), {"u": row["upload_id"]}).first()
        else:
            r = conn.execute(text("SELECT o.sha256, o.size_bytes, o.storage_path, o.deleted_at FROM evidence_items e JOIN objects o ON o.sha256 = e.object_sha256 "
                                  "WHERE e.evidence_id = :e"), {"e": row["evidence_id"]}).first()
        if r is None or r.deleted_at is not None:
            raise NotFound("source object missing or reclaimed")
        return ObjectRef(bytes(r.sha256), int(r.size_bytes), r.storage_path), bytes(r.sha256).hex()

    def _run(self, conn: Connection, row: dict) -> ForensicJobStatusV1:
        aid = row["analysis_id"]
        params = row["params"] if isinstance(row["params"], dict) else json.loads(row["params"])
        ref, src_hex = self._source_ref(conn, row)
        if not self.store.verify(ref):
            raise RuntimeError("source object failed integrity verification")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "source.pcap"
            self.store.copy_out(ref, path)
            flows, parse_stats = _flows_from_pcap(path, row["requested_by"], self.packet_budget)
        findings: list[ForensicFindingV1] = []
        artifacts: list[ForensicArtifactV1] = []
        limitations = ["rule-based heuristics with stated parameters; not validated detections",
                       "payloads were not inspected; header/flow level only"]
        if parse_stats["truncated_at_budget"]:
            limitations.append(f"analysis stopped at the packet budget ({self.packet_budget})")
        for kind in params["analyses"]:
            if kind == "flow_reconstruction":
                buf = io.BytesIO()
                with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
                    w = csv.writer(io.TextIOWrapper(gz, encoding="utf-8", newline="", write_through=True))
                    w.writerow(["ts_start", "ts_end", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "conn_state", "history"])
                    for f in flows:
                        w.writerow([f.ts_start.isoformat(), f.ts_end.isoformat() if f.ts_end else "", f.src_ip, f.src_port, f.dst_ip, f.dst_port, f.proto,
                                    f.orig_bytes, f.resp_bytes, f.orig_pkts, f.resp_pkts, f.conn_state or "", f.history or ""])
                aref = self.store.put_bytes(buf.getvalue(), "export")
                investigations.register_object(conn, aref, "export", "application/gzip")
                artifacts.append(ForensicArtifactV1(sha256=aref.hex, size_bytes=aref.size_bytes, media_type="application/gzip", kind="export",
                                                    derived_from_sha256=src_hex, tool=TOOL, tool_version=TOOL_VERSION, produced_at=datetime.now(timezone.utc)))
            elif kind in RULES:
                findings.extend(RULES[kind](flows, params.get("params", {})))
            else:
                limitations.append(f"analysis '{kind}' is not implemented")
        findings.sort(key=lambda f: f.ts)
        findings = [f.model_copy(update={"seq": i}) for i, f in enumerate(findings, start=1)]
        if findings:
            conn.execute(text(
                "INSERT INTO forensic_findings (analysis_id, seq, ts, src_ip, dst_ip, technique_id, description, confidence) "
                "VALUES (:a, :seq, :ts, CAST(:s AS inet), CAST(:d AS inet), :t, :desc, :c)"),
                [{"a": aid, "seq": f.seq, "ts": f.ts, "s": str(f.src_ip) if f.src_ip else None, "d": str(f.dst_ip) if f.dst_ip else None,
                  "t": f.technique_id, "desc": f.description, "c": f.confidence} for f in findings])
        report = ForensicReportV1(analysis_id=aid, investigation_id=row["investigation_id"], generated_at=datetime.now(timezone.utc), source_sha256=src_hex,
                                  analyses=params["analyses"], summary={"flows": len(flows), **parse_stats, "findings": len(findings)},
                                  findings=findings, artifacts=artifacts, limitations=limitations)
        rref = self.store.put_bytes(report.model_dump_json().encode(), "report")
        investigations.register_object(conn, rref, "report", "application/json")
        conn.execute(text("UPDATE forensic_analyses SET status = 'completed', completed_at = now(), result_sha256 = :r, summary = CAST(:s AS jsonb) WHERE analysis_id = :a"),
                     {"r": rref.sha256, "s": json.dumps(report.summary), "a": aid})
        if row["upload_id"] is not None:
            conn.execute(text("UPDATE uploads SET status = 'processed' WHERE upload_id = :u"), {"u": row["upload_id"]})
        audit.record(conn, "forensics.complete", object_type="forensic_analysis", object_id=aid, details={"findings": len(findings), "report": rref.hex})
        return self.status(aid, conn)

    def status(self, analysis_id: UUID, conn: Connection | None = None) -> ForensicJobStatusV1:
        def _q(c: Connection) -> ForensicJobStatusV1:
            r = c.execute(text("SELECT a.status, a.started_at, a.completed_at, a.error, encode(a.result_sha256,'hex') AS res, "
                               "(SELECT count(*) FROM forensic_findings f WHERE f.analysis_id = a.analysis_id) AS n FROM forensic_analyses a WHERE a.analysis_id = :a"),
                          {"a": analysis_id}).mappings().first()
            if r is None:
                raise NotFound("analysis not found")
            return ForensicJobStatusV1(analysis_id=analysis_id, status=r["status"], started_at=r["started_at"], completed_at=r["completed_at"],
                                       progress=1.0 if r["status"] in ("completed", "failed") else 0.0, error=r["error"], finding_count=int(r["n"]), result_sha256=r["res"])
        if conn is not None:
            return _q(conn)
        with self.conn_factory() as c:
            return _q(c)

    def report(self, analysis_id: UUID, actor_id: UUID) -> ForensicReportV1:
        with self.conn_factory() as conn:
            r = conn.execute(text("SELECT a.requested_by, a.investigation_id, a.status, o.sha256, o.size_bytes, o.storage_path FROM forensic_analyses a "
                                  "LEFT JOIN objects o ON o.sha256 = a.result_sha256 WHERE a.analysis_id = :a"), {"a": analysis_id}).first()
            if r is None:
                raise NotFound("analysis not found")
            if r.investigation_id is not None:
                investigations.require_access(conn, actor_id, r.investigation_id, "metadata")
            elif r.requested_by != actor_id:
                role = conn.execute(text("SELECT role FROM users WHERE user_id = :u AND active"), {"u": actor_id}).scalar()
                if role != "admin":
                    raise Forbidden("report belongs to another user")
            if r.status != "completed" or r.sha256 is None:
                raise NotFound("report not available")
            ref = ObjectRef(bytes(r.sha256), int(r.size_bytes), r.storage_path)
            if not self.store.verify(ref):
                raise RuntimeError("report failed integrity verification")
            with self.store.open(ref) as fh:
                rep = ForensicReportV1.model_validate_json(fh.read())
            audit.record(conn, "forensics.report_read", object_type="forensic_analysis", object_id=analysis_id, actor_id=actor_id)
            return rep

    def link_finding(self, finding_id: UUID, investigation_id: UUID, actor_id: UUID, note: str | None = None) -> None:
        """Authorized linking is the only bridge from the historical pipeline into live investigations."""
        with self.conn_factory() as conn:
            exists = conn.execute(text("SELECT 1 FROM forensic_findings WHERE finding_id = :f"), {"f": finding_id}).scalar()
            if not exists:
                raise NotFound("finding not found")
            investigations.link_object(conn, investigation_id, "forensic_finding", finding_id, actor_id, note)
            audit.record(conn, "forensics.link", object_type="forensic_finding", object_id=finding_id, actor_id=actor_id,
                         details={"investigation_id": str(investigation_id)})
