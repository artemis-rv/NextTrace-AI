"""Person 3 module: validated uploads, authorized jobs, rule findings, reports, linking into investigations."""
from __future__ import annotations

import io
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from nextrace.contracts.errors import ContractViolation, Forbidden, NotFound, PayloadTooLarge
from nextrace.contracts.forensics import ForensicJobRequestV1
from nextrace.modules.forensics.engine import DbForensicEngine, register_upload
from nextrace.services import investigations
from nextrace.services.security import AuthorizationError
from tests.backend_helpers import an_hour_ago, savepoint, scenario_packets, write_pcap

PCAP = "application/vnd.tcpdump.pcap"


@pytest.fixture
def pcap_bytes(tmp_path):
    return write_pcap(tmp_path / "f.pcap", scenario_packets(an_hour_ago(), beacon_count=15, beacon_period_s=20.0)).read_bytes()


def test_upload_validation(conn, store, seed, pcap_bytes):
    u = seed["users"]["analyst"]
    with pytest.raises(ContractViolation):
        register_upload(conn, store, u, "x.pcap", io.BytesIO(b"not a pcap at all"), PCAP, 10 ** 7)
    with pytest.raises(ContractViolation):
        register_upload(conn, store, u, "x.pcap", io.BytesIO(pcap_bytes), "application/x-pcapng", 10 ** 7)   # declared type lies
    with pytest.raises(PayloadTooLarge):
        register_upload(conn, store, u, "x.pcap", io.BytesIO(pcap_bytes), PCAP, 1000)
    with pytest.raises(ValueError):
        register_upload(conn, store, u, "../../etc/passwd\x00.pcap", io.BytesIO(pcap_bytes), PCAP, 10 ** 7)
    uid = register_upload(conn, store, u, "capture one.pcap", io.BytesIO(pcap_bytes), PCAP, 10 ** 7)
    row = conn.execute(text("SELECT status, original_filename, size_bytes FROM uploads WHERE upload_id = :u"), {"u": uid}).first()
    assert row.status == "validated" and row.original_filename == "capture one.pcap" and row.size_bytes == len(pcap_bytes)
    assert store.usage_bytes("upload") == len(pcap_bytes)


def test_job_runs_finds_scan_and_beacon_and_reports_with_authz(conn, store, seed, pcap_bytes):
    users = seed["users"]
    eng = DbForensicEngine(lambda: savepoint(conn), store)
    uid = register_upload(conn, store, users["analyst"], "f.pcap", io.BytesIO(pcap_bytes), PCAP, 10 ** 7)
    # another analyst cannot analyse my upload without case access
    with pytest.raises(Forbidden):
        eng.submit(ForensicJobRequestV1(requested_by=users["analyst2"], upload_id=uid, analyses=["scan_detection"]))
    aid = eng.submit(ForensicJobRequestV1(requested_by=users["analyst"], upload_id=uid,
                                          analyses=["flow_reconstruction", "scan_detection", "beacon_detection", "timeline", "ioc_match"],
                                          params={"min_ports": 50, "min_flows": 10, "max_cv": 0.2}))
    assert eng.status(aid).status == "queued"
    st = eng.run_next()
    assert st is not None and st.status == "completed" and st.finding_count > 0 and st.result_sha256
    assert eng.run_next() is None
    rep = eng.report(aid, users["analyst"])
    rules = {f.rule_id for f in rep.findings}
    assert "scan_detection.v1" in rules and "beacon_detection.v1" in rules and "timeline.v1" in rules
    scan = [f for f in rep.findings if f.rule_id == "scan_detection.v1"]
    assert str(scan[0].src_ip) == "10.0.0.99" and scan[0].technique_id == "T1046"
    beacon = [f for f in rep.findings if f.rule_id == "beacon_detection.v1"]
    assert str(beacon[0].dst_ip) == "203.0.113.5" and beacon[0].technique_id == "T1071"
    assert any("ioc_match" in lim for lim in rep.limitations) and rep.artifacts and rep.artifacts[0].derived_from_sha256 == rep.source_sha256
    assert [f.seq for f in rep.findings] == list(range(1, len(rep.findings) + 1))
    assert conn.execute(text("SELECT status FROM uploads WHERE upload_id = :u"), {"u": uid}).scalar() == "processed"
    with pytest.raises(Forbidden):
        eng.report(aid, users["analyst2"])
    assert eng.report(aid, users["admin"]).analysis_id == aid


def test_case_scoped_job_and_authorized_linking(conn, store, seed, pcap_bytes):
    users = seed["users"]
    eng = DbForensicEngine(lambda: savepoint(conn), store)
    case = investigations.open_case(conn, "CASE-F1", "forensic case", "high", users["dfir"])
    with pytest.raises(AuthorizationError):
        register_upload(conn, store, users["analyst"], "f.pcap", io.BytesIO(pcap_bytes), PCAP, 10 ** 7, investigation_id=case)
    investigations.grant_access(conn, case, users["analyst"], "metadata", users["dfir"], datetime.now(timezone.utc) + timedelta(days=1), "working the case")
    uid = register_upload(conn, store, users["analyst"], "f.pcap", io.BytesIO(pcap_bytes), PCAP, 10 ** 7, investigation_id=case)
    aid = eng.submit(ForensicJobRequestV1(requested_by=users["analyst"], investigation_id=case, upload_id=uid, analyses=["scan_detection"], params={"min_ports": 50}))
    assert eng.run_next().status == "completed"
    fid = conn.execute(text("SELECT finding_id FROM forensic_findings WHERE analysis_id = :a LIMIT 1"), {"a": aid}).scalar_one()
    with pytest.raises(AuthorizationError):
        eng.link_finding(fid, case, users["analyst2"])      # no case access
    eng.link_finding(fid, case, users["analyst"], "scan source")
    assert conn.execute(text("SELECT count(*) FROM investigation_links WHERE investigation_id = :c AND object_type = 'forensic_finding'"), {"c": case}).scalar_one() == 1
    with pytest.raises(NotFound):
        eng.link_finding(uuid.uuid4(), case, users["analyst"])
    # a job whose source vanished is marked failed, never left running
    conn.execute(text("INSERT INTO forensic_analyses (investigation_id, upload_id, requested_by, params) VALUES (:c, :u, :r, '{\"analyses\": [\"timeline\"]}')"),
                 {"c": case, "u": uid, "r": users["analyst"]})
    conn.execute(text("UPDATE objects SET deleted_at = now() WHERE sha256 = (SELECT object_sha256 FROM uploads WHERE upload_id = :u)"), {"u": uid})
    st = eng.run_next()
    assert st.status == "failed" and "NotFound" in st.error
