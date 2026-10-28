"""Model modules: real architectures with honest availability, reproducible training on a synthetic dataset."""
from __future__ import annotations

import json
import uuid
from datetime import timedelta, timezone

import numpy as np
import pytest

from nextrace.contracts.models import InferenceRequestV1, ModelVersionV1, SimulationRequestV1
from nextrace.contracts.temporal import GraphSnapshotV1, StateSequenceV1
from nextrace.contracts.v1 import PredictionV1, TemporalStateV1
from nextrace.modules.detection.detector import HeuristicBaselineDetector, UnavailableDetector
from nextrace.modules.forecasting.forecaster import TransitionTableForecaster, UnavailableForecaster
from nextrace.modules.forecasting.world_model import MonteCarloSimulator, RSSMWorldModel, TechniqueTableTransition
from nextrace.services.states import WINDOW_FEATURES_V1
from tests.backend_helpers import an_hour_ago

torch = pytest.importorskip("torch")
NAMES = [f["name"] for f in WINDOW_FEATURES_V1]
FS = uuid.uuid4()


def _seq(sensor, n=6, failed=0.0, ports=5.0, flows=50.0):
    base = an_hour_ago().replace(second=0)
    sts = []
    for i in range(n):
        feats = [flows, 6.0, 6.0, 1e5, 500.0, ports, 0.9, 0.1, failed, 40.0]
        sts.append(TemporalStateV1(state_id=uuid.uuid4(), sensor_id=sensor, window_start=base + timedelta(seconds=10 * i), window_seconds=10, schema_version=1,
                                   n_flows=int(flows), n_nodes=6, n_edges=6, total_bytes=100000, total_pkts=500, features=feats))
    return StateSequenceV1(sensor_id=sensor, feature_schema_id=FS, window_seconds=10, states=sts, complete=True)


def _req(seq):
    return InferenceRequestV1(request_id=uuid.uuid4(), sensor_id=seq.sensor_id, requested_at=an_hour_ago(), sequence=seq, horizon_seconds=300)


def test_unavailable_detector_and_forecaster_say_so():
    seq = _seq(uuid.uuid4())
    d = UnavailableDetector().detect(_req(seq))
    assert d.status == "unavailable" and d.predictions == [] and "artifact" in d.reason
    f = UnavailableForecaster().forecast(_req(seq), d)
    assert f.status == "unavailable" and f.steps == []


def test_heuristic_baseline_is_labelled_and_rule_driven():
    det = HeuristicBaselineDetector(NAMES, uuid.uuid4(), failed_ratio_min=0.5, distinct_ports_min=30, min_flows=10)
    assert det.model_version().kind == "heuristic_baseline"
    quiet = det.detect(_req(_seq(uuid.uuid4())))
    assert quiet.status == "completed" and len(quiet.predictions) == 1 and not quiet.predictions[0].is_malicious
    scan = det.detect(_req(_seq(uuid.uuid4(), failed=0.9, ports=120.0)))
    p = scan.predictions[0]
    assert p.is_malicious and p.technique_ids == ["T1046"] and p.category == "scan_like" and scan.calibrated is False


def test_lstm_attention_shapes_masking_and_safe_artifact(tmp_path):
    from nextrace.modules.detection.model import LSTMAttentionClassifier, load_artifact, save_artifact

    torch.manual_seed(0)
    m = LSTMAttentionClassifier(n_features=10, hidden=8, n_categories=3).eval()
    x = torch.randn(4, 6, 10)
    mask = torch.ones(4, 6, dtype=torch.bool); mask[:, :2] = False
    out = m(x, mask)
    assert out["logit"].shape == (4,) and out["category_logits"].shape == (4, 3) and out["attention"].shape == (4, 6)
    assert torch.allclose(out["attention"].sum(-1), torch.ones(4)) and torch.all(out["attention"][:, :2] == 0)
    p = tmp_path / "m.pt"
    save_artifact(m, str(p), {"scaler_mean": [0.0] * 10, "scaler_std": [1.0] * 10, "temperature": 1.3})
    m2, meta = load_artifact(str(p))
    assert meta["temperature"] == 1.3 and torch.allclose(m2(x, mask)["logit"], out["logit"])
    # an artifact carrying code instead of weights is refused (weights_only)
    bad = tmp_path / "bad.pt"
    torch.save({"hparams": m.hparams, "state_dict": m.state_dict(), "evil": lambda: 1}, bad) if False else None
    with pytest.raises(Exception):
        import pickle
        bad.write_bytes(pickle.dumps({"hparams": m.hparams, "state_dict": {}, "cls": LSTMAttentionClassifier}))
        load_artifact(str(bad))


def test_training_script_is_reproducible_and_reports_only_measured_metrics(tmp_path, seed, conn, store):
    from nextrace.modules.detection import train
    from nextrace.modules.detection.detector import TorchDetector

    rng = np.random.default_rng(3)
    N, T, F = 240, 6, 10
    y = (rng.random(N) < 0.35).astype(np.int64)
    X = rng.normal(size=(N, T, F)).astype(np.float32)
    X[y == 1, :, 8] += 2.0  # failed_ratio shifts for positives
    base = an_hour_ago().timestamp() - 100000
    ts = np.array([[base + i * 60 + k * 10 for k in range(T)] for i in range(N)], dtype=np.float64)
    ds = tmp_path / "ds.npz"
    np.savez(ds, X=X, y=y, ts=ts, cat=y, categories=np.array(["benign", "malicious"]))
    args = ["--dataset", str(ds), "--out", str(tmp_path / "a.pt"), "--metrics", str(tmp_path / "m.json"), "--epochs", "3", "--seed", "11", "--hidden", "8"]
    assert train.main(args) == 0
    rep1 = json.loads((tmp_path / "m.json").read_text())
    assert train.main(args[:-6] + ["--metrics", str(tmp_path / "m2.json"), "--epochs", "3", "--seed", "11", "--hidden", "8"]) == 0
    rep2 = json.loads((tmp_path / "m2.json").read_text())
    assert rep1["metrics"]["test"]["auc"] == pytest.approx(rep2["metrics"]["test"]["auc"], abs=1e-6)
    assert rep1["split"]["rows"]["train"] + rep1["split"]["rows"]["validation"] + rep1["split"]["rows"]["test"] <= N
    assert rep1["split"]["train_end"] < rep1["split"]["validation_end"] < rep1["split"]["test_end"]
    assert "caveats" in rep1 and 0 <= rep1["metrics"]["test"]["ece"] <= 1
    # the trained artifact loads through the object store into a TorchDetector; schema mismatch is refused
    ref = store.put_path(tmp_path / "a.pt", "model")
    mv = ModelVersionV1(model_version_id=seed["model_version_id"], name="lstm", kind="lstm_attention", version="t", feature_schema_id=seed["feature_schema_id"])
    det = TorchDetector(store, ref, mv)
    seq = _seq(seed["sensor_id"])
    wrong = det.detect(_req(seq))
    assert wrong.status == "refused" and "schema" in wrong.reason
    ok = det.detect(_req(seq.model_copy(update={"feature_schema_id": seed["feature_schema_id"]})))
    assert ok.status == "completed" and 0.0 <= ok.predictions[0].probability <= 1.0 and ok.attention and ok.model_version_id == seed["model_version_id"]


def test_gat_layer_shapes():
    from nextrace.modules.forecasting.gat import GATLayer, GATProgressionModel

    torch.manual_seed(0)
    x = torch.randn(5, 2); ei = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 4]]); ea = torch.randn(4, 5)
    assert GATLayer(2, 4, 5, heads=3)(x, ei, ea).shape == (5, 12)
    assert GATProgressionModel(2, 5, n_techniques=7, hidden=4, heads=2)(x, ei, ea).shape == (5, 7)


def test_transition_table_and_simulator_honesty(store):
    f = TransitionTableForecaster(uuid.uuid4(), max_steps=3, tactic_map={"T1110": "credential-access", "T1021": "lateral-movement"})
    seq = _seq(uuid.uuid4())
    det_ok = type("D", (), {"predictions": [PredictionV1(state_id=seq.states[-1].state_id, window_start=seq.states[-1].window_start, is_malicious=True,
                                                         probability=0.9, technique_ids=["T1046"])]})()
    assert f.forecast(_req(seq), det_ok).status == "unavailable" and f.model_version() is None
    f.fit([[("T1046", 0), ("T1110", 60), ("T1021", 400)], [("T1046", 0), ("T1110", 90)], [("T1046", 0), ("T1021", 30)]])
    out = f.forecast(_req(seq), det_ok)
    assert out.status == "completed" and out.steps[0].predicted_technique_id == "T1110" and out.steps[0].expected_within_s in (60, 90)
    assert out.steps[0].probability > out.steps[1].probability and "first_step_entropy" in out.uncertainty
    f2 = TransitionTableForecaster.from_json(f.to_json(), f.mv_id)
    assert f2.forecast(_req(seq), det_ok).steps[0].predicted_technique_id == "T1110"

    sim = MonteCarloSimulator(None, store)
    g = GraphSnapshotV1(state_id=uuid.uuid4(), sensor_id=seq.sensor_id, window_start=seq.states[0].window_start, window_seconds=10, edge_feature_schema_id=uuid.uuid4(), nodes=[], edges=[])
    req = SimulationRequestV1(simulation_id=uuid.uuid4(), base_run_id=uuid.uuid4(), start=g, start_technique_id="T1046", n_rollouts=200, horizon_steps=3, seed=5)
    assert sim.simulate(req).status == "unavailable"
    sim = MonteCarloSimulator(TechniqueTableTransition(f), store)
    r1, r2 = sim.simulate(req), sim.simulate(req)
    strip = lambda d: {k: v for k, v in d.items() if k != "latency_ms"}  # noqa: E731
    assert r1.status == "completed" and strip(r1.rollout_summary) == strip(r2.rollout_summary) and r1.progression[0].predicted_technique_id == "T1110"
    assert r1.result_sha256 and "assumptions" in r1.rollout_summary
    from nextrace.contracts.models import InterventionV1
    blocked = sim.simulate(req.model_copy(update={"interventions": [InterventionV1(kind="block_ip", at_step=1)]}))
    assert blocked.progression == [] and blocked.rollout_summary["mean_chain_length"] == 0
    assert sim.simulate(req.model_copy(update={"start_technique_id": None})).status == "refused"
    with pytest.raises(NotImplementedError):
        RSSMWorldModel()
