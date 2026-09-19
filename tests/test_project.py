import json
from pathlib import Path

from app.topology.graph_builder import build_graph
from app.topology.graph_queries import internet_to_private_databases
from app.detection.drift_detector import detect_drift
from app.remediation.ast_generator import generate_revoke_code
from app.remediation.executor import SafeExecutor

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    return json.loads((ROOT / "data" / name).read_text())

def test_graph_finds_public_database_path():
    g = build_graph(load("current_state.json"))
    paths = internet_to_private_databases(g)
    assert paths

def test_drift_detects_public_ingress():
    findings = detect_drift(load("baseline.json"), load("current_state.json"))
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"

def test_generated_code_is_allow_listed():
    f = detect_drift(load("baseline.json"), load("current_state.json"))[0]
    code = generate_revoke_code(f)
    SafeExecutor(dry_run=True).validate(code)
    assert "revoke_security_group_ingress" in code
