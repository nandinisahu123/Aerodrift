import asyncio
import json
from pathlib import Path
from flask import Flask, jsonify, render_template, request, send_file, redirect, url_for, session

from app.ingestion.mock_aws import collect_mock_state, collect_baseline
from app.topology.graph_builder import build_graph
from app.topology.graph_queries import internet_to_private_databases
from app.detection.drift_detector import detect_drift
from app.remediation.ast_generator import generate_revoke_code
from app.remediation.executor import SafeExecutor
from app.storage.database import log_incident, history
from app.report import create_report

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
REPORTS = ROOT / "reports"
app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
app.secret_key = "aerodrift-demo-secret-change-me"
AUTH_DB = DATA / "auth.db"

def init_auth_db():
    import sqlite3
    DATA.mkdir(exist_ok=True)
    with sqlite3.connect(AUTH_DB) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        conn.commit()

def current_user():
    return session.get("user")

@app.before_request
def protect_dashboard():
    public = {"/", "/login", "/signup", "/forgot-password", "/verify-email", "/api/auth/login", "/api/auth/signup", "/api/auth/logout", "/static"}
    if request.path.startswith("/static/") or request.path in public or request.path.startswith("/api/auth/"):
        return None
    if request.path.startswith(("/dashboard", "/resources", "/topology", "/drift", "/incidents", "/remediation", "/audit", "/history", "/reports", "/settings", "/profile", "/api/")) and not current_user():
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "message": "Authentication required."}), 401
        return redirect(url_for("login", next=request.path))

init_auth_db()


def load_state():
    mock = DATA / "mock_cloud.json"
    if mock.exists():
        return json.loads(mock.read_text(encoding="utf-8"))
    return asyncio.run(collect_mock_state())


def get_analysis():
    state = load_state()
    baseline = asyncio.run(collect_baseline())
    graph = build_graph(state)
    paths = internet_to_private_databases(graph)
    findings = []
    for item in detect_drift(baseline, state):
        finding = dict(item)
        finding["database_paths"] = paths
        findings.append(finding)
    return state, graph, findings, paths


def graph_payload(graph):
    nodes = []
    for node, data in graph.nodes(data=True):
        nodes.append({"id": node, "label": data.get("label", node), "type": data.get("type", "resource")})
    edges = []
    for source, target, data in graph.edges(data=True):
        edges.append({"id": f"{source}-{target}", "source": source, "target": target, "reason": data.get("reason", "connection")})
    return {"nodes": nodes, "edges": edges}


def page(template, **ctx):
    return render_template(template, **ctx)


@app.get("/")
def landing():
    return page("landing.html")

@app.get("/login")
def login(): return page("login.html")
@app.get("/signup")
def signup(): return page("signup.html")
@app.get("/forgot-password")
def forgot(): return page("forgot.html")
@app.get("/verify-email")
def verify(): return page("verify.html")

@app.get("/dashboard")
def dashboard(): return page("dashboard.html")
@app.get("/resources")
def resources(): return page("resources.html")
@app.get("/topology")
def topology_page(): return page("topology.html")
@app.get("/drift")
def drift_page(): return page("drift.html")
@app.get("/incidents")
def incidents(): return page("incidents.html")
@app.get("/incidents/<incident_id>")
def incident_detail(incident_id): return page("incident_detail.html", incident_id=incident_id)
@app.get("/remediation")
def remediation_page(): return page("remediation.html")
@app.get("/audit")
def audit(): return page("audit.html")
@app.get("/history")
def history_page(): return page("history.html")
@app.get("/reports")
def reports_page(): return page("reports.html")
@app.get("/settings")
def settings(): return page("settings.html")
@app.get("/profile")
def profile(): return page("profile.html")

@app.get("/api/overview")
def api_overview():
    state, graph, findings, paths = get_analysis()
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    return jsonify({
        "resources": len(state.get("resources", [])),
        "security_groups": len(state.get("security_groups", [])),
        "findings": len(findings), "critical": critical, "high": high,
        "nodes": graph.number_of_nodes(), "connections": graph.number_of_edges(),
        "exposure_paths": len(paths), "status": "AT RISK" if findings else "SECURE",
        "healthy_resources": max(0, len(state.get("resources", [])) - len(findings)),
        "remediations": len(history()), "aws_accounts": 1,
    })

@app.get("/api/auth/me")
def auth_me():
    return jsonify({"authenticated": bool(current_user()), "user": current_user()})

@app.get("/api/system/status")
def api_system_status():
    return jsonify({"agent": "ONLINE", "collector": "ONLINE", "graph": "ONLINE", "detector": "ONLINE", "remediation": "READY", "audit": "ONLINE", "mode": "DEMO"})

@app.get("/api/resources")
def api_resources():
    state, _, findings, _ = get_analysis()
    drift_sgs = {f.get("security_group") for f in findings}
    rows = []
    for r in state.get("resources", []):
        rid = r.get("id", r.get("name", "resource"))
        rows.append({"id": rid, "name": r.get("name", rid), "type": r.get("type", "resource"), "status": "DRIFTED" if rid in drift_sgs else "HEALTHY", "region": r.get("region", "demo-region")})
    return jsonify(rows)

@app.get("/api/topology")
def api_topology():
    _, graph, findings, paths = get_analysis()
    payload = graph_payload(graph); payload["paths"] = paths; payload["findings"] = findings
    return jsonify(payload)

@app.get("/api/drift")
def api_drift():
    _, _, findings, paths = get_analysis(); return jsonify({"findings": findings, "paths": paths})

@app.get("/api/incidents")
def api_incidents():
    _, _, findings, _ = get_analysis()
    rows = []
    for i, f in enumerate(findings, 1):
        rows.append({"id": f"INC-2026-{i:05d}", "title": "Private production resource exposed", "type": f.get("type"), "severity": f.get("severity"), "resource": f.get("security_group"), "status": "DETECTED", "detected": "Live demo scan"})
    return jsonify(rows)

@app.get("/api/remediation")
def api_remediation():
    _, _, findings, _ = get_analysis()
    code = generate_revoke_code(findings[0]) if findings else "# No active remediation"
    return jsonify({"active": bool(findings), "finding": findings[0] if findings else None, "code": code, "jobs": history()})

@app.post("/api/scan")
def api_scan():
    state = load_state(); (DATA / "last_scan.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    return jsonify({"ok": True, "message": "Demo cloud scan completed.", "security_groups": len(state.get("security_groups", []))})

@app.post("/api/remediation/generate")
def api_generate():
    _, _, findings, _ = get_analysis()
    if not findings: return jsonify({"ok": False, "message": "No active drift."}), 404
    code = generate_revoke_code(findings[0]); return jsonify({"ok": True, "code": code, "finding": findings[0], "status": "READY"})

@app.post("/api/remediation/execute")
def api_execute():
    data = request.get_json(silent=True) or {}; dry_run = bool(data.get("dry_run", True))
    _, _, findings, _ = get_analysis()
    if not findings: return jsonify({"ok": True, "status": "NO_ACTION", "message": "No drift detected."})
    finding = findings[0]; code = generate_revoke_code(finding); result = SafeExecutor(dry_run=dry_run).execute_mock(code)
    log_incident(finding["type"], finding["severity"], finding["security_group"], "revoke_security_group_ingress", result["status"])
    if not dry_run:
        current_path = DATA / "mock_cloud.json"
        state = json.loads(current_path.read_text(encoding="utf-8"))
        for sg in state["security_groups"]:
            sg["rules"] = [r for r in sg["rules"] if not (r.get("source") == "0.0.0.0/0" and r.get("port") == finding["port"] and sg["id"] == finding["security_group"])]
        current_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    pdf = create_report([finding], code, result["status"])
    return jsonify({"ok": True, "status": result["status"], "message": result["message"], "finding": finding, "code": code, "report": str(pdf.relative_to(ROOT))})

@app.post("/api/remediate")
def api_remediate_legacy(): return api_execute()

@app.get("/api/audit-logs")
def api_audit(): return api_history()

@app.get("/api/history")
def api_history():
    rows = history(); return jsonify([{"id": r[0], "timestamp": r[1], "drift_type": r[2], "severity": r[3], "resource": r[4], "action": r[5], "status": r[6]} for r in rows])

@app.get("/api/history/summary")
def history_summary():
    rows = history(); return jsonify({"total": len(rows), "completed": sum(1 for r in rows if r[6] in ("DRY_RUN", "EXECUTED", "SUCCESS")), "failed": sum(1 for r in rows if "FAIL" in str(r[6]).upper())})

@app.get("/api/report")
def api_report():
    _, _, findings, _ = get_analysis()
    if not findings: return jsonify({"ok": False, "message": "No current drift to report."}), 404
    code = generate_revoke_code(findings[0]); pdf = create_report(findings, code, "DRY_RUN")
    return send_file(pdf, as_attachment=True, download_name="aerodrift_incident_report.pdf")

@app.post("/api/auth/login")
def auth_login():
    import sqlite3
    from werkzeug.security import check_password_hash
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    with sqlite3.connect(AUTH_DB) as conn:
        row = conn.execute("SELECT id, name, email, password_hash FROM users WHERE email = ?", (email,)).fetchone()
    if not row or not check_password_hash(row[3], password):
        return jsonify({"ok": False, "message": "Invalid email or password."}), 401
    session["user"] = {"id": row[0], "name": row[1], "email": row[2]}
    return jsonify({"ok": True, "message": "Login successful.", "user": session["user"]})

@app.post("/api/auth/signup")
def auth_signup():
    import sqlite3
    from werkzeug.security import generate_password_hash
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not name or not email or len(password) < 6:
        return jsonify({"ok": False, "message": "Name, email and a password of at least 6 characters are required."}), 400
    try:
        with sqlite3.connect(AUTH_DB) as conn:
            cur = conn.execute("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)", (name, email, generate_password_hash(password)))
            user_id = cur.lastrowid
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "message": "An account with this email already exists."}), 409
    session["user"] = {"id": user_id, "name": name, "email": email}
    return jsonify({"ok": True, "message": "Account created.", "user": session["user"]})

@app.post("/api/auth/logout")
def auth_logout():
    session.clear()
    return jsonify({"ok": True})

if __name__ == "__main__": app.run(host="127.0.0.1", port=5000, debug=True)
