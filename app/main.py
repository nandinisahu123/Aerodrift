import argparse
import asyncio
import json
from pathlib import Path

from app.ingestion.mock_aws import collect_mock_state, collect_baseline
from app.ingestion.aws_client import collect_aws_state
from app.topology.graph_builder import build_graph
from app.topology.graph_queries import internet_to_private_databases
from app.detection.drift_detector import detect_drift
from app.remediation.ast_generator import generate_revoke_code
from app.remediation.executor import SafeExecutor
from app.storage.database import log_incident, history
from app.dashboard.cli import banner, show_graph, show_findings, show_history
from app.report import create_report

ROOT = Path(__file__).resolve().parents[1]

async def get_state(mode):
    if mode == "aws":
        return await collect_aws_state()
    return await collect_mock_state()

async def scan(mode):
    state = await get_state(mode)
    (ROOT / "data" / "last_scan.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    return state

async def command_drift(mode):
    banner()
    state = await get_state(mode)
    baseline = await collect_baseline()
    graph = build_graph(state)
    show_graph(graph)
    raw = detect_drift(baseline, state)
    paths = internet_to_private_databases(graph)
    findings = []
    for f in raw:
        f = dict(f)
        f["database_paths"] = paths
        findings.append(f)
    show_findings(findings)
    if paths:
        print("\nPotential exposure paths:")
        for p in paths:
            print(" -> ".join(p))
    return findings

async def command_heal(mode, dry_run):
    banner()
    findings = await command_drift(mode)
    if not findings:
        return
    f = findings[0]
    code = generate_revoke_code(f)
    print("\nGenerated AST remediation:\n")
    print(code)
    executor = SafeExecutor(dry_run=dry_run)
    result = executor.execute_mock(code)
    print("\nExecution:", result["status"], "-", result["message"])
    log_incident(f["type"], f["severity"], f["security_group"], "revoke_security_group_ingress", result["status"])

    if not dry_run and mode == "mock":
        current_path = ROOT / "data" / "current_state.json"
        state = json.loads(current_path.read_text(encoding="utf-8"))
        for sg in state["security_groups"]:
            sg["rules"] = [r for r in sg["rules"]
                           if not (r.get("source") == "0.0.0.0/0"
                                   and r.get("port") == f["port"]
                                   and sg["id"] == f["security_group"])]
        current_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        print("[green]✓ Mock cloud state healed.[/green]")

    pdf = create_report(findings, code, result["status"])
    print("Report:", pdf)

def main():
    parser = argparse.ArgumentParser(description="AeroDrift CloudOps agent")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ["scan", "drift"]:
        p = sub.add_parser(name)
        p.add_argument("--mode", choices=["mock", "aws"], default="mock")

    p = sub.add_parser("heal")
    p.add_argument("--mode", choices=["mock", "aws"], default="mock")
    p.add_argument("--dry-run", action="store_true")

    sub.add_parser("history")
    sub.add_parser("report")

    args = parser.parse_args()

    if args.command == "scan":
        state = asyncio.run(scan(args.mode))
        print(f"Scan complete: {len(state.get('security_groups', []))} security groups")
    elif args.command == "drift":
        asyncio.run(command_drift(args.mode))
    elif args.command == "heal":
        asyncio.run(command_heal(args.mode, args.dry_run))
    elif args.command == "history":
        banner()
        show_history(history())
    elif args.command == "report":
        print("Generate a report by running: python -m app.main heal --dry-run")

if __name__ == "__main__":
    main()
