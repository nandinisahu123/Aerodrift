from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

console = Console()

def banner():
    console.print(Panel.fit("[bold]AeroDrift[/bold]\nAgentic Cloud Topology & Remediation Graph"))

def show_graph(graph):
    tree = Tree("[bold]Cloud Topology[/bold]")
    internet = tree.add("[cyan]Internet[/cyan]")
    for target in graph.successors("internet"):
        branch = internet.add(f"[yellow]{target}[/yellow]")
        for db in graph.successors(target):
            branch.add(f"[magenta]{db}[/magenta]")
    console.print(tree)

def show_findings(findings):
    if not findings:
        console.print("[green]✓ No critical public-database path detected.[/green]")
        return
    table = Table(title="Drift Findings")
    for col in ["Severity", "Type", "Security Group", "Port", "Source"]:
        table.add_column(col)
    for f in findings:
        table.add_row(f["severity"], f["type"], f["security_group"], str(f["port"]), f["source"])
    console.print(table)

def show_history(rows):
    table = Table(title="Audit History")
    for c in ["ID","Timestamp","Drift","Severity","Resource","Action","Status"]:
        table.add_column(c)
    for r in rows:
        table.add_row(*(str(x) for x in r))
    console.print(table)
