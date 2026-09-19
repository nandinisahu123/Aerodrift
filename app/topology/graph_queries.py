import networkx as nx

def internet_to_private_databases(graph):
    findings = []
    for node, data in graph.nodes(data=True):
        if data.get("type") == "database" and data.get("private") is True:
            if nx.has_path(graph, "internet", node):
                path = nx.shortest_path(graph, "internet", node)
                findings.append({"database": node, "path": path})
    return findings
