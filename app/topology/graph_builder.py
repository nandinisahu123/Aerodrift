import networkx as nx

def build_graph(state: dict) -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node("internet", type="internet", label="Internet", private=False)

    for resource in state.get("resources", []):
        g.add_node(resource["id"], type=resource["type"], label=resource["name"], private=resource.get("private", False))

    for sg in state.get("security_groups", []):
        g.add_node(sg["id"], type="security_group", label=sg["name"], private=False)
        for rule in sg.get("rules", []):
            source = rule.get("source")
            if source == "0.0.0.0/0":
                g.add_edge("internet", sg["id"], reason="public_ingress", rule=rule)
            elif source:
                g.add_edge(source, sg["id"], reason="network_ingress", rule=rule)

    # Optional explicit demo topology connections from mock_cloud.json.
    for connection in state.get("connections", []):
        source = connection.get("source")
        target = connection.get("target")
        if source and target:
            if source not in g:
                g.add_node(source, type="network", label=source)
            if target not in g:
                g.add_node(target, type="network", label=target)
            g.add_edge(source, target, reason=connection.get("reason", "connection"))

    # Preserve the project's database/security-group attachment when it is not
    # explicitly supplied by the mock topology.
    if "sg-db-prod" in g and "db-prod" in g and not g.has_edge("sg-db-prod", "db-prod"):
        g.add_edge("sg-db-prod", "db-prod", reason="security_group_attachment")

    return g
