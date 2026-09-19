def detect_drift(baseline: dict, current: dict):
    findings = []
    baseline_sgs = {x["id"]: x for x in baseline.get("security_groups", [])}
    for sg in current.get("security_groups", []):
        old = baseline_sgs.get(sg["id"], {"rules": []})
        old_rules = {(r.get("protocol"), r.get("port"), r.get("source")) for r in old.get("rules", [])}
        for rule in sg.get("rules", []):
            key = (rule.get("protocol"), rule.get("port"), rule.get("source"))
            if key not in old_rules and rule.get("source") == "0.0.0.0/0":
                findings.append({
                    "type": "PUBLIC_INGRESS_DRIFT",
                    "severity": "CRITICAL" if rule.get("port") in {22, 3306, 5432, 6379, 27017} else "HIGH",
                    "security_group": sg["id"],
                    "port": rule.get("port"),
                    "protocol": rule.get("protocol"),
                    "source": rule.get("source"),
                    "rule": rule
                })
    return findings
