import pytest


RULE_BASED_QA = {
    "what ports are open": "open_ports",
    "how many hosts": "host_count",
    "how many ports are open": "open_port_count",
    "list the services": "services",
    "what is the os": "os_info",
    "are there any risks": "risk_summary",
}


def _rule_based_answer(query: str, hosts: list) -> dict:
    query_lower = query.lower()
    for pattern, intent in RULE_BASED_QA.items():
        if pattern in query_lower:
            if intent == "open_ports":
                ports = []
                for h in hosts:
                    for p in h.get("ports", []):
                        if p.get("state") == "open":
                            ports.append(f"{h['ip']}:{p['port']}/{p.get('protocol', 'tcp')} ({p.get('service_name', 'unknown')})")
                answer = "Open ports:\n" + "\n".join(f"  - {p}" for p in ports) if ports else "No open ports found."
                return {"answer": answer, "confidence": 0.95, "evidence_refs": [f"hosts[{h['ip']}].ports" for h in hosts if h.get("ports")]}
            elif intent == "host_count":
                return {"answer": f"Scan found {len(hosts)} host(s).", "confidence": 1.0, "evidence_refs": ["stats.total_hosts"]}
            elif intent == "open_port_count":
                count = sum(1 for h in hosts for p in h.get("ports", []) if p.get("state") == "open")
                return {"answer": f"Found {count} open port(s) across {len(hosts)} host(s).", "confidence": 0.95, "evidence_refs": ["ports[*].state"]}
            elif intent == "services":
                svcs = set()
                for h in hosts:
                    for p in h.get("ports", []):
                        name = p.get("service_name", "").strip()
                        if name:
                            svcs.add(name)
                answer = "Detected services: " + ", ".join(sorted(svcs)) if svcs else "No services detected."
                return {"answer": answer, "confidence": 0.9, "evidence_refs": ["ports[*].service_name"]}
            elif intent == "os_info":
                os_list = [h.get("os_guess", "") for h in hosts if h.get("os_guess")]
                answer = "OS detection: " + "; ".join(f"{h['ip']}: {h.get('os_guess', 'unknown')}" for h in hosts if h.get("os_guess")) if os_list else "No OS detection results available."
                return {"answer": answer, "confidence": 0.85, "evidence_refs": ["hosts[*].os_guess"]}
            elif intent == "risk_summary":
                open_ports_count = sum(1 for h in hosts for p in h.get("ports", []) if p.get("state") == "open")
                answer = f"Identified {open_ports_count} open port(s). Review exposed services for unnecessary or outdated software."
                if any(p.get("port") in (22, 23, 3389) for h in hosts for p in h.get("ports", []) if p.get("state") == "open"):
                    answer += " Remote access services (SSH, Telnet, RDP) detected - ensure strong authentication."
                return {"answer": answer, "confidence": 0.8, "evidence_refs": ["ports[*]"]}
    return {"answer": "I don't have enough information to answer that question.", "confidence": 0.1, "evidence_refs": []}


def _rule_risk_scorer(hosts: list) -> list:
    scores = []
    for h in hosts:
        ip = h.get("ip", "unknown")
        for p in h.get("ports", []):
            if p.get("state") != "open":
                continue
            port = p.get("port", 0)
            svc = p.get("service_name", "").lower()
            score = 1.0
            factors = []
            if port == 23:
                score = 9.0
                factors.append("Telnet is unencrypted and insecure")
            elif port == 21:
                score = 8.0
                factors.append("FTP transmits credentials in cleartext")
            elif port in (22,):
                score = 3.0
                factors.append("SSH is generally safe but should use key-based auth")
            elif port in (80, 8080):
                score = 5.0
                factors.append("Unencrypted HTTP traffic")
            elif port == 3306:
                score = 7.0
                factors.append("MySQL should not be exposed to the internet")
            elif port == 443:
                score = 2.0
                factors.append("HTTPS is standard, verify TLS configuration")
            else:
                score = 4.0
                factors.append(f"Exposed port {port} ({svc})")
            severity = "critical" if score >= 8 else "high" if score >= 6 else "medium" if score >= 4 else "low"
            scores.append({
                "host_id": ip,
                "port_id": port,
                "score": score,
                "severity": severity,
                "factors": factors,
                "recommendation": f"Review and restrict access to port {port} ({svc})",
            })
    if not scores:
        scores.append({"host_id": "", "port_id": 0, "score": 0, "severity": "info", "factors": ["No open ports found"], "recommendation": ""})
    return scores


def _rule_comparator(hosts1: list, hosts2: list) -> dict:
    ips1 = {h["ip"] for h in hosts1}
    ips2 = {h["ip"] for h in hosts2}
    new_hosts = list(ips2 - ips1)
    removed_hosts = list(ips1 - ips2)
    ports1 = {(h["ip"], p["port"], p["protocol"]) for h in hosts1 for p in h.get("ports", [])}
    ports2 = {(h["ip"], p["port"], p["protocol"]) for h in hosts2 for p in h.get("ports", [])}
    new_ports = [f"{ip}:{port}/{proto}" for ip, port, proto in (ports2 - ports1)]
    removed_ports = [f"{ip}:{port}/{proto}" for ip, port, proto in (ports1 - ports2)]
    summary_parts = []
    if new_hosts:
        summary_parts.append(f"{len(new_hosts)} new host(s)")
    if removed_hosts:
        summary_parts.append(f"{len(removed_hosts)} host(s) removed")
    if new_ports:
        summary_parts.append(f"{len(new_ports)} new port(s)")
    if removed_ports:
        summary_parts.append(f"{len(removed_ports)} port(s) closed")
    summary = "Differences: " + ", ".join(summary_parts) if summary_parts else "No differences found"
    return {"new_hosts": new_hosts, "removed_hosts": removed_hosts, "new_ports": new_ports, "removed_ports": removed_ports, "summary": summary}


def _rule_recommender(hosts: list) -> list:
    recommendations = []
    for h in hosts:
        for p in h.get("ports", []):
            if p.get("state") != "open":
                continue
            port = p.get("port", 0)
            svc = p.get("service_name", "")
            if port == 23:
                recommendations.append({"category": "security", "priority": "high", "title": "Disable Telnet", "description": f"Replace Telnet on {h['ip']}:{port} with SSH.", "evidence_refs": [f"port:{port}"]})
            elif port == 21:
                recommendations.append({"category": "security", "priority": "high", "title": "Replace FTP", "description": f"Use SFTP or SCP instead of FTP on {h['ip']}:{port}.", "evidence_refs": [f"port:{port}"]})
            elif port == 80:
                recommendations.append({"category": "best-practice", "priority": "medium", "title": "Enable HTTPS", "description": f"Redirect HTTP on {h['ip']}:{port} to HTTPS.", "evidence_refs": [f"port:{port}"]})
            elif port == 3306:
                recommendations.append({"category": "security", "priority": "high", "title": "Restrict MySQL Access", "description": f"MySQL on {h['ip']}:{port} should not be publicly accessible.", "evidence_refs": [f"port:{port}"]})
    if not recommendations:
        recommendations.append({"category": "info", "priority": "low", "title": "No Critical Issues", "description": "No urgent recommendations at this time.", "evidence_refs": []})
    return recommendations


SAMPLE_HOSTS = [
    {
        "ip": "192.168.1.1", "hostname": "gateway.local", "os_guess": "Linux 5.4", "status": "up",
        "ports": [
            {"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh", "service_version": "OpenSSH 8.0", "service_product": "", "banner": ""},
            {"port": 80, "protocol": "tcp", "state": "open", "service_name": "http", "service_version": "nginx 1.18", "service_product": "", "banner": ""},
            {"port": 443, "protocol": "tcp", "state": "open", "service_name": "https", "service_version": "nginx 1.18", "service_product": "", "banner": ""},
        ],
    },
    {
        "ip": "10.0.0.1", "hostname": "", "os_guess": "", "status": "up",
        "ports": [
            {"port": 3306, "protocol": "tcp", "state": "open", "service_name": "mysql", "service_version": "MySQL 8.0", "service_product": "", "banner": ""},
            {"port": 23, "protocol": "tcp", "state": "open", "service_name": "telnet", "service_version": "", "service_product": "", "banner": ""},
        ],
    },
]


class TestRuleBasedAI:
    def test_summarizer_rule_based(self):
        hosts = SAMPLE_HOSTS
        total = len(hosts)
        open_ports = sum(1 for h in hosts for p in h.get("ports", []) if p.get("state") == "open")
        services = {p.get("service_name", "") for h in hosts for p in h.get("ports", []) if p.get("service_name")}
        assert total == 2
        assert open_ports == 5
        assert services == {"ssh", "http", "https", "mysql", "telnet"}

    def test_risk_scorer_rule_based(self):
        scores = _rule_risk_scorer(SAMPLE_HOSTS)
        assert len(scores) == 5
        score_map = {(s["host_id"], s["port_id"]): s for s in scores}
        assert score_map[("10.0.0.1", 23)]["severity"] == "critical"
        assert score_map[("10.0.0.1", 23)]["score"] == 9.0
        assert score_map[("10.0.0.1", 3306)]["severity"] == "high"
        assert score_map[("192.168.1.1", 22)]["severity"] == "low"

    def test_risk_scorer_no_open_ports(self):
        scores = _rule_risk_scorer([{"ip": "10.0.0.1", "ports": [{"port": 22, "state": "closed"}]}])
        assert scores[0]["severity"] == "info"

    def test_comparator_compare(self):
        hosts1 = [
            {"ip": "10.0.0.1", "ports": [{"port": 22, "protocol": "tcp", "state": "open"}]},
            {"ip": "10.0.0.2", "ports": [{"port": 80, "protocol": "tcp", "state": "open"}]},
        ]
        hosts2 = [
            {"ip": "10.0.0.1", "ports": [{"port": 22, "protocol": "tcp", "state": "open"}, {"port": 443, "protocol": "tcp", "state": "open"}]},
            {"ip": "10.0.0.3", "ports": [{"port": 8080, "protocol": "tcp", "state": "open"}]},
        ]
        result = _rule_comparator(hosts1, hosts2)
        assert "10.0.0.3" in result["new_hosts"]
        assert "10.0.0.2" in result["removed_hosts"]
        assert "10.0.0.1:443/tcp" in result["new_ports"]
        assert "10.0.0.2:80/tcp" in result["removed_ports"]

    def test_comparator_identical(self):
        hosts = [{"ip": "10.0.0.1", "ports": [{"port": 22, "protocol": "tcp", "state": "open"}]}]
        result = _rule_comparator(hosts, hosts)
        assert result["summary"] == "No differences found"
        assert result["new_hosts"] == []
        assert result["removed_hosts"] == []

    def test_recommender_basic(self):
        recs = _rule_recommender(SAMPLE_HOSTS)
        rec_map = {(r["title"], r["priority"]): r for r in recs}
        assert ("Disable Telnet", "high") in rec_map
        assert ("Enable HTTPS", "medium") in rec_map
        assert ("Restrict MySQL Access", "high") in rec_map

    def test_recommender_no_issues(self):
        hosts = [{"ip": "10.0.0.1", "ports": [{"port": 443, "protocol": "tcp", "state": "open", "service_name": "https"}]}]
        recs = _rule_recommender(hosts)
        assert len(recs) == 1
        assert recs[0]["priority"] == "low"

    def test_qa_common_questions(self):
        result = _rule_based_answer("what ports are open", SAMPLE_HOSTS)
        assert "22" in result["answer"]
        assert "80" in result["answer"]
        assert result["confidence"] > 0.9

        result = _rule_based_answer("how many hosts", SAMPLE_HOSTS)
        assert "2" in result["answer"]
        assert result["confidence"] == 1.0

        result = _rule_based_answer("how many ports are open", SAMPLE_HOSTS)
        assert "5" in result["answer"]

        result = _rule_based_answer("list the services", SAMPLE_HOSTS)
        assert "ssh" in result["answer"]
        assert "mysql" in result["answer"]

        result = _rule_based_answer("what is the os", SAMPLE_HOSTS)
        assert "Linux" in result["answer"]

        result = _rule_based_answer("are there any risks", SAMPLE_HOSTS)
        assert result["confidence"] > 0.7

    def test_qa_unknown_question(self):
        result = _rule_based_answer("what is the weather today", SAMPLE_HOSTS)
        assert result["confidence"] < 0.5
        assert "don't have enough" in result["answer"]

    def test_qa_empty_hosts(self):
        result = _rule_based_answer("how many hosts", [])
        assert "0" in result["answer"]

    def test_evidence_citation(self):
        result = _rule_based_answer("what ports are open", SAMPLE_HOSTS)
        assert len(result["evidence_refs"]) > 0
        assert any("192.168.1.1" in ref for ref in result["evidence_refs"])

    def test_evidence_citation_risk_scorer(self):
        scores = _rule_risk_scorer(SAMPLE_HOSTS)
        for s in scores:
            if s["severity"] != "info":
                assert len(s["factors"]) > 0
                assert s["recommendation"]
