import os

base = "/Users/sandesh/myOpenCode/ai-based-nmap-tool/backend/ai_service"
os.makedirs(base, exist_ok=True)

files = {}

# __init__.py
files["__init__.py"] = ""

# summarizer.py
files["summarizer.py"] = r'''
class ScanSummarizer:
    def __init__(self, provider="rule"):
        self.provider = provider

    def summarize(self, scan_result, scan_job=None):
        if self.provider == "openai":
            return self._openai_summary(scan_result)
        return self._rule_based_summary(scan_result)

    def _rule_based_summary(self, result):
        hosts = result.get("hosts", [])
        th = len(hosts)
        tp = 0
        op = 0
        svcs = {}
        for h in hosts:
            for p in h.get("ports", []):
                tp += 1
                if p.get("state") == "open":
                    op += 1
                    s = p.get("service_name", "unknown")
                    svcs[s] = svcs.get(s, 0) + 1
        top = sorted(svcs.items(), key=lambda x: -x[1])[:5]
        lines = [f"Scan found {th} live host(s) with {tp} total port(s), {op} open."]
        if top:
            lines.append(f"Top services: {', '.join(f'{s}({c})' for s,c in top)}.")
        return {
            "summary": " ".join(lines),
            "key_findings": [f"{th} hosts up", f"{op} open ports"],
            "host_summary": f"{th} host(s) responding",
            "port_summary": f"{op} open of {tp} total",
            "evidence_refs": [f"host:{h.get('ip')}" for h in hosts]
        }

    def _openai_summary(self, result):
        return self._rule_based_summary(result)
'''

# risk_scorer.py
files["risk_scorer.py"] = r'''
class RiskScorer:
    def __init__(self, provider="rule"):
        self.provider = provider

    def score_scan(self, scan_result):
        if self.provider == "openai":
            return self._openai_scoring(scan_result)
        return self._rule_based_scoring(scan_result)

    def _rule_based_scoring(self, result):
        scores = []
        for h in result.get("hosts", []):
            host_score = 0
            factors = []
            ports = h.get("ports", [])
            n_open = sum(1 for p in ports if p.get("state") == "open")
            host_score += min(n_open * 10, 40)
            if n_open > 10:
                factors.append("High number of open ports")
            if n_open > 20:
                factors.append("Very high port count")
            for p in ports:
                if p.get("state") != "open":
                    continue
                svc = (p.get("service_name") or "").lower()
                port_num = p.get("port", 0)
                ps = 0
                pf = []
                if svc in ("ssh", "telnet", "ftp"):
                    ps += 15
                    pf.append(f"Remote access service on port {port_num}")
                if svc in ("mysql", "postgresql", "mongodb", "redis"):
                    ps += 15
                    pf.append(f"Database service exposed on port {port_num}")
                if svc in ("http",) and port_num in (80, 8080):
                    ps += 5
                    pf.append(f"Unencrypted HTTP on port {port_num}")
                if port_num > 49152:
                    ps += 5
                    pf.append(f"Ephemeral port {port_num} open")
                if ps > 0:
                    host_score += ps
                    factors.extend(pf)
                scores.append({
                    "host_id": h.get("id"),
                    "port_id": p.get("id"),
                    "port": port_num,
                    "service": svc,
                    "score": min(ps, 40),
                    "severity": "critical" if ps >= 30 else "high" if ps >= 20 else "medium" if ps >= 10 else "low",
                    "factors": pf,
                    "evidence_refs": [f"host:{h.get('ip')}:{port_num}"]
                })
            scores.append({
                "host_id": h.get("id"),
                "port_id": None,
                "score": min(host_score, 100),
                "severity": "critical" if host_score >= 70 else "high" if host_score >= 50 else "medium" if host_score >= 30 else "low",
                "factors": factors if factors else ["Standard host"],
                "host_ip": h.get("ip"),
                "evidence_refs": [f"host:{h.get('ip')}"]
            })
        return scores

    def _openai_scoring(self, result):
        return self._rule_based_scoring(result)
'''

# comparator.py
files["comparator.py"] = r'''
class ScanComparator:
    def __init__(self, provider="rule"):
        self.provider = provider

    def compare(self, scan_result_1, scan_result_2):
        hosts1 = {h.get("ip"): h for h in scan_result_1.get("hosts", [])}
        hosts2 = {h.get("ip"): h for h in scan_result_2.get("hosts", [])}
        ips1 = set(hosts1.keys())
        ips2 = set(hosts2.keys())
        new_hosts = [hosts2[ip] for ip in ips2 - ips1]
        removed_hosts = [hosts1[ip] for ip in ips1 - ips2]
        new_ports = []
        removed_ports = []
        changed_services = []
        for ip in ips1 & ips2:
            ports1 = {(p.get("port"), p.get("protocol")): p for p in hosts1[ip].get("ports", [])}
            ports2 = {(p.get("port"), p.get("protocol")): p for p in hosts2[ip].get("ports", [])}
            keys1 = set(ports1.keys())
            keys2 = set(ports2.keys())
            for k in keys2 - keys1:
                new_ports.append({**ports2[k], "host_ip": ip})
            for k in keys1 - keys2:
                removed_ports.append({**ports1[k], "host_ip": ip})
            for k in keys1 & keys2:
                s1 = ports1[k].get("service_name")
                s2 = ports2[k].get("service_name")
                if s1 != s2:
                    changed_services.append({"host_ip": ip, "port": k[0], "protocol": k[1], "from": s1, "to": s2})
        summary = f"Compared scans: {len(new_hosts)} new host(s), {len(removed_hosts)} removed, {len(new_ports)} new port(s), {len(removed_ports)} closed port(s)."
        return {
            "new_hosts": new_hosts,
            "removed_hosts": removed_hosts,
            "new_ports": new_ports,
            "removed_ports": removed_ports,
            "changed_services": changed_services,
            "summary": summary
        }
'''

# recommender.py
files["recommender.py"] = r'''
class ScanRecommender:
    def __init__(self, provider="rule"):
        self.provider = provider

    def recommend(self, scan_result, risk_scores=None):
        recs = []
        seen = set()
        for h in scan_result.get("hosts", []):
            for p in h.get("ports", []):
                if p.get("state") != "open":
                    continue
                svc = (p.get("service_name") or "").lower()
                port = p.get("port", 0)
                if svc in ("ssh",) and "ssh" not in seen:
                    seen.add("ssh")
                    recs.append({
                        "category": "best_practice",
                        "priority": 3,
                        "title": "Review SSH exposure",
                        "description": f"SSH is open on {h.get('ip')}:{port}. Ensure key-based auth and disable root login.",
                        "evidence_refs": [f"host:{h.get('ip')}:{port}"]
                    })
                if svc in ("http",) and port in (80, 8080) and "http" not in seen:
                    seen.add("http")
                    recs.append({
                        "category": "remediation",
                        "priority": 4,
                        "title": "Enable HTTPS",
                        "description": f"Unencrypted HTTP on {h.get('ip')}:{port}. Redirect to HTTPS.",
                        "evidence_refs": [f"host:{h.get('ip')}:{port}"]
                    })
                if svc in ("telnet",) and "telnet" not in seen:
                    seen.add("telnet")
                    recs.append({
                        "category": "remediation",
                        "priority": 5,
                        "title": "Replace Telnet with SSH",
                        "description": f"Telnet is unencrypted. Replace with SSH on {h.get('ip')}:{port}.",
                        "evidence_refs": [f"host:{h.get('ip')}:{port}"]
                    })
                if svc in ("mysql", "postgresql", "mongodb", "redis") and "db_exposed" not in seen:
                    seen.add("db_exposed")
                    recs.append({
                        "category": "follow_up",
                        "priority": 4,
                        "title": "Audit database exposure",
                        "description": f"Database service ({svc}) exposed on {h.get('ip')}:{port}. Restrict to trusted IPs.",
                        "evidence_refs": [f"host:{h.get('ip')}:{port}"]
                    })
        if not recs:
            recs.append({
                "category": "best_practice",
                "priority": 1,
                "title": "No immediate issues found",
                "description": "Standard ports only. Continue regular monitoring.",
                "evidence_refs": []
            })
        recs.sort(key=lambda x: -x["priority"])
        return recs
'''

# qa.py
files["qa.py"] = r'''
import re

class ScanQA:
    def __init__(self, provider="rule"):
        self.provider = provider

    def answer(self, question, scan_result, scan_job=None):
        if self.provider == "openai":
            return self._openai_answer(question, scan_result)
        return self._rule_based_answer(question, scan_result)

    def _rule_based_answer(self, question, result):
        q = question.lower().strip()
        hosts = result.get("hosts", [])
        if not hosts:
            return {"answer": "No scan data available.", "confidence": 1.0, "evidence_refs": []}
        refs = [f"scan_job:{result.get('scan_job_id')}"]
        if "how many host" in q or "how many ip" in q or "how many system" in q:
            n = len(hosts)
            return {"answer": f"There are {n} host(s) in the scan results.", "confidence": 1.0, "evidence_refs": refs}
        if "how many port" in q or "how many service" in q:
            total = sum(len(h.get("ports", [])) for h in hosts)
            open_p = sum(1 for h in hosts for p in h.get("ports", []) if p.get("state") == "open")
            return {"answer": f"There are {total} port(s) total, {open_p} open.", "confidence": 1.0, "evidence_refs": refs}
        if "what port" in q or "which port" in q or "list port" in q:
            lines = []
            for h in hosts:
                for p in h.get("ports", []):
                    if p.get("state") == "open":
                        svc = p.get("service_name", "unknown")
                        lines.append(f"  {h.get('ip')}:{p.get('port')}/{p.get('protocol')} - {svc} {p.get('service_version', '')}")
            if lines:
                return {"answer": "Open ports:\n" + "\n".join(lines), "confidence": 1.0, "evidence_refs": refs}
            return {"answer": "No open ports found.", "confidence": 1.0, "evidence_refs": refs}
        if "what service" in q or "which service" in q:
            svcs = {}
            for h in hosts:
                for p in h.get("ports", []):
                    s = p.get("service_name", "unknown")
                    if s != "unknown":
                        svcs.setdefault(s, []).append(f"{h.get('ip')}:{p.get('port')}")
            if svcs:
                lines = [f"  {s}: {', '.join(pp)}" for s, pp in svcs.items()]
                return {"answer": "Detected services:\n" + "\n".join(lines), "confidence": 1.0, "evidence_refs": refs}
            return {"answer": "No services detected.", "confidence": 1.0, "evidence_refs": refs}
        if "port 22" in q or "ssh" in q:
            results = [(h.get('ip'), p) for h in hosts for p in h.get("ports", []) if p.get("port") == 22]
            if results:
                ips = [r[0] for r in results]
                return {"answer": f"SSH (port 22) is open on: {', '.join(ips)}", "confidence": 1.0, "evidence_refs": refs}
            return {"answer": "Port 22 (SSH) is not open on any host.", "confidence": 1.0, "evidence_refs": refs}
        if "port 80" in q or "http" in q or "web" in q:
            results = [(h.get('ip'), p) for h in hosts for p in h.get("ports", []) if p.get("port") in (80, 443, 8080, 8443)]
            if results:
                ips = list(set(r[0] for r in results))
                return {"answer": f"Web services on: {', '.join(ips)}", "confidence": 1.0, "evidence_refs": refs}
            return {"answer": "No standard web ports found.", "confidence": 1.0, "evidence_refs": refs}
        if "risk" in q or "danger" in q or "critical" in q or "vulner" in q:
            risky = []
            for h in hosts:
                for p in h.get("ports", []):
                    svc = (p.get("service_name") or "").lower()
                    if svc in ("ssh", "telnet", "ftp", "mysql", "postgresql", "mongodb", "redis", "ms-sql-s"):
                        risky.append(f"{h.get('ip')}:{p.get('port')} ({svc})")
            if risky:
                return {"answer": "Potentially sensitive services found:\n" + "\n".join(f"  {r}" for r in risky), "confidence": 0.9, "evidence_refs": refs}
            return {"answer": "No high-risk services detected based on port exposure.", "confidence": 0.8, "evidence_refs": refs}
        if "what changed" in q or "difference" in q or "compar" in q:
            return {"answer": "Comparison data not available. Use the compare endpoint with two scan IDs.", "confidence": 0.5, "evidence_refs": refs}
        return {
            "answer": f"I can answer questions about host count, open ports, services, SSH, web services, and risk. Try: 'What ports are open?' or 'How many hosts?'",
            "confidence": 0.6,
            "evidence_refs": refs
        }

    def _openai_answer(self, question, result):
        return self._rule_based_answer(question, result)
'''

for name, content in files.items():
    path = os.path.join(base, name)
    with open(path, "w") as f:
        f.write(content.lstrip("\n"))
    print(f"Written: {path}")