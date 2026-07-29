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
