class ScanRecommender:
    def __init__(self, provider="rule"):
        self.provider = provider
        self._llm = None

    def _get_llm(self):
        if self._llm is None:
            from backend.ai_service.llm_provider import LLMProvider
            self._llm = LLMProvider()
        return self._llm

    def recommend(self, scan_result, risk_scores=None):
        if self.provider == "openai":
            return self._openai_recommend(scan_result)
        return self._rule_based_recommend(scan_result)

    def _rule_based_recommend(self, scan_result):
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

    def _openai_recommend(self, scan_result):
        llm = self._get_llm()
        resp = llm.recommend(scan_result)
        if resp:
            return resp.get("recommendations", [])
        return self._rule_based_recommend(scan_result)
