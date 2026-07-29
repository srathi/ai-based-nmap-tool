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
