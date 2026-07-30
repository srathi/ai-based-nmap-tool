class ScanSummarizer:
    def __init__(self, provider="rule"):
        self.provider = provider
        self._llm = None

    def _get_llm(self):
        if self._llm is None:
            from backend.ai_service.llm_provider import LLMProvider
            self._llm = LLMProvider()
        return self._llm

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
        llm = self._get_llm()
        resp = llm.summarize(result)
        if resp:
            return {
                "summary": resp.get("summary", ""),
                "key_findings": resp.get("key_findings", []),
                "host_summary": resp.get("host_summary", ""),
                "port_summary": resp.get("port_summary", ""),
                "risk_level": resp.get("risk_level", "medium"),
                "evidence_refs": [f"host:{h.get('ip')}" for h in result.get("hosts", [])]
            }
        return self._rule_based_summary(result)
