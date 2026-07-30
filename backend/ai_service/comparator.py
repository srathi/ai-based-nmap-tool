class ScanComparator:
    def __init__(self, provider="rule"):
        self.provider = provider
        self._llm = None

    def _get_llm(self):
        if self._llm is None:
            from backend.ai_service.llm_provider import LLMProvider
            self._llm = LLMProvider()
        return self._llm

    def compare(self, scan_result_1, scan_result_2):
        if self.provider == "openai":
            return self._openai_compare(scan_result_1, scan_result_2)
        return self._rule_based_compare(scan_result_1, scan_result_2)

    def _rule_based_compare(self, scan_result_1, scan_result_2):
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
            "summary": summary,
            "detail": summary,
            "comparison": summary
        }

    def _openai_compare(self, scan_result_1, scan_result_2):
        llm = self._get_llm()
        resp = llm.compare(scan_result_1, scan_result_2)
        if resp:
            base = self._rule_based_compare(scan_result_1, scan_result_2)
            base["comparison"] = resp.get("comparison", base["summary"])
            base["detail"] = resp.get("comparison", base["summary"])
            base["new_concerns"] = resp.get("new_concerns", [])
            base["resolved_concerns"] = resp.get("resolved_concerns", [])
            return base
        return self._rule_based_compare(scan_result_1, scan_result_2)
