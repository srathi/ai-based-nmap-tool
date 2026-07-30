import json
from backend.config import GROQ_API_KEY, GROQ_MODEL, LLM_PROVIDER


class LLMProvider:
    def __init__(self):
        self.api_key = GROQ_API_KEY
        self.model = GROQ_MODEL or "llama-3.3-70b-versatile"
        self.provider = LLM_PROVIDER
        self.client = None
        if self.api_key and self.provider == "groq":
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url="https://api.groq.com/openai/v1"
                )
            except Exception as e:
                print(f"LLM init failed: {e}")

    def _call(self, system_prompt, user_prompt, max_tokens=1024):
        if not self.client:
            return None
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=max_tokens
            )
            return json.loads(resp.choices[0].message.content)
        except Exception as e:
            print(f"LLM call failed: {e}")
            return None

    def _format_scan_data(self, scan_data):
        hosts = scan_data.get("hosts", [])
        if len(hosts) > 20:
            summary = {
                "total_hosts": len(hosts),
                "total_open_ports": sum(
                    len(h.get("ports", [])) for h in hosts
                ),
                "top_services": list(set(
                    p.get("service_name", "unknown")
                    for h in hosts
                    for p in h.get("ports", [])
                    if p.get("state") == "open"
                ))[:10],
                "hosts": [
                    {
                        "ip": h.get("ip"),
                        "hostname": h.get("hostname", ""),
                        "port_count": len(h.get("ports", [])),
                        "ports": [
                            {
                                "port": p.get("port"),
                                "protocol": p.get("protocol", "tcp"),
                                "state": p.get("state", "unknown"),
                                "service_name": p.get("service_name", ""),
                                "service_version": p.get("service_version", ""),
                            }
                            for p in (h.get("ports") or [])
                        ],
                    }
                    for h in hosts[:20]
                ],
                "note": f"Showing first 20 of {len(hosts)} hosts"
            }
        else:
            summary = {
                "total_hosts": len(hosts),
                "total_open_ports": sum(
                    len(h.get("ports", [])) for h in hosts
                ),
                "hosts": [
                    {
                        "ip": h.get("ip"),
                        "hostname": h.get("hostname", ""),
                        "os": h.get("os", ""),
                        "ports": [
                            {
                                "port": p.get("port"),
                                "protocol": p.get("protocol", "tcp"),
                                "state": p.get("state", "unknown"),
                                "service_name": p.get("service_name", ""),
                                "service_version": p.get("service_version", ""),
                            }
                            for p in (h.get("ports") or [])
                        ],
                    }
                    for h in hosts
                ],
            }
        return json.dumps(summary, indent=2)

    def summarize(self, scan_data):
        system_prompt = (
            "You are a network security analyst. Given the following Nmap scan data, "
            "produce a JSON object with these fields:\n"
            "- summary: a 2-3 sentence summary of the scan\n"
            "- key_findings: an array of 3-6 key findings (strings)\n"
            "- risk_level: one of 'low', 'medium', 'high', 'critical'\n"
            "- host_summary: one sentence about hosts found\n"
            "- port_summary: one sentence about open ports\n"
            "\nBe accurate and specific. Only reference data present in the scan."
        )
        user_prompt = f"Scan data:\n{self._format_scan_data(scan_data)}"
        return self._call(system_prompt, user_prompt)

    def risk_score(self, scan_data):
        system_prompt = (
            "You are a network security risk assessor. Given the following Nmap scan data, "
            "score the security risk of this network. Return JSON with:\n"
            "- risk_score: an integer from 0 to 100 (higher = more risky)\n"
            "- risk_level: one of 'low', 'medium', 'high', 'critical'\n"
            "- reason: 2-3 sentences explaining the score, mentioning specific findings\n"
            "- factors: an array of strings describing individual risk factors\n"
            "\nConsider: number of open ports, sensitive services (SSH, RDP, database), "
            "encrypted vs unencrypted protocols, and overall exposure."
        )
        user_prompt = f"Scan data:\n{self._format_scan_data(scan_data)}"
        return self._call(system_prompt, user_prompt)

    def recommend(self, scan_data):
        system_prompt = (
            "You are a network security advisor. Given the Nmap scan data, "
            "provide prioritized security recommendations. Return JSON with:\n"
            "- summary: a brief overview sentence\n"
            "- recommendations: an array of objects, each with:\n"
            "  - priority: 1-5 (5=highest)\n"
            "  - category: 'remediation', 'best_practice', 'follow_up'\n"
            "  - title: short title\n"
            "  - description: specific actionable advice\n"
            "\nBe specific and reference actual findings from the scan."
        )
        user_prompt = f"Scan data:\n{self._format_scan_data(scan_data)}"
        return self._call(system_prompt, user_prompt, max_tokens=1536)

    def answer(self, question, scan_data):
        system_prompt = (
            "You are a network security QA system. Given the Nmap scan data and "
            "a user question, answer accurately and concisely. Return JSON with:\n"
            "- answer: your response to the question\n"
            "- confidence: a float from 0.0 to 1.0\n"
            "\nBase your answer only on the scan data provided. "
            "If the question cannot be answered from the data, say so."
        )
        user_prompt = f"Question: {question}\n\nScan data:\n{self._format_scan_data(scan_data)}"
        return self._call(system_prompt, user_prompt, max_tokens=1024)

    def stream_answer(self, question, scan_data):
        if not self.client:
            return
        system_prompt = (
            "You are a network security expert. Answer the user's question about "
            "the provided Nmap scan data. Be concise and accurate. "
            "If the question cannot be answered from the data, say so."
        )
        user_prompt = f"Question: {question}\n\nScan data:\n{self._format_scan_data(scan_data)}"
        try:
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                stream=True,
                temperature=0.1,
                max_tokens=1024,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta if chunk.choices else None
                if delta and delta.content:
                    yield delta.content
        except Exception as e:
            print(f"LLM stream failed: {e}")
            yield f"\n[Error: {e}]"

    def compare(self, scan1, scan2):
        system_prompt = (
            "You are a network security analyst comparing two Nmap scans. "
            "Given the data from two scans of the same network at different times, "
            "analyze what changed and its security implications. Return JSON with:\n"
            "- comparison: a detailed narrative (3-5 sentences) describing changes and their impact\n"
            "- new_concerns: array of new security concerns found in scan 2\n"
            "- resolved_concerns: array of concerns that were present in scan 1 but not scan 2\n"
            "\nFocus on security-relevant changes only."
        )
        user_prompt = (
            f"SCAN A (older):\n{self._format_scan_data(scan1)}\n\n"
            f"SCAN B (newer):\n{self._format_scan_data(scan2)}"
        )
        return self._call(system_prompt, user_prompt, max_tokens=1536)
