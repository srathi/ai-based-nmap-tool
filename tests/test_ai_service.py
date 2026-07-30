import json
from unittest.mock import patch, MagicMock

import pytest

from backend.ai_service.summarizer import ScanSummarizer
from backend.ai_service.risk_scorer import RiskScorer
from backend.ai_service.recommender import ScanRecommender
from backend.ai_service.comparator import ScanComparator
from backend.ai_service.qa import ScanQA

SAMPLE_SCAN = {
    "hosts": [
        {
            "ip": "192.168.1.1",
            "hostname": "gateway.local",
            "os_guess": "Linux 5.4",
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh", "service_version": "OpenSSH 8.0"},
                {"port": 80, "protocol": "tcp", "state": "open", "service_name": "http", "service_version": "nginx 1.18"},
                {"port": 443, "protocol": "tcp", "state": "open", "service_name": "https", "service_version": "nginx 1.18"},
            ],
        },
        {
            "ip": "10.0.0.1",
            "hostname": "",
            "os_guess": "",
            "ports": [
                {"port": 3306, "protocol": "tcp", "state": "open", "service_name": "mysql", "service_version": "MySQL 8.0"},
                {"port": 23, "protocol": "tcp", "state": "open", "service_name": "telnet", "service_version": ""},
            ],
        },
    ]
}

LLM_MOCK_RESPONSE = {
    "summary": "Mock LLM summary",
    "key_findings": ["Mock finding 1", "Mock finding 2"],
    "host_summary": "Mock host summary",
    "port_summary": "Mock port summary",
    "risk_level": "medium",
    "risk_score": 45,
    "reason": "Mock risk reason",
    "factors": ["Mock factor"],
    "recommendations": [
        {"priority": 5, "category": "remediation", "title": "Mock rec", "description": "Mock description"}
    ],
    "answer": "Mock LLM answer",
    "confidence": 0.95,
    "comparison": "Mock comparison narrative",
    "new_concerns": ["Mock concern"],
    "resolved_concerns": ["Mock resolved"],
}


def mock_llm_call(*args, **kwargs):
    return LLM_MOCK_RESPONSE


class MockLLMProvider:
    def summarize(self, scan_data):
        return LLM_MOCK_RESPONSE

    def risk_score(self, scan_data):
        return LLM_MOCK_RESPONSE

    def recommend(self, scan_data):
        return LLM_MOCK_RESPONSE

    def answer(self, question, scan_data):
        return LLM_MOCK_RESPONSE

    def compare(self, scan1, scan2):
        return LLM_MOCK_RESPONSE


class MockLLMProviderNone:
    def summarize(self, scan_data):
        return None

    def risk_score(self, scan_data):
        return None

    def recommend(self, scan_data):
        return None

    def answer(self, question, scan_data):
        return None

    def compare(self, scan1, scan2):
        return None


class TestScanSummarizer:
    def test_rule_based_summary(self):
        s = ScanSummarizer(provider="rule")
        result = s.summarize(SAMPLE_SCAN)
        assert "2" in result["summary"]
        assert "5" in result["summary"]
        assert len(result["key_findings"]) == 2
        assert "evidence_refs" in result

    def test_rule_based_empty_hosts(self):
        s = ScanSummarizer(provider="rule")
        result = s.summarize({"hosts": []})
        assert "0" in result["summary"]

    @patch.object(ScanSummarizer, "_get_llm", return_value=MockLLMProvider())
    def test_openai_summary(self, mock_get_llm):
        s = ScanSummarizer(provider="openai")
        result = s.summarize(SAMPLE_SCAN)
        assert result["summary"] == "Mock LLM summary"
        assert result["key_findings"] == ["Mock finding 1", "Mock finding 2"]
        assert result["risk_level"] == "medium"

    @patch.object(ScanSummarizer, "_get_llm", return_value=MockLLMProviderNone())
    def test_openai_fallback_to_rule(self, mock_get_llm):
        s = ScanSummarizer(provider="openai")
        result = s.summarize(SAMPLE_SCAN)
        assert "2" in result["summary"]
        assert "5" in result["summary"]


class TestRiskScorer:
    def test_rule_based_scoring(self):
        r = RiskScorer(provider="rule")
        result = r.score_scan(SAMPLE_SCAN)
        assert isinstance(result, list)
        assert len(result) > 0
        host_scores = [s for s in result if s.get("port_id") is None]
        for hs in host_scores:
            assert 0 <= hs["score"] <= 100
            assert hs["severity"] in ("low", "medium", "high", "critical")

    def test_rule_based_no_open_ports(self):
        r = RiskScorer(provider="rule")
        result = r.score_scan({"hosts": [{"ip": "10.0.0.1", "ports": [{"port": 22, "state": "closed"}]}]})
        assert len(result) > 0

    @patch.object(RiskScorer, "_get_llm", return_value=MockLLMProvider())
    def test_openai_scoring(self, mock_get_llm):
        r = RiskScorer(provider="openai")
        result = r.score_scan(SAMPLE_SCAN)
        assert isinstance(result, dict)
        assert result["risk_score"] == 45
        assert result["score"] == 45
        assert result["risk_level"] == "medium"
        assert result["reason"] == "Mock risk reason"

    @patch.object(RiskScorer, "_get_llm", return_value=MockLLMProviderNone())
    def test_openai_scoring_fallback(self, mock_get_llm):
        r = RiskScorer(provider="openai")
        result = r.score_scan(SAMPLE_SCAN)
        assert isinstance(result, list)
        assert len(result) > 0


class TestScanRecommender:
    def test_rule_based_recommend(self):
        r = ScanRecommender(provider="rule")
        result = r.recommend(SAMPLE_SCAN)
        assert len(result) > 0
        titles = [rec["title"] for rec in result]
        assert "Review SSH exposure" in titles
        assert "Replace Telnet with SSH" in titles

    def test_rule_based_no_issues(self):
        r = ScanRecommender(provider="rule")
        result = r.recommend({"hosts": [{"ip": "10.0.0.1", "ports": [{"port": 443, "state": "open", "service_name": "https"}]}]})
        assert result[0]["title"] == "No immediate issues found"

    @patch.object(ScanRecommender, "_get_llm", return_value=MockLLMProvider())
    def test_openai_recommend(self, mock_get_llm):
        r = ScanRecommender(provider="openai")
        result = r.recommend(SAMPLE_SCAN)
        assert len(result) == 1
        assert result[0]["title"] == "Mock rec"

    @patch.object(ScanRecommender, "_get_llm", return_value=MockLLMProviderNone())
    def test_openai_recommend_fallback(self, mock_get_llm):
        r = ScanRecommender(provider="openai")
        result = r.recommend(SAMPLE_SCAN)
        assert len(result) > 0


class TestScanComparator:
    def test_rule_based_compare(self):
        c = ScanComparator(provider="rule")
        result = c.compare(SAMPLE_SCAN, SAMPLE_SCAN)
        assert result["new_hosts"] == []
        assert result["removed_hosts"] == []
        assert "0 new host" in result["summary"]

    def test_rule_based_compare_different(self):
        c = ScanComparator(provider="rule")
        scan2 = {"hosts": [{"ip": "10.0.0.2", "ports": [{"port": 80, "protocol": "tcp", "state": "open"}]}]}
        result = c.compare(SAMPLE_SCAN, scan2)
        assert "10.0.0.2" in str(result["new_hosts"])
        assert "192.168.1.1" in str(result["removed_hosts"])

    @patch.object(ScanComparator, "_get_llm", return_value=MockLLMProvider())
    def test_openai_compare(self, mock_get_llm):
        c = ScanComparator(provider="openai")
        result = c.compare(SAMPLE_SCAN, SAMPLE_SCAN)
        assert result["comparison"] == "Mock comparison narrative"
        assert result["new_concerns"] == ["Mock concern"]
        assert result["resolved_concerns"] == ["Mock resolved"]

    @patch.object(ScanComparator, "_get_llm", return_value=MockLLMProviderNone())
    def test_openai_compare_fallback(self, mock_get_llm):
        c = ScanComparator(provider="openai")
        result = c.compare(SAMPLE_SCAN, SAMPLE_SCAN)
        assert "0 new host" in result["summary"]


class TestScanQA:
    def test_rule_based_qa_host_count(self):
        q = ScanQA(provider="rule")
        result = q.answer("How many hosts?", SAMPLE_SCAN)
        assert "2" in result["answer"]
        assert result["confidence"] == 1.0

    def test_rule_based_qa_open_ports(self):
        q = ScanQA(provider="rule")
        result = q.answer("What ports are open?", SAMPLE_SCAN)
        assert "22" in result["answer"]
        assert "3306" in result["answer"]

    def test_rule_based_qa_ssh(self):
        q = ScanQA(provider="rule")
        result = q.answer("Is SSH running?", SAMPLE_SCAN)
        assert "22" in result["answer"]

    def test_rule_based_qa_risk(self):
        q = ScanQA(provider="rule")
        result = q.answer("What are the risks?", SAMPLE_SCAN)
        assert "telnet" in result["answer"].lower() or "sensitive" in result["answer"].lower()

    def test_rule_based_qa_empty_hosts(self):
        q = ScanQA(provider="rule")
        result = q.answer("How many hosts?", {"hosts": []})
        assert "No scan data" in result["answer"]

    def test_rule_based_qa_unknown(self):
        q = ScanQA(provider="rule")
        result = q.answer("What is the weather?", SAMPLE_SCAN)
        assert result["confidence"] < 0.8

    @patch.object(ScanQA, "_get_llm", return_value=MockLLMProvider())
    def test_openai_qa(self, mock_get_llm):
        q = ScanQA(provider="openai")
        result = q.answer("Tell me about this scan", SAMPLE_SCAN)
        assert result["answer"] == "Mock LLM answer"
        assert result["confidence"] == 0.95

    @patch.object(ScanQA, "_get_llm", return_value=MockLLMProviderNone())
    def test_openai_qa_fallback(self, mock_get_llm):
        q = ScanQA(provider="openai")
        result = q.answer("How many hosts?", SAMPLE_SCAN)
        assert "2" in result["answer"]


class TestLLMProvider:
    @patch("backend.ai_service.llm_provider.LLMProvider._call")
    def test_summarize_calls_llm(self, mock_call):
        mock_call.return_value = LLM_MOCK_RESPONSE
        from backend.ai_service.llm_provider import LLMProvider
        llm = LLMProvider()
        result = llm.summarize(SAMPLE_SCAN)
        assert result["summary"] == "Mock LLM summary"
        mock_call.assert_called_once()

    @patch("backend.ai_service.llm_provider.LLMProvider._call")
    def test_risk_score_calls_llm(self, mock_call):
        mock_call.return_value = LLM_MOCK_RESPONSE
        from backend.ai_service.llm_provider import LLMProvider
        llm = LLMProvider()
        result = llm.risk_score(SAMPLE_SCAN)
        assert result["risk_score"] == 45

    @patch("backend.ai_service.llm_provider.LLMProvider._call")
    def test_recommend_calls_llm(self, mock_call):
        mock_call.return_value = LLM_MOCK_RESPONSE
        from backend.ai_service.llm_provider import LLMProvider
        llm = LLMProvider()
        result = llm.recommend(SAMPLE_SCAN)
        assert len(result["recommendations"]) == 1

    @patch("backend.ai_service.llm_provider.LLMProvider._call")
    def test_answer_calls_llm(self, mock_call):
        mock_call.return_value = LLM_MOCK_RESPONSE
        from backend.ai_service.llm_provider import LLMProvider
        llm = LLMProvider()
        result = llm.answer("test question", SAMPLE_SCAN)
        assert result["answer"] == "Mock LLM answer"

    @patch("backend.ai_service.llm_provider.LLMProvider._call")
    def test_compare_calls_llm(self, mock_call):
        mock_call.return_value = LLM_MOCK_RESPONSE
        from backend.ai_service.llm_provider import LLMProvider
        llm = LLMProvider()
        result = llm.compare(SAMPLE_SCAN, SAMPLE_SCAN)
        assert result["comparison"] == "Mock comparison narrative"

    def test_llm_no_key_returns_none(self):
        from backend.ai_service.llm_provider import LLMProvider
        llm = LLMProvider()
        llm.client = None
        assert llm.summarize(SAMPLE_SCAN) is None
        assert llm.risk_score(SAMPLE_SCAN) is None
        assert llm.recommend(SAMPLE_SCAN) is None
        assert llm.answer("q", SAMPLE_SCAN) is None
        assert llm.compare(SAMPLE_SCAN, SAMPLE_SCAN) is None
