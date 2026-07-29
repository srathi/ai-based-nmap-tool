import pytest
from unittest.mock import patch, MagicMock


class TestTargetParser:
    def test_target_parse_ip(self):
        from backend.engine.target_parser import TargetParser
        result = TargetParser.parse("192.168.1.1")
        assert result["type"] == "ip"
        assert result["value"] == "192.168.1.1"

    def test_target_parse_cidr(self):
        from backend.engine.target_parser import TargetParser
        result = TargetParser.parse("192.168.1.0/24")
        assert result["type"] == "cidr"
        assert "192.168.1.0/24" in result["value"]

    def test_target_parse_range(self):
        from backend.engine.target_parser import TargetParser
        result = TargetParser.parse("192.168.1.1-100")
        assert result["type"] == "range"
        assert result["value"] == "192.168.1.1-100"

    def test_target_parse_hostname(self):
        from backend.engine.target_parser import TargetParser
        result = TargetParser.parse("example.com")
        assert result["type"] == "hostname"
        assert result["value"] == "example.com"

    def test_target_parse_invalid(self):
        from backend.engine.target_parser import TargetParser
        with pytest.raises(ValueError, match="Could not determine target type"):
            TargetParser.parse("not_a_valid_target!!!")

    def test_target_parse_empty(self):
        from backend.engine.target_parser import TargetParser
        with pytest.raises(ValueError, match="cannot be empty"):
            TargetParser.parse("")

    def test_target_validate_valid(self):
        from backend.engine.target_parser import TargetParser
        valid, reason = TargetParser.validate_target("192.168.1.1")
        assert valid is True
        assert "valid IP" in reason

    def test_target_validate_cidr(self):
        from backend.engine.target_parser import TargetParser
        valid, reason = TargetParser.validate_target("10.0.0.0/24")
        assert valid is True

    def test_target_validate_invalid(self):
        from backend.engine.target_parser import TargetParser
        valid, reason = TargetParser.validate_target("not_a_valid_hostname_or_ip!!!")
        assert valid is False

    def test_target_validate_empty(self):
        from backend.engine.target_parser import TargetParser
        valid, reason = TargetParser.validate_target("")
        assert valid is False
        assert "empty" in reason

    def test_target_expand_cidr(self):
        from backend.engine.target_parser import TargetParser
        ips = TargetParser.expand_targets("192.168.1.0/30")
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    def test_target_expand_single_ip(self):
        from backend.engine.target_parser import TargetParser
        ips = TargetParser.expand_targets("192.168.1.1")
        assert ips == ["192.168.1.1"]

    def test_target_expand_hostname(self):
        from backend.engine.target_parser import TargetParser
        ips = TargetParser.expand_targets("example.com")
        assert ips == ["example.com"]


class TestNmapScanner:
    def _make_scanner(self):
        from backend.engine.scanner import NmapScanner
        scanner = NmapScanner.__new__(NmapScanner)
        scanner.timeout = 600
        scanner._check_nmap = MagicMock()
        return scanner

    def test_build_args_tcp_connect(self):
        scanner = self._make_scanner()
        args = scanner._build_args(target="192.168.1.1", ports="22,80", scan_type="tcp_connect", timing="T4")
        assert "nmap" in args
        assert "-sT" in args
        assert "-p" in args
        assert "22,80" in args
        assert "-T4" in args
        assert "192.168.1.1" in args

    def test_build_args_syn_scan(self):
        scanner = self._make_scanner()
        args = scanner._build_args(target="10.0.0.1", ports="443", scan_type="syn", timing="T3")
        assert "-sS" in args

    def test_build_args_udp(self):
        scanner = self._make_scanner()
        args = scanner._build_args(target="10.0.0.1", scan_type="udp", udp_ports="53,123")
        assert "-sU" in args
        assert "53,123" in args

    def test_build_args_discovery(self):
        scanner = self._make_scanner()
        args = scanner._build_args(target="10.0.0.0/24", discovery=True)
        assert "-sn" in args
        assert "-sT" not in args

    def test_build_args_service_os_detect(self):
        scanner = self._make_scanner()
        args = scanner._build_args(target="192.168.1.1", ports="1-1000", scan_type="tcp_connect", service_detect=True, os_detect=True)
        assert "-sV" in args
        assert "-O" in args

    def test_build_args_invalid_scan_type(self):
        scanner = self._make_scanner()
        with pytest.raises(ValueError, match="Unknown scan type"):
            scanner._build_args(target="x", scan_type="invalid")

    def test_parse_xml(self, sample_raw_nmap):
        scanner = self._make_scanner()
        result = scanner._parse_nmap_xml(sample_raw_nmap)
        assert result is not None
        assert len(result["hosts"]) == 2
        assert result["hosts"][0]["ip"] == "192.168.1.1"
        assert result["hosts"][0]["hostname"] == "gateway.local"
        assert len(result["hosts"][0]["ports"]) == 2
        assert result["hosts"][0]["ports"][0]["port"] == 22
        assert result["hosts"][0]["ports"][0]["service_name"] == "ssh"
        assert result["hosts"][1]["ip"] == "10.0.0.1"

    def test_parse_xml_empty(self):
        scanner = self._make_scanner()
        assert scanner._parse_nmap_xml("") is None
        assert scanner._parse_nmap_xml("   ") is None
        assert scanner._parse_nmap_xml("not xml") is None

    def test_scan_with_invalid_target(self):
        scanner = self._make_scanner()
        result = scanner.scan(target="invalid!!!")
        assert result["success"] is False
        assert "Invalid target" in result.get("error", "")

    def test_scan_with_mocked_subprocess(self, sample_raw_nmap):
        scanner = self._make_scanner()
        mock_proc = MagicMock()
        mock_proc.stdout = sample_raw_nmap
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        with patch("subprocess.run", return_value=mock_proc):
            result = scanner.scan(target="192.168.1.1", ports="22,80")
        assert result["success"] is True
        assert len(result["hosts"]) == 2
        assert result["stats"]["total_hosts"] == 2
        assert result["stats"]["total_ports"] == 3

    def test_discovery_sweep(self):
        from backend.engine.discovery import HostDiscovery
        discovery = HostDiscovery.__new__(HostDiscovery)
        discovery.timeout = 120
        discovery._check_nmap = MagicMock()
        xml_data = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="gw.local" type="PTR"/></hostnames>
    <times srtt="1000"/></host>
  <host><status state="up"/><address addr="192.168.1.2" addrtype="ipv4"/><hostnames/></host>
</nmaprun>"""
        mock_proc = MagicMock()
        mock_proc.stdout = xml_data
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        with patch("subprocess.run", return_value=mock_proc):
            result = discovery.discover("192.168.1.0/30")
        assert result["success"] is True
        assert len(result["hosts"]) == 2
        assert result["hosts"][0]["ip"] == "192.168.1.1"

    def test_discovery_invalid_target(self):
        from backend.engine.discovery import HostDiscovery
        discovery = HostDiscovery.__new__(HostDiscovery)
        result = discovery.discover("not valid")
        assert result["success"] is False


class TestScanResultParser:
    def test_parser_normalize(self, sample_scan_result):
        from backend.engine.parser import ScanResultParser
        result = ScanResultParser.normalize(sample_scan_result)
        assert result["success"] is True
        assert len(result["hosts"]) == 2
        assert result["stats"]["total_hosts"] == 2
        assert result["stats"]["total_ports"] == 5
        assert result["hosts"][0]["ip"] == "192.168.1.1"
        assert result["hosts"][0]["ports"][0]["port"] == 22

    def test_parser_normalize_empty(self):
        from backend.engine.parser import ScanResultParser
        result = ScanResultParser.normalize({})
        assert result["success"] is False
        assert result["hosts"] == []
        assert result["stats"]["total_hosts"] == 0

    def test_parser_normalize_partial(self):
        from backend.engine.parser import ScanResultParser
        result = ScanResultParser.normalize({"success": True, "hosts": [{"ip": "10.0.0.1", "status": "up", "ports": []}]})
        assert result["hosts"][0]["ip"] == "10.0.0.1"

    def test_parser_extract_services(self, sample_scan_result):
        from backend.engine.parser import ScanResultParser
        hosts = sample_scan_result["hosts"]
        all_ports = [p for h in hosts for p in h.get("ports", [])]
        result = ScanResultParser.extract_services(all_ports)
        assert result["service_count"] == 4
        assert result["unique_services"] == 4
        assert "ssh" in result["service_breakdown"]
        assert "http" in result["service_breakdown"]
        assert "https" in result["service_breakdown"]
        assert "mysql" in result["service_breakdown"]

    def test_parser_compute_summary(self, sample_scan_result):
        from backend.engine.parser import ScanResultParser
        hosts = sample_scan_result["hosts"]
        summary = ScanResultParser.compute_summary(hosts)
        assert summary["total_hosts"] == 2
        assert summary["total_ports_open"] == 4
        assert summary["total_ports_filtered"] == 1
        assert "Linux 5.4" in summary["os_detections"]
        assert "ssh" in summary["top_services"]
        assert len(summary["top_open_ports"]) == 4

    def test_parser_validate_result(self, sample_scan_result):
        from backend.engine.parser import ScanResultParser
        data = {
            "success": True,
            "raw_output": "",
            "command": "nmap ...",
            "return_code": 0,
            "duration_ms": 1000,
            "hosts": [{"ip": "10.0.0.1", "hostname": "", "mac": "", "os_guess": "", "latency": "", "status": "up", "ports": [{"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh", "service_version": "", "service_product": "", "banner": ""}]}],
            "stats": {"elapsed": 1.0, "total_hosts": 1, "total_ports": 1},
        }
        valid, errors = ScanResultParser.validate_result(data)
        assert valid is True, errors
        assert errors == []

    def test_parser_validate_invalid(self):
        from backend.engine.parser import ScanResultParser
        valid, errors = ScanResultParser.validate_result({})
        assert valid is False
        assert any("success" in e for e in errors)

    def test_parser_merge_results(self):
        from backend.engine.parser import ScanResultParser
        r1 = {
            "success": True, "command": "scan1", "duration_ms": 1000,
            "hosts": [{"ip": "10.0.0.1", "hostname": "", "mac": "", "os_guess": "", "latency": "", "status": "up",
                       "ports": [{"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh", "service_version": "", "service_product": "", "banner": ""}]}],
            "stats": {"elapsed": 1.0, "total_hosts": 1, "total_ports": 1},
        }
        r2 = {
            "success": True, "command": "scan2", "duration_ms": 2000,
            "hosts": [{"ip": "10.0.0.1", "hostname": "", "mac": "", "os_guess": "", "latency": "", "status": "up",
                       "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service_name": "http", "service_version": "", "service_product": "", "banner": ""},
                                 {"port": 443, "protocol": "tcp", "state": "open", "service_name": "https", "service_version": "", "service_product": "", "banner": ""}]}],
            "stats": {"elapsed": 2.0, "total_hosts": 1, "total_ports": 2},
        }
        merged = ScanResultParser.merge_results(r1, r2)
        assert merged["merged"] is True
        assert len(merged["hosts"]) == 1
        assert len(merged["hosts"][0]["ports"]) == 3
        assert merged["duration_ms"] == 3000


class TestHostDiscovery:
    def _make_discovery(self):
        from backend.engine.discovery import HostDiscovery
        d = HostDiscovery.__new__(HostDiscovery)
        d.timeout = 120
        d._check_nmap = MagicMock()
        return d

    def test_ping_sweep(self):
        discovery = self._make_discovery()
        xml_data = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><hostnames/></host>
  <host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/><hostnames/></host>
</nmaprun>"""
        mock_proc = MagicMock()
        mock_proc.stdout = xml_data
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        with patch("subprocess.run", return_value=mock_proc):
            result = discovery.ping_sweep(["10.0.0.1", "10.0.0.2"])
        assert result["success"] is True
        assert len(result["hosts"]) == 2

    def test_ping_sweep_no_targets(self):
        from backend.engine.discovery import HostDiscovery
        discovery = HostDiscovery.__new__(HostDiscovery)
        result = discovery.ping_sweep([])
        assert result["success"] is False

    def test_ping_sweep_invalid_targets(self):
        from backend.engine.discovery import HostDiscovery
        discovery = HostDiscovery.__new__(HostDiscovery)
        result = discovery.ping_sweep(["bad input"])
        assert result["success"] is False
