import xml.etree.ElementTree as ET
from xml.dom import minidom

from backend.exporters.base import BaseExporter


class XMLExporter(BaseExporter):

    def export(self, scan_result: dict) -> str:
        root = ET.Element("scan_result")
        hosts_elem = ET.SubElement(root, "hosts")
        for host in scan_result.get("hosts", []):
            host_elem = ET.SubElement(hosts_elem, "host")
            ET.SubElement(host_elem, "ip").text = host.get("ip", "")
            ET.SubElement(host_elem, "hostname").text = host.get("hostname", "")
            ET.SubElement(host_elem, "status").text = host.get("status", "")
            ET.SubElement(host_elem, "os_guess").text = host.get("os_guess", "")
            ports_elem = ET.SubElement(host_elem, "ports")
            for port in host.get("ports", []):
                port_elem = ET.SubElement(ports_elem, "port")
                ET.SubElement(port_elem, "port_number").text = str(port.get("port", ""))
                ET.SubElement(port_elem, "protocol").text = port.get("protocol", "tcp")
                ET.SubElement(port_elem, "state").text = port.get("state", "")
                ET.SubElement(port_elem, "service").text = port.get("service", "")
                ET.SubElement(port_elem, "version").text = port.get("version", "")
                ET.SubElement(port_elem, "product").text = port.get("product", "")
        ET.SubElement(root, "total_hosts").text = str(scan_result.get("total_hosts", 0))

        rough_string = ET.tostring(root, encoding="unicode")
        dom = minidom.parseString(rough_string)
        return dom.toprettyxml(indent="  ")

    def get_mime_type(self) -> str:
        return "application/xml"

    def get_extension(self) -> str:
        return ".xml"
