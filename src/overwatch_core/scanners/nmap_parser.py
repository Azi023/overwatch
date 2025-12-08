# src/overwatch_core/scanners/nmap_parser.py
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap_xml(xml_path: str) -> dict:
    xml_file = Path(xml_path)
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Nmap XML root usually has <host> elements
    host_elem = root.find("host")
    if host_elem is None:
        return {"target": xml_file.parent.name, "ports": []}

    address_elem = host_elem.find("address")
    target_ip = (
        address_elem.get("addr") if address_elem is not None else xml_file.parent.name
    )

    ports_summary = []
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            port_id = int(port_elem.get("portid"))
            proto = port_elem.get("protocol")

            service_elem = port_elem.find("service")
            if service_elem is not None:
                service_name = service_elem.get("name")
                product = service_elem.get("product")
                version = service_elem.get("version")
            else:
                service_name = product = version = None

            ports_summary.append(
                {
                    "port": port_id,
                    "protocol": proto,
                    "service": service_name,
                    "product": product,
                    "version": version,
                }
            )

    return {
        "target": target_ip,
        "ports": ports_summary,
    }
