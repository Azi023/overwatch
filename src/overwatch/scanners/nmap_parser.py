"""
Nmap XML output parser.
"""
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def parse_nmap_xml(xml_path: str) -> Dict[str, Any]:
    """Parse nmap XML output into structured data."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as exc:
        logger.error("Failed to parse nmap XML %s: %s", xml_path, exc)
        return {"ports": [], "target": {}, "error": str(exc)}

    result: Dict[str, Any] = {"ports": [], "target": {}}

    for host in root.findall("host"):
        # Get host status
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Get addresses
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                result["target"]["ip"] = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                result["target"]["mac"] = addr.get("addr")

        # Get hostnames
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            result["target"]["hostnames"] = [
                h.get("name") for h in hostnames_elem.findall("hostname")
            ]

        # Get OS info
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                result["target"]["os"] = {
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy"),
                }

        # Get ports
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_data: Dict[str, Any] = {
                    "port": int(port.get("portid", 0)),
                    "protocol": port.get("protocol", "tcp"),
                    "state": "open",
                    "service": "unknown",
                    "product": "",
                    "version": "",
                    "cpe": [],
                    "scripts": {},
                }

                service = port.find("service")
                if service is not None:
                    port_data["service"] = service.get("name", "unknown")
                    port_data["product"] = service.get("product", "")
                    port_data["version"] = service.get("version", "")
                    port_data["extrainfo"] = service.get("extrainfo", "")
                    port_data["tunnel"] = service.get("tunnel", "")

                    for cpe in service.findall("cpe"):
                        port_data["cpe"].append(cpe.text)

                # Parse NSE scripts
                for script in port.findall("script"):
                    port_data["scripts"][script.get("id", "")] = script.get("output", "")

                result["ports"].append(port_data)

    return result
