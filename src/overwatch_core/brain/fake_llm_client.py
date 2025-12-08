# src/overwatch_core/brain/fake_llm_client.py
from typing import Dict, List


class FakeLLMClient:
    """
    Placeholder 'brain' that uses simple rules instead of a real LLM.
    Later we replace this with a proper LLMClient implementation.
    """

    def suggest_next_steps(self, summary: Dict) -> str:
        target = summary.get("target")
        ports: List[Dict] = summary.get("ports", [])

        lines = [f"For target {target}, here are some basic next steps:"]

        http_ports = [p for p in ports if p.get("service") in ("http", "https")]
        ssh_ports = [p for p in ports if p.get("service") == "ssh"]

        if http_ports:
            lines.append("- HTTP/HTTPS detected:")
            for p in http_ports:
                lines.append(
                    f"  - Port {p['port']} ({p['service']}): run dir fuzzing (ffuf/gobuster), check for default pages, "
                    "fingerprint technologies, and identify potential CVEs based on product/version."
                )

        if ssh_ports:
            lines.append("- SSH detected:")
            lines.append(
                "  - Consider version-based vulns, weak auth, or pivoting after initial foothold."
            )

        if not http_ports and not ssh_ports:
            lines.append(
                "- No typical web or SSH ports found; focus on any unusual ports and service banners."
            )

        lines.append(
            "- Save these results into your notes and think about chaining 'low' misconfigs later (e.g. info leak + auth bypass)."
        )

        return "\n".join(lines)
