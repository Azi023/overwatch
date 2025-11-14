# src/overwatch_core/scanners/nmap_runner.py
import os
import subprocess
from datetime import datetime
from pathlib import Path

def run_nmap_scan(target: str, profile: str, settings) -> str:
    profile_cfg = settings.scan_profiles["nmap"].get(profile)
    if not profile_cfg:
        raise ValueError(f"Unknown Nmap profile: {profile}")

    flags = profile_cfg["flags"]
    data_root = Path(settings.paths["data_root"])
    engagement_dir = data_root / "engagements" / target
    engagement_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_path = engagement_dir / f"{timestamp}_nmap.xml"

    cmd = f"nmap {flags} -oX {xml_path} {target}"
    print(f"[+] Running: {cmd}")
    subprocess.run(cmd, shell=True, check=True)

    return str(xml_path)
