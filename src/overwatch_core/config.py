# src/overwatch_core/config.py
from pathlib import Path


class Settings:
    def __init__(self) -> None:
        # project root = .../overwatch
        base_dir = Path(__file__).resolve().parents[2]

        # paths we need
        self.paths = {
            "base_dir": str(base_dir),
            "data_root": str(base_dir / "data"),
        }

        # Nmap scan profiles (can move to YAML later)
        self.scan_profiles = {
            "nmap": {
                "safe": {"flags": "-sV -T2"},
                "balanced": {"flags": "-sV -sC -T3"},
                "aggressive": {"flags": "-A -T4"},
            }
        }


settings = Settings()
