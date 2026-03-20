"""
KnowledgeBase - YAML-based vulnerability pattern, tool profile, and playbook loader.

All YAML files under knowledge_base/ are loaded at startup and kept in memory.
No database writes are performed; this is a read-only reference layer.
"""
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """
    In-memory knowledge base loaded from YAML files on disk.

    Directory structure expected:
        kb_dir/
          vulnerability_patterns/   *.yaml   → vulnerability pattern dicts
          tool_profiles/            *.yaml   → tool profile dicts
          attack_playbooks/         *.yaml   → attack playbook dicts

    All YAML documents must be either a dict (single entry) or a list of dicts
    (multiple entries per file).
    """

    def __init__(self, kb_dir: str = "knowledge_base") -> None:
        self._kb_dir = Path(kb_dir)
        self._vulnerability_patterns: List[dict] = []
        self._tool_profiles: Dict[str, dict] = {}
        self._attack_playbooks: Dict[str, dict] = {}

    # ─────────────────────── Loading ─────────────────────────────

    def load_all(self) -> None:
        """
        Load all YAML files from the knowledge base directory.

        Clears any previously loaded data before reloading. Safe to call
        multiple times (e.g., to hot-reload after file changes).
        """
        self._vulnerability_patterns = []
        self._tool_profiles = {}
        self._attack_playbooks = {}

        if not self._kb_dir.exists():
            logger.warning(
                "KnowledgeBase: directory '%s' does not exist — no patterns loaded.",
                self._kb_dir,
            )
            return

        self._load_directory(
            self._kb_dir / "vulnerability_patterns",
            self._vulnerability_patterns,
            None,
        )
        self._load_directory(
            self._kb_dir / "tool_profiles",
            None,
            self._tool_profiles,
        )
        self._load_directory(
            self._kb_dir / "attack_playbooks",
            None,
            self._attack_playbooks,
        )

        logger.info(
            "KnowledgeBase loaded: %d vulnerability patterns, %d tool profiles, "
            "%d playbooks",
            len(self._vulnerability_patterns),
            len(self._tool_profiles),
            len(self._attack_playbooks),
        )

    def _load_directory(
        self,
        directory: Path,
        list_store: Optional[List[dict]],
        dict_store: Optional[Dict[str, dict]],
    ) -> None:
        """Load all .yaml files from directory into the appropriate store."""
        if not directory.exists():
            logger.debug("KnowledgeBase: subdirectory '%s' not found, skipping.", directory)
            return

        for yaml_file in sorted(directory.glob("*.yaml")):
            try:
                with yaml_file.open("r", encoding="utf-8") as fh:
                    document = yaml.safe_load(fh)

                if document is None:
                    logger.debug("KnowledgeBase: empty file '%s', skipping.", yaml_file)
                    continue

                entries: List[dict] = (
                    document if isinstance(document, list) else [document]
                )

                for entry in entries:
                    if not isinstance(entry, dict):
                        logger.warning(
                            "KnowledgeBase: unexpected entry type %s in '%s', skipping.",
                            type(entry).__name__,
                            yaml_file,
                        )
                        continue

                    if list_store is not None:
                        list_store.append(entry)

                    if dict_store is not None:
                        name = entry.get("name", yaml_file.stem)
                        dict_store[name] = entry

                logger.debug("KnowledgeBase: loaded '%s'", yaml_file.name)

            except yaml.YAMLError as exc:
                logger.error(
                    "KnowledgeBase: YAML parse error in '%s': %s", yaml_file, exc
                )
            except OSError as exc:
                logger.error(
                    "KnowledgeBase: could not read '%s': %s", yaml_file, exc
                )

    # ─────────────────────── Query API ───────────────────────────

    def get_vulnerability_patterns(
        self, vuln_type: Optional[str] = None
    ) -> List[dict]:
        """
        Return vulnerability patterns.

        If vuln_type is given, filter patterns whose 'name' or 'type' field
        matches (case-insensitive substring match).
        """
        if vuln_type is None:
            return list(self._vulnerability_patterns)

        # Normalise: underscores and hyphens treated as spaces for matching
        needle = vuln_type.lower().replace("_", " ").replace("-", " ")
        return [
            p
            for p in self._vulnerability_patterns
            if needle in str(p.get("name", "")).lower().replace("_", " ").replace("-", " ")
            or needle in str(p.get("type", "")).lower().replace("_", " ").replace("-", " ")
            or needle.replace(" ", "_") in str(p.get("type", "")).lower()
        ]

    def get_tool_profile(self, tool_name: str) -> Optional[dict]:
        """Return the profile dict for the named tool, or None if not loaded."""
        # Try exact match first, then case-insensitive
        profile = self._tool_profiles.get(tool_name)
        if profile is not None:
            return profile

        tool_lower = tool_name.lower()
        for name, prof in self._tool_profiles.items():
            if name.lower() == tool_lower:
                return prof
        return None

    def get_attack_playbook(self, scenario: str) -> Optional[dict]:
        """Return the playbook dict for the named scenario, or None if not found."""
        playbook = self._attack_playbooks.get(scenario)
        if playbook is not None:
            return playbook

        scenario_lower = scenario.lower()
        for name, pb in self._attack_playbooks.items():
            if name.lower() == scenario_lower:
                return pb
        return None

    def get_payloads(self, vuln_type: str) -> List[str]:
        """
        Return all payload strings for a given vulnerability type.

        Searches all patterns whose name matches vuln_type and returns the
        combined 'payloads' list.
        """
        payloads: List[str] = []
        for pattern in self.get_vulnerability_patterns(vuln_type):
            raw = pattern.get("payloads", [])
            if isinstance(raw, list):
                payloads.extend(str(p) for p in raw)
        return payloads

    def search_patterns(self, tech_stack: List[str]) -> List[dict]:
        """
        Return vulnerability patterns relevant to the given technology stack.

        A pattern is considered relevant if any of the tech_stack items appears
        in the pattern's 'tech_stack', 'applies_to', 'name', or 'description'
        fields (case-insensitive).
        """
        if not tech_stack:
            return list(self._vulnerability_patterns)

        needles = [t.lower() for t in tech_stack]
        results: List[dict] = []

        for pattern in self._vulnerability_patterns:
            pattern_text = " ".join(
                str(v)
                for v in [
                    pattern.get("name", ""),
                    pattern.get("description", ""),
                    " ".join(pattern.get("tech_stack", [])),
                    " ".join(pattern.get("applies_to", [])),
                ]
            ).lower()

            if any(needle in pattern_text for needle in needles):
                results.append(pattern)

        return results

    # ─────────────────────── Properties ──────────────────────────

    @property
    def pattern_count(self) -> int:
        return len(self._vulnerability_patterns)

    @property
    def tool_count(self) -> int:
        return len(self._tool_profiles)

    @property
    def playbook_count(self) -> int:
        return len(self._attack_playbooks)

    def __repr__(self) -> str:
        return (
            f"KnowledgeBase(dir={self._kb_dir!r}, "
            f"patterns={self.pattern_count}, "
            f"tools={self.tool_count}, "
            f"playbooks={self.playbook_count})"
        )
