"""
CVSS v3.1 base score calculator for Overwatch V2.

Reference: https://www.first.org/cvss/calculator/3.1
"""
from __future__ import annotations

import math
from typing import Dict


# ──────────────────────────── Metric tables ────────────────────────────

# Attack Vector
_AV: Dict[str, float] = {
    "Network": 0.85,
    "Adjacent": 0.62,
    "Local": 0.55,
    "Physical": 0.20,
}

# Attack Complexity
_AC: Dict[str, float] = {
    "Low": 0.77,
    "High": 0.44,
}

# Privileges Required (Unchanged scope)
_PR_U: Dict[str, float] = {
    "None": 0.85,
    "Low": 0.62,
    "High": 0.27,
}

# Privileges Required (Changed scope)
_PR_C: Dict[str, float] = {
    "None": 0.85,
    "Low": 0.68,
    "High": 0.50,
}

# User Interaction
_UI: Dict[str, float] = {
    "None": 0.85,
    "Required": 0.62,
}

# Scope
_SCOPE_CHANGED = "Changed"

# Confidentiality / Integrity / Availability Impact
_CIA: Dict[str, float] = {
    "None": 0.00,
    "Low": 0.22,
    "High": 0.56,
}

# Severity thresholds (CVSS v3.1)
_SEVERITY_THRESHOLDS = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "Info"),
]


# ──────────────────────────── Scorer ────────────────────────────

class CVSSScorer:
    """
    Compute CVSS v3.1 base scores from individual metric values.

    Usage::

        scorer = CVSSScorer()
        score = scorer.calculate_base_score(
            av="Network", ac="Low", pr="None", ui="None",
            s="Unchanged", c="High", i="High", a="None"
        )
        print(score)           # 9.1
        print(scorer.score_to_severity(score))   # Critical
        print(scorer.generate_vector_string(
            av="Network", ac="Low", pr="None", ui="None",
            s="Unchanged", c="High", i="High", a="None"
        ))
    """

    def calculate_base_score(
        self,
        av: str,
        ac: str,
        pr: str,
        ui: str,
        s: str,
        c: str,
        i: str,
        a: str,
    ) -> float:
        """
        Calculate the CVSS v3.1 base score.

        Args:
            av: Attack Vector      – Network / Adjacent / Local / Physical
            ac: Attack Complexity  – Low / High
            pr: Privileges Required – None / Low / High
            ui: User Interaction   – None / Required
            s:  Scope              – Unchanged / Changed
            c:  Confidentiality    – None / Low / High
            i:  Integrity          – None / Low / High
            a:  Availability       – None / Low / High

        Returns:
            Base score as float in [0.0, 10.0], rounded to 1 decimal place.

        Raises:
            ValueError: If any metric value is unrecognised.
        """
        av_val = self._lookup("AV", _AV, av)
        ac_val = self._lookup("AC", _AC, ac)
        ui_val = self._lookup("UI", _UI, ui)

        # PR depends on scope
        pr_table = _PR_C if s == _SCOPE_CHANGED else _PR_U
        pr_val = self._lookup("PR", pr_table, pr)

        c_val = self._lookup("C", _CIA, c)
        i_val = self._lookup("I", _CIA, i)
        a_val = self._lookup("A", _CIA, a)

        # Exploitability sub-score
        ess = 8.22 * av_val * ac_val * pr_val * ui_val

        # Impact sub-score
        iss_base = 1.0 - (1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val)

        if s == _SCOPE_CHANGED:
            iss = 7.52 * (iss_base - 0.029) - 3.25 * ((iss_base - 0.02) ** 15)
        else:
            iss = 6.42 * iss_base

        if iss <= 0.0:
            return 0.0

        if s == _SCOPE_CHANGED:
            raw = min(1.08 * (iss + ess), 10.0)
        else:
            raw = min(iss + ess, 10.0)

        return self._roundup(raw)

    # ── Helpers ───────────────────────────────────────────────────

    @staticmethod
    def _lookup(metric_name: str, table: Dict[str, float], value: str) -> float:
        if value not in table:
            raise ValueError(
                f"Unknown value '{value}' for metric {metric_name}. "
                f"Valid values: {list(table.keys())}"
            )
        return table[value]

    @staticmethod
    def _roundup(value: float) -> float:
        """
        CVSS v3.1 'Roundup' function: round up to the nearest 0.1.
        """
        int_input = round(value * 100_000)
        if int_input % 10_000 == 0:
            return int_input / 100_000
        return math.floor(int_input / 10_000 + 1) / 10.0

    def score_to_severity(self, score: float) -> str:
        """Convert a numeric CVSS score to a severity label."""
        for threshold, label in _SEVERITY_THRESHOLDS:
            if score >= threshold:
                return label
        return "Info"

    def generate_vector_string(
        self,
        av: str,
        ac: str,
        pr: str,
        ui: str,
        s: str,
        c: str,
        i: str,
        a: str,
    ) -> str:
        """
        Generate the standard CVSS v3.1 vector string.

        Returns:
            e.g. ``"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"``
        """
        _AV_ABBR = {"Network": "N", "Adjacent": "A", "Local": "L", "Physical": "P"}
        _AC_ABBR = {"Low": "L", "High": "H"}
        _PR_ABBR = {"None": "N", "Low": "L", "High": "H"}
        _UI_ABBR = {"None": "N", "Required": "R"}
        _S_ABBR  = {"Unchanged": "U", "Changed": "C"}
        _CIA_ABBR = {"None": "N", "Low": "L", "High": "H"}

        return (
            f"CVSS:3.1"
            f"/AV:{_AV_ABBR.get(av, av)}"
            f"/AC:{_AC_ABBR.get(ac, ac)}"
            f"/PR:{_PR_ABBR.get(pr, pr)}"
            f"/UI:{_UI_ABBR.get(ui, ui)}"
            f"/S:{_S_ABBR.get(s, s)}"
            f"/C:{_CIA_ABBR.get(c, c)}"
            f"/I:{_CIA_ABBR.get(i, i)}"
            f"/A:{_CIA_ABBR.get(a, a)}"
        )
