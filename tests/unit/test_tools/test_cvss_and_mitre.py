"""
Unit tests for CVSS scorer and MITRE mapper.
"""
import pytest
from src.overwatch.reporting.cvss_scorer import CVSSScorer
from src.overwatch.reporting.mitre_mapper import MITREMapper


class TestCvssScorer:
    def setup_method(self):
        self.scorer = CVSSScorer()

    def test_network_high_impact_is_critical(self):
        score = self.scorer.calculate_base_score(
            av="Network", ac="Low", pr="None", ui="None",
            s="Unchanged", c="High", i="High", a="None",
        )
        assert score >= 9.0

    def test_local_low_impact_is_medium_or_below(self):
        score = self.scorer.calculate_base_score(
            av="Local", ac="High", pr="High", ui="Required",
            s="Unchanged", c="Low", i="None", a="None",
        )
        assert score < 5.0

    def test_score_to_severity_critical(self):
        assert self.scorer.score_to_severity(9.5) == "Critical"

    def test_score_to_severity_high(self):
        assert self.scorer.score_to_severity(8.0) == "High"

    def test_score_to_severity_medium(self):
        assert self.scorer.score_to_severity(5.0) == "Medium"

    def test_score_to_severity_low(self):
        assert self.scorer.score_to_severity(2.5) == "Low"

    def test_score_to_severity_info(self):
        assert self.scorer.score_to_severity(0.0) == "Info"

    def test_vector_string_format(self):
        vector = self.scorer.generate_vector_string(
            av="Network", ac="Low", pr="None", ui="None",
            s="Unchanged", c="High", i="High", a="None",
        )
        assert vector.startswith("CVSS:3.1/")
        assert "AV:N" in vector

    def test_invalid_metric_raises(self):
        with pytest.raises((KeyError, ValueError)):
            self.scorer.calculate_base_score(
                av="INVALID", ac="Low", pr="None", ui="None",
                s="Unchanged", c="High", i="High", a="None",
            )


class TestMitreMapper:
    def setup_method(self):
        self.mapper = MITREMapper()

    def test_sqli_maps_to_techniques(self):
        # The mapper uses "sqli" or "sql_injection" keys
        finding = {"vulnerability_type": "sqli", "cwe_ids": [], "mitre_techniques": []}
        techniques = self.mapper.map_finding(finding)
        assert isinstance(techniques, list)
        assert len(techniques) >= 1

    def test_xss_has_techniques(self):
        finding = {"vulnerability_type": "xss", "cwe_ids": [], "mitre_techniques": []}
        techniques = self.mapper.map_finding(finding)
        assert len(techniques) >= 1

    def test_unknown_vuln_returns_list(self):
        finding = {"vulnerability_type": "completely_unknown_xyz", "cwe_ids": [], "mitre_techniques": []}
        techniques = self.mapper.map_finding(finding)
        assert isinstance(techniques, list)

    def test_technique_description_known(self):
        desc = self.mapper.get_technique_description("T1190")
        assert isinstance(desc, str)

    def test_technique_description_unknown_returns_string(self):
        desc = self.mapper.get_technique_description("T9999")
        assert isinstance(desc, str)
