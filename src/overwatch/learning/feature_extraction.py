"""
Feature extractors for converting raw observations to ML-ready feature vectors.
"""
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List


class FeatureExtractor(ABC):
    """Base class for extracting ML features from observations."""

    @abstractmethod
    def extract(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        """Convert raw observation to a normalised feature vector (values 0.0–1.0)."""


class HTTPResponseFeatureExtractor(FeatureExtractor):
    SQL_ERROR_PATTERNS = [
        (r"SQL syntax.*MySQL", "mysql_syntax_error", 0.9),
        (r"ORA-\d+", "oracle_error", 0.85),
        (r"SQLSTATE", "sqlstate_error", 0.8),
        (r"syntax error at or near", "postgres_error", 0.85),
        (r"Microsoft SQL Native Client", "mssql_error", 0.85),
        (r"unclosed quotation mark", "quote_error", 0.7),
        (r"you have an error in your sql", "generic_sql_error", 0.75),
    ]
    XSS_PATTERNS = [
        (r"<script[^>]*>", "script_tag_reflection", 0.6),
        (r"javascript:", "javascript_protocol", 0.5),
        (r"on\w+\s*=", "event_handler", 0.4),
    ]

    def extract(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        features: Dict[str, float] = {}
        body = raw_data.get("body", "").lower()
        headers = raw_data.get("headers", {})
        status_code = raw_data.get("status_code", 0)
        response_time = raw_data.get("response_time_ms", 0)

        for pattern, name, weight in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                features[f"sqli_{name}"] = weight

        for pattern, name, weight in self.XSS_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                features[f"xss_{name}"] = weight

        features["status_code_5xx"] = 1.0 if 500 <= status_code < 600 else 0.0
        features["status_code_4xx"] = 1.0 if 400 <= status_code < 500 else 0.0
        features["response_length"] = min(len(body) / 100_000, 1.0)
        features["response_time_slow"] = 1.0 if response_time > 5000 else 0.0
        features["response_time_very_slow"] = 1.0 if response_time > 10_000 else 0.0
        features["response_time_normalized"] = min(response_time / 30_000, 1.0)

        security_headers = [
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
            "strict-transport-security",
        ]
        headers_lower = {k.lower(): v for k, v in headers.items()}
        features["security_headers_count"] = (
            sum(1 for h in security_headers if h in headers_lower) / len(security_headers)
        )

        error_keywords = ["exception", "stack trace", "debug", "line ", "file "]
        features["error_verbosity"] = (
            sum(1 for kw in error_keywords if kw in body) / len(error_keywords)
        )
        return features


class TimingFeatureExtractor(FeatureExtractor):
    def extract(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        features: Dict[str, float] = {}
        baseline = raw_data.get("baseline_ms", 100)
        test_time = raw_data.get("test_ms", 100)
        expected_delay = raw_data.get("expected_delay_ms", 5000)

        time_diff = test_time - baseline
        features["time_diff_ms"] = min(time_diff / 30_000, 1.0)

        if expected_delay > 0:
            delay_accuracy = 1 - abs(time_diff - expected_delay) / expected_delay
            features["delay_accuracy"] = max(0.0, min(delay_accuracy, 1.0))

        test_times: List[float] = raw_data.get("test_times", [test_time])
        if len(test_times) > 1:
            mean = sum(test_times) / len(test_times)
            variance = sum((t - mean) ** 2 for t in test_times) / len(test_times)
            features["timing_consistency"] = 1.0 / (1.0 + variance / 1000)

        return features


class PortScanFeatureExtractor(FeatureExtractor):
    HIGH_RISK_PORTS = {
        21, 22, 23, 25, 110, 135, 139, 143, 445,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 27017,
    }
    WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888}
    DB_PORTS = {1433, 1521, 3306, 5432, 6379, 27017, 9200}
    REMOTE_ACCESS_PORTS = {22, 23, 3389, 5900}
    DANGEROUS_SERVICES = {"telnet", "ftp", "rsh", "rlogin", "vnc", "x11"}

    def extract(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        features: Dict[str, float] = {}
        ports_found: List[Dict] = raw_data.get("ports_found", [])
        scan_duration = raw_data.get("scan_duration_ms", 0)
        success = raw_data.get("success", False)

        port_numbers: set = set()
        services: set = set()
        for p in ports_found:
            if isinstance(p, dict):
                port_numbers.add(p.get("port", 0))
                services.add(p.get("service", "").lower())

        features["web_ports_count"] = len(port_numbers & self.WEB_PORTS) / max(len(self.WEB_PORTS), 1)
        features["db_ports_count"] = len(port_numbers & self.DB_PORTS) / max(len(self.DB_PORTS), 1)
        features["remote_access_ports_count"] = len(port_numbers & self.REMOTE_ACCESS_PORTS) / max(len(self.REMOTE_ACCESS_PORTS), 1)
        features["high_risk_ports_ratio"] = len(port_numbers & self.HIGH_RISK_PORTS) / max(len(port_numbers), 1)
        features["total_ports_found"] = min(len(port_numbers) / 100, 1.0)
        features["service_diversity"] = min(len(services) / 20, 1.0)
        features["scan_success"] = 1.0 if success else 0.0
        features["scan_duration_normalized"] = min(scan_duration / 600_000, 1.0)
        features["dangerous_services_found"] = 1.0 if services & self.DANGEROUS_SERVICES else 0.0
        has_versions = sum(1 for p in ports_found if isinstance(p, dict) and p.get("version"))
        features["version_detection_ratio"] = has_versions / max(len(ports_found), 1)

        return features
