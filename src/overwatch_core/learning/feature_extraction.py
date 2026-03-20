# src/overwatch_core/learning/feature_extraction.py
from abc import ABC, abstractmethod
from typing import Dict, Any, List
import re
from collections import Counter

class FeatureExtractor(ABC):
    """Base class for extracting ML features from observations."""
    
    @abstractmethod
    def extract(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        """Convert raw observation to feature vector."""
        pass

class HTTPResponseFeatureExtractor(FeatureExtractor):
    """Extract features from HTTP responses for vulnerability detection."""
    
    # SQL error patterns with weights
    SQL_ERROR_PATTERNS = [
        (r"SQL syntax.*MySQL", "mysql_syntax_error", 0.9),
        (r"ORA-\d+", "oracle_error", 0.85),
        (r"SQLSTATE", "sqlstate_error", 0.8),
        (r"syntax error at or near", "postgres_error", 0.85),
        (r"Microsoft SQL Native Client", "mssql_error", 0.85),
        (r"unclosed quotation mark", "quote_error", 0.7),
        (r"you have an error in your sql", "generic_sql_error", 0.75),
    ]
    
    # XSS reflection patterns
    XSS_PATTERNS = [
        (r"<script[^>]*>", "script_tag_reflection", 0.6),
        (r"javascript:", "javascript_protocol", 0.5),
        (r"on\w+\s*=", "event_handler", 0.4),
    ]
    
    def extract(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract features from HTTP response.
        
        Features include:
        - Error pattern matches
        - Response timing characteristics
        - Header anomalies
        - Content characteristics
        """
        features = {}
        
        body = raw_data.get("body", "").lower()
        headers = raw_data.get("headers", {})
        status_code = raw_data.get("status_code", 0)
        response_time = raw_data.get("response_time_ms", 0)
        
        # SQL injection indicators
        for pattern, name, weight in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                features[f"sqli_{name}"] = weight
        
        # XSS indicators
        for pattern, name, weight in self.XSS_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                features[f"xss_{name}"] = weight
        
        # Response characteristics
        features["status_code_5xx"] = 1.0 if 500 <= status_code < 600 else 0.0
        features["status_code_4xx"] = 1.0 if 400 <= status_code < 500 else 0.0
        features["response_length"] = min(len(body) / 100000, 1.0)  # Normalized
        
        # Timing features (important for blind injections)
        features["response_time_slow"] = 1.0 if response_time > 5000 else 0.0
        features["response_time_very_slow"] = 1.0 if response_time > 10000 else 0.0
        features["response_time_normalized"] = min(response_time / 30000, 1.0)
        
        # Security headers (defensive posture)
        security_headers = ["x-content-type-options", "x-frame-options", 
                          "content-security-policy", "strict-transport-security"]
        headers_lower = {k.lower(): v for k, v in headers.items()}
        features["security_headers_count"] = sum(
            1 for h in security_headers if h in headers_lower
        ) / len(security_headers)
        
        # Error verbosity (more verbose = likely debug mode)
        error_keywords = ["exception", "stack trace", "debug", "line ", "file "]
        features["error_verbosity"] = sum(
            1 for kw in error_keywords if kw in body
        ) / len(error_keywords)
        
        return features


class TimingFeatureExtractor(FeatureExtractor):
    """Extract features from timing-based observations."""
    
    def extract(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        features = {}
        
        baseline_time = raw_data.get("baseline_ms", 100)
        test_time = raw_data.get("test_ms", 100)
        expected_delay = raw_data.get("expected_delay_ms", 5000)
        
        # Time difference analysis
        time_diff = test_time - baseline_time
        features["time_diff_ms"] = min(time_diff / 30000, 1.0)
        
        # Check if delay matches expected (for time-based SQLi)
        if expected_delay > 0:
            delay_accuracy = 1 - abs(time_diff - expected_delay) / expected_delay
            features["delay_accuracy"] = max(0, min(delay_accuracy, 1.0))
        
        # Consistency across multiple tests
        test_times = raw_data.get("test_times", [test_time])
        if len(test_times) > 1:
            variance = sum((t - sum(test_times)/len(test_times))**2 
                          for t in test_times) / len(test_times)
            features["timing_consistency"] = 1.0 / (1.0 + variance / 1000)
        
        return features
    
"""
Port scan feature extractor - to be added to feature_extraction.py
"""


class PortScanFeatureExtractor(FeatureExtractor):
    """Extract features from port scan results for ML models."""
    
    # Well-known port categories
    HIGH_RISK_PORTS = {21, 22, 23, 25, 110, 135, 139, 143, 445, 1433, 1521, 
                       3306, 3389, 5432, 5900, 6379, 8080, 27017}
    WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888}
    DB_PORTS = {1433, 1521, 3306, 5432, 6379, 27017, 9200}
    REMOTE_ACCESS_PORTS = {22, 23, 3389, 5900}
    
    def extract(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract features from port scan results.
        
        Features include:
        - Port category counts (web, db, remote access)
        - High-risk port ratio
        - Service diversity
        - Scan success indicators
        """
        features = {}
        
        ports_found = raw_data.get("ports_found", [])
        scan_duration = raw_data.get("scan_duration_ms", 0)
        success = raw_data.get("success", False)
        
        # Extract port numbers
        port_numbers = set()
        services = set()
        for port_info in ports_found:
            if isinstance(port_info, dict):
                port_numbers.add(port_info.get("port", 0))
                services.add(port_info.get("service", "").lower())
        
        # Port category features (normalized 0-1)
        features["web_ports_count"] = len(port_numbers & self.WEB_PORTS) / max(len(self.WEB_PORTS), 1)
        features["db_ports_count"] = len(port_numbers & self.DB_PORTS) / max(len(self.DB_PORTS), 1)
        features["remote_access_ports_count"] = len(port_numbers & self.REMOTE_ACCESS_PORTS) / max(len(self.REMOTE_ACCESS_PORTS), 1)
        features["high_risk_ports_ratio"] = len(port_numbers & self.HIGH_RISK_PORTS) / max(len(port_numbers), 1)
        
        # Total ports found (normalized, assuming max 1000 interesting)
        features["total_ports_found"] = min(len(port_numbers) / 100, 1.0)
        
        # Service diversity (more services = larger attack surface)
        features["service_diversity"] = min(len(services) / 20, 1.0)
        
        # Scan metadata features
        features["scan_success"] = 1.0 if success else 0.0
        features["scan_duration_normalized"] = min(scan_duration / 600000, 1.0)  # 10 min max
        
        # Risk indicators
        dangerous_services = {"telnet", "ftp", "rsh", "rlogin", "vnc", "x11"}
        features["dangerous_services_found"] = 1.0 if services & dangerous_services else 0.0
        
        # Version detection (more specific = better for exploitation)
        has_versions = sum(1 for p in ports_found if isinstance(p, dict) and p.get("version"))
        features["version_detection_ratio"] = has_versions / max(len(ports_found), 1)
        
        return features