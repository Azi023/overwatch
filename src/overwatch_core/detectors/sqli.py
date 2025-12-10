# src/overwatch_core/detectors/sqli.py
from typing import Dict, Any, List, Tuple
from ..learning.observation import Observation, ObservationType
from ..learning.feature_extraction import HTTPResponseFeatureExtractor

class SQLiDetector:
    """
    SQL Injection detector with learning capabilities.
    
    Detection Strategy:
    1. Error-based: Look for SQL error messages
    2. Boolean-based: Compare response lengths with true/false conditions
    3. Time-based: Measure response time with SLEEP/WAITFOR
    4. Union-based: Detect successful UNION injection
    
    Each test creates observations that feed the learning system.
    """
    
    # Payloads organized by technique
    PAYLOADS = {
        "error_based": [
            ("'", "single_quote"),
            ('"', "double_quote"),
            ("'--", "comment_single"),
            ("' OR '1'='1", "or_true"),
            ("1' AND '1'='2", "and_false"),
            ("' UNION SELECT NULL--", "union_null"),
        ],
        "time_based": [
            ("' OR SLEEP(5)--", "mysql_sleep", 5000),
            ("'; WAITFOR DELAY '0:0:5'--", "mssql_waitfor", 5000),
            ("' OR pg_sleep(5)--", "postgres_sleep", 5000),
        ],
        "boolean_based": [
            ("' AND '1'='1", "and_true", True),
            ("' AND '1'='2", "and_false", False),
        ]
    }
    
    def __init__(self, http_client, observation_store):
        self.http_client = http_client
        self.observation_store = observation_store
        self.feature_extractor = HTTPResponseFeatureExtractor()
    
    async def test_parameter(
        self, 
        url: str, 
        param_name: str,
        param_value: str,
        scan_job_id: str
    ) -> List[Observation]:
        """
        Test a single parameter for SQL injection.
        Returns observations for the learning system.
        """
        observations = []
        
        # Get baseline response
        baseline = await self._get_baseline(url, param_name, param_value)
        baseline_obs = self._create_observation(
            baseline, scan_job_id, "baseline", param_name
        )
        observations.append(baseline_obs)
        await self.observation_store.save(baseline_obs)
        
        # Test error-based payloads
        for payload, payload_name in self.PAYLOADS["error_based"]:
            test_value = param_value + payload
            response = await self.http_client.request(
                url, {param_name: test_value}
            )
            
            obs = self._create_observation(
                response, scan_job_id, f"error_{payload_name}", param_name
            )
            obs.context_ids = [baseline_obs.id]
            
            # Extract features and make prediction
            features = self.feature_extractor.extract(response)
            obs.features = features
            
            # Rule-based prediction
            rule_confidence = self._rule_based_sqli_check(features, baseline)
            obs.predictions["rule_based"] = rule_confidence
            
            observations.append(obs)
            await self.observation_store.save(obs)
        
        # Test time-based if error-based didn't trigger
        if not any(o.predictions.get("rule_based", 0) > 0.5 for o in observations[1:]):
            time_obs = await self._test_time_based(
                url, param_name, param_value, baseline_obs, scan_job_id
            )
            observations.extend(time_obs)
        
        return observations
    
    async def _test_time_based(
        self,
        url: str,
        param_name: str, 
        param_value: str,
        baseline_obs: Observation,
        scan_job_id: str
    ) -> List[Observation]:
        """Test time-based SQL injection."""
        observations = []
        
        for payload, payload_name, expected_delay in self.PAYLOADS["time_based"]:
            test_value = param_value + payload
            
            # Multiple tests for consistency
            times = []
            for _ in range(3):
                start = time.time()
                response = await self.http_client.request(
                    url, {param_name: test_value}
                )
                elapsed = (time.time() - start) * 1000
                times.append(elapsed)
            
            avg_time = sum(times) / len(times)
            
            obs = self._create_observation(
                response, scan_job_id, f"time_{payload_name}", param_name
            )
            obs.raw_data["test_times"] = times
            obs.raw_data["expected_delay_ms"] = expected_delay
            obs.raw_data["baseline_ms"] = baseline_obs.raw_data.get("response_time_ms", 100)
            obs.context_ids = [baseline_obs.id]
            
            # Time-based feature extraction
            time_features = TimingFeatureExtractor().extract(obs.raw_data)
            obs.features.update(time_features)
            
            # Prediction: delay matches expected?
            delay_match = abs(avg_time - expected_delay) < expected_delay * 0.3
            obs.predictions["rule_based"] = 0.85 if delay_match else 0.1
            
            observations.append(obs)
            await self.observation_store.save(obs)
        
        return observations
    
    def _rule_based_sqli_check(
        self, 
        features: Dict[str, float],
        baseline: Dict[str, Any]
    ) -> float:
        """Rule-based SQLi confidence calculation."""
        confidence = 0.0
        
        # SQL error patterns are strong indicators
        for key, value in features.items():
            if key.startswith("sqli_") and value > 0:
                confidence = max(confidence, value)
        
        # 500 errors with SQL-like content
        if features.get("status_code_5xx", 0) > 0:
            confidence += 0.2
        
        # High error verbosity suggests vulnerable
        if features.get("error_verbosity", 0) > 0.5:
            confidence += 0.15
        
        return min(confidence, 1.0)
    
    def _create_observation(
        self,
        response: Dict[str, Any],
        scan_job_id: str,
        test_name: str,
        param_name: str
    ) -> Observation:
        """Create observation from HTTP response."""
        return Observation(
            id="",  # Will be set in __post_init__
            observation_type=ObservationType.HTTP_RESPONSE,
            timestamp=datetime.utcnow(),
            target_id=response.get("target_id", ""),
            scan_job_id=scan_job_id,
            raw_data={
                "url": response.get("url"),
                "status_code": response.get("status_code"),
                "headers": response.get("headers"),
                "body": response.get("body", "")[:50000],  # Truncate
                "response_time_ms": response.get("response_time_ms"),
                "test_name": test_name,
                "parameter": param_name
            },
            features={},
            predictions={}
        )