# src/overwatch_core/learning/training_pipeline.py
import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score

class TrainingPipeline:
    """
    Pipeline for training vulnerability detection models.
    
    Process:
    1. Export observations with ground truth to JSONL
    2. Split into train/val/test sets
    3. Train specialized models per vulnerability type
    4. Evaluate and deploy if improved
    """
    
    def __init__(self, observation_store, model_store):
        self.observation_store = observation_store
        self.model_store = model_store
    
    async def export_training_data(
        self, 
        output_path: Path,
        min_observations: int = 1000
    ) -> Dict[str, int]:
        """
        Export observations with ground truth to JSONL format.
        """
        stats = {"total": 0, "by_type": {}}
        
        with open(output_path, "w") as f:
            async for obs in self.observation_store.iter_with_ground_truth():
                example = obs.to_training_example()
                if example:
                    f.write(json.dumps(example) + "\n")
                    stats["total"] += 1
                    
                    vuln_type = example.get("ground_truth", {}).get("vulnerability_type", "unknown")
                    stats["by_type"][vuln_type] = stats["by_type"].get(vuln_type, 0) + 1
        
        return stats
    
    def train_model(
        self,
        training_data_path: Path,
        vulnerability_type: str,
        model_type: str = "random_forest"
    ) -> Dict[str, Any]:
        """
        Train a model for detecting specific vulnerability type.
        """
        # Load and filter data
        examples = []
        with open(training_data_path) as f:
            for line in f:
                ex = json.loads(line)
                if ex["observation_type"] == "http_response":
                    examples.append(ex)
        
        if len(examples) < 100:
            raise ValueError(f"Not enough examples: {len(examples)}")
        
        # Prepare features and labels
        X, y = self._prepare_data(examples, vulnerability_type)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=42
        )
        
        # Train model
        if model_type == "random_forest":
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                class_weight="balanced",
                random_state=42
            )
        else:
            model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                random_state=42
            )
        
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        metrics = {
            "precision": precision_score(y_test, y_pred),
            "recall": recall_score(y_test, y_pred),
            "f1": f1_score(y_test, y_pred),
            "samples": len(examples),
            "positive_samples": sum(y),
            "trained_at": datetime.utcnow().isoformat()
        }
        
        return {
            "model": model,
            "metrics": metrics,
            "feature_names": self._get_feature_names()
        }
    
    def _prepare_data(
        self, 
        examples: List[Dict],
        vulnerability_type: str
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Convert examples to feature matrix and labels."""
        feature_names = self._get_feature_names()
        
        X = []
        y = []
        
        for ex in examples:
            # Extract features
            features = ex.get("features", {})
            row = [features.get(name, 0.0) for name in feature_names]
            X.append(row)
            
            # Extract label
            gt = ex.get("ground_truth", {})
            is_vulnerable = (
                gt.get("vulnerability_type") == vulnerability_type and
                gt.get("is_true_positive", False)
            )
            y.append(1 if is_vulnerable else 0)
        
        return np.array(X), np.array(y)
    
    def _get_feature_names(self) -> List[str]:
        """Get ordered list of feature names."""
        return [
            # SQL injection features
            "sqli_mysql_syntax_error",
            "sqli_oracle_error", 
            "sqli_sqlstate_error",
            "sqli_postgres_error",
            "sqli_mssql_error",
            "sqli_quote_error",
            "sqli_generic_sql_error",
            
            # XSS features
            "xss_script_tag_reflection",
            "xss_javascript_protocol",
            "xss_event_handler",
            
            # Response features
            "status_code_5xx",
            "status_code_4xx",
            "response_length",
            "response_time_slow",
            "response_time_very_slow",
            "response_time_normalized",
            
            # Security posture
            "security_headers_count",
            "error_verbosity",
            
            # Timing features
            "time_diff_ms",
            "delay_accuracy",
            "timing_consistency"
        ]