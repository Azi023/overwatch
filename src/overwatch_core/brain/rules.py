# src/overwatch_core/brain/rules.py

from typing import Dict, List, Any

class HeuristicRules:
    """
    Expert knowledge base encoded as rules.
    """
    
    @staticmethod
    def calculate_risk_score(finding: Dict[str, Any]) -> int:
        """
        Calculate a risk score (0-100) based on severity and type.
        """
        severity = finding.get("severity", "info").lower()
        title = finding.get("title", "").lower()
        
        base_score = 0
        if severity == "critical":
            base_score = 90
        elif severity == "high":
            base_score = 70
        elif severity == "medium":
            base_score = 40
        elif severity == "low":
            base_score = 10
            
        # Context Modifiers
        if "sql injection" in title or "sqli" in title:
            base_score += 10 # Critical vector
        if "rce" in title or "remote code execution" in title:
            base_score = 100 # Always max
        if "xss" in title and severity == "high":
            base_score += 5
            
        return min(100, base_score)

    @staticmethod
    def suggest_next_steps(finding: Dict[str, Any]) -> List[str]:
        """
        Suggest actionable next steps based on the finding.
        """
        title = finding.get("title", "").lower()
        steps = []
        
        # SQL Injection
        if "sql injection" in title or "sqli" in title:
            steps.append("Run sqlmap to confirm exploitability: `sqlmap -u <url> --batch`")
            steps.append("Check for database errors in response.")
            
        # XSS
        elif "xss" in title:
            steps.append("Verify with a manual browser test using a safe payload (alert(1)).")
            steps.append("Check if HttpOnly flag is missing on cookies.")
            
        # WordPress
        elif "wordpress" in title:
            steps.append("Run wpscan for user enumeration: `wpscan --url <url> --enumerate u`")
            steps.append("Check for vulnerable plugins.")
            
        # Open Ports
        elif "open port" in title:
            port = finding.get("details", {}).get("port")
            if port == 21:
                steps.append("Check for Anonymous FTP login.")
            elif port == 445:
                steps.append("Check for SMB vulnerabilities (EternalBlue, etc).")
        
        if not steps:
            steps.append("Manually verify the finding with curl.")
            
        return steps
