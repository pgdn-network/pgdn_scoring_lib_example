"""
Advanced PGDN Scorer - Machine Learning Enhanced Scoring
"""

from .default_scorer import DefaultScorer
import hashlib
import json
from datetime import datetime


class AdvancedScorer(DefaultScorer):
    """
    Advanced PGDN Scorer with ML-enhanced risk assessment.
    Extends the DefaultScorer with additional intelligence.
    """
    
    def __init__(self):
        """Initialize advanced scorer with ML models (simulated)."""
        super().__init__()
        self.version = "2.0.0-advanced"
        
        # Simulated ML model weights (in real implementation, load trained models)
        self.ml_weights = {
            'port_pattern_risk': 0.3,
            'geographic_risk': 0.2,
            'temporal_risk': 0.1,
            'behavioral_anomaly': 0.4
        }
    
    def score(self, scan_data):
        """
        Advanced ML-enhanced scoring with behavioral analysis.
        
        Args:
            scan_data (dict): Generic scan data
            
        Returns:
            dict: Advanced trust result with ML predictions
        """
        # Get base score from parent class
        base_result = super().score(scan_data)
        
        # Apply ML enhancements
        ml_adjustments = self._apply_ml_analysis(scan_data)
        
        # Adjust score based on ML predictions
        adjusted_score = base_result['score'] + ml_adjustments['score_adjustment']
        adjusted_score = max(0, min(100, adjusted_score))
        
        # Enhanced flags
        enhanced_flags = base_result['flags'] + ml_adjustments['ml_flags']
        
        # Update summary
        enhanced_summary = f"Advanced ML Score: {adjusted_score}/100 (v{self.version}). " \
                          f"ML Risk: {ml_adjustments['ml_risk_level']}"
        
        # Merge results
        advanced_result = {
            **base_result,
            "score": adjusted_score,
            "flags": enhanced_flags,
            "summary": enhanced_summary,
            "ml_analysis": ml_adjustments,
            "scorer_id": "pgdn.scoring.advanced_scorer.AdvancedScorer",
            "ml_enhanced": True
        }
        
        return advanced_result
    
    def _apply_ml_analysis(self, scan_data):
        """
        Apply ML-based risk analysis (simulated).
        In production, this would use trained ML models.
        """
        open_ports = scan_data.get('open_ports', [])
        ip = scan_data.get('ip', '')
        
        ml_flags = []
        score_adjustment = 0
        
        # Simulate port pattern analysis
        if self._is_suspicious_port_pattern(open_ports):
            score_adjustment -= 15
            ml_flags.append("ML: Suspicious port pattern detected")
            
        # Simulate geographic risk assessment
        geo_risk = self._assess_geographic_risk(ip)
        if geo_risk > 0.7:
            score_adjustment -= 10
            ml_flags.append("ML: High geographic risk detected")
            
        # Simulate behavioral anomaly detection
        if self._detect_behavioral_anomaly(scan_data):
            score_adjustment -= 20
            ml_flags.append("ML: Behavioral anomaly detected")
            
        # Simulate positive adjustments for good patterns
        if self._detect_security_best_practices(scan_data):
            score_adjustment += 5
            ml_flags.append("ML: Security best practices detected")
            
        # Calculate ML risk level
        ml_risk_level = self._calculate_ml_risk_level(score_adjustment)
        
        return {
            'score_adjustment': score_adjustment,
            'ml_flags': ml_flags,
            'ml_risk_level': ml_risk_level,
            'ml_confidence': 0.85,  # Simulated confidence score
            'analysis_methods': ['port_pattern', 'geo_risk', 'behavioral', 'best_practices']
        }
    
    def _is_suspicious_port_pattern(self, ports):
        """Simulate ML-based suspicious port pattern detection."""
        # Example: too many sequential ports might indicate scanning
        if len(ports) > 10:
            return True
        
        # Check for common attack patterns
        attack_patterns = [
            [80, 443, 8080, 8443],  # Web service enumeration
            [21, 22, 23, 25],       # Service enumeration
            [3306, 5432, 27017]     # Database enumeration
        ]
        
        for pattern in attack_patterns:
            if all(port in ports for port in pattern):
                return True
                
        return False
    
    def _assess_geographic_risk(self, ip):
        """Simulate geographic risk assessment."""
        # In production, this would use IP geolocation and threat intelligence
        # For demo, use simple heuristics based on IP ranges
        
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return 0.1  # Private IP, lower risk
        elif ip.startswith('127.'):
            return 0.0  # Localhost, no risk
        else:
            # Simulate risk based on IP hash (deterministic but pseudo-random)
            ip_hash = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
            return (ip_hash % 100) / 100.0
    
    def _detect_behavioral_anomaly(self, scan_data):
        """Simulate behavioral anomaly detection."""
        # Example: unusual combination of services
        open_ports = scan_data.get('open_ports', [])
        
        # SSH + Database + Web might indicate a compromised system
        has_ssh = 22 in open_ports
        has_db = any(port in open_ports for port in [3306, 5432, 27017])
        has_web = any(port in open_ports for port in [80, 443])
        has_docker = 2375 in open_ports
        
        if has_ssh and has_db and has_web and has_docker:
            return True
            
        return False
    
    def _detect_security_best_practices(self, scan_data):
        """Detect security best practices."""
        open_ports = scan_data.get('open_ports', [])
        tls = scan_data.get('tls', {})
        
        # Good practices:
        # - HTTPS but not HTTP
        # - Good TLS configuration
        # - Minimal port exposure
        
        has_https = 443 in open_ports
        has_http = 80 in open_ports
        good_tls = tls and tls.get('issuer') and 'Self-signed' not in str(tls.get('issuer', ''))
        
        if has_https and not has_http and good_tls and len(open_ports) <= 3:
            return True
            
        return False
    
    def _calculate_ml_risk_level(self, score_adjustment):
        """Calculate ML-specific risk level."""
        if score_adjustment >= 0:
            return 'LOW'
        elif score_adjustment >= -10:
            return 'MODERATE'
        elif score_adjustment >= -20:
            return 'HIGH'
        else:
            return 'CRITICAL'
