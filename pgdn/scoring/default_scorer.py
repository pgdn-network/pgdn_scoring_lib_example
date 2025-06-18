"""
Default PGDN Scorer - Enhanced scoring with proprietary algorithms
"""

from datetime import datetime
import hashlib
import json


class DefaultScorer:
    """
    PGDN Default Scorer - Enhanced version of the built-in scorer
    with proprietary scoring algorithms and additional security checks.
    """
    
    def __init__(self):
        """Initialize the PGDN scorer with enhanced weights."""
        self.version = "1.0.0"
        self.weights = {
            'docker_exposure': 35,      # Higher penalty for Docker
            'ssh_open': 12,            # Slightly higher SSH penalty
            'tls_issues': 28,          # Higher TLS penalty
            'vulnerabilities': 18,      # Higher vuln penalty
            'open_ports': 2,           # Penalty per open port
            'database_exposure': 30,    # High penalty for DB exposure
        }
    
    def score(self, scan_data):
        """
        Enhanced scoring algorithm with PGDN proprietary logic.
        
        Args:
            scan_data (dict): Generic scan data from DePIN scanner
            
        Returns:
            dict: Enhanced trust result with PGDN-specific fields
        """
        score = 100
        flags = []
        pgdn_metrics = {
            'scorer_version': self.version,
            'risk_factors': {},
            'security_grade': 'A+',
            'compliance_score': 100
        }
        
        open_ports = scan_data.get('open_ports', [])
        
        # Enhanced Docker analysis
        if 2375 in open_ports:
            score -= self.weights['docker_exposure']
            flags.append("CRITICAL: Docker socket exposed (unencrypted)")
            pgdn_metrics['risk_factors']['docker'] = 'CRITICAL'
            pgdn_metrics['security_grade'] = 'F'
        elif 2376 in open_ports:
            score -= 15  # Less penalty for encrypted Docker
            flags.append("WARNING: Docker TLS socket exposed")
            pgdn_metrics['risk_factors']['docker'] = 'MEDIUM'
        
        # Enhanced SSH analysis
        if 22 in open_ports:
            score -= self.weights['ssh_open']
            flags.append("SSH port exposed")
            pgdn_metrics['risk_factors']['ssh'] = 'MEDIUM'
            
        # Check for non-standard SSH ports
        ssh_alt_ports = [p for p in open_ports if p in [2222, 2200, 2022]]
        if ssh_alt_ports:
            score -= 8
            flags.append(f"Alternative SSH ports detected: {ssh_alt_ports}")
            
        # Enhanced TLS analysis
        tls = scan_data.get("tls", {})
        if not tls or tls.get("issuer") in (None, "Self-signed") or not tls.get("expiry"):
            score -= self.weights['tls_issues']
            flags.append("TLS configuration critical issues")
            pgdn_metrics['risk_factors']['tls'] = 'CRITICAL'
            if pgdn_metrics['security_grade'] not in ['F']:
                pgdn_metrics['security_grade'] = 'D'
        else:
            # Grade TLS quality
            issuer = str(tls.get("issuer", "")).lower()
            if "let's encrypt" in issuer:
                pgdn_metrics['tls_grade'] = 'B'
            elif any(ca in issuer for ca in ['digicert', 'comodo', 'globalsign']):
                pgdn_metrics['tls_grade'] = 'A'
            else:
                pgdn_metrics['tls_grade'] = 'C'
                
        # Enhanced vulnerability analysis
        vulns = scan_data.get("vulns", {})
        for vuln_id, vuln_desc in vulns.items():
            severity = self._assess_vuln_severity(vuln_id, vuln_desc)
            penalty = self.weights['vulnerabilities']
            
            if severity == 'CRITICAL':
                penalty *= 1.5
            elif severity == 'HIGH':
                penalty *= 1.2
                
            score -= penalty
            flags.append(f"Vulnerability: {vuln_id} ({severity})")
            pgdn_metrics['risk_factors'][f'vuln_{vuln_id}'] = severity
            
        # Database exposure analysis (PGDN proprietary)
        db_ports = [p for p in open_ports if p in [3306, 5432, 27017, 6379, 1433, 1521]]
        if db_ports:
            score -= self.weights['database_exposure']
            flags.append(f"CRITICAL: Database ports exposed: {db_ports}")
            pgdn_metrics['risk_factors']['database'] = 'CRITICAL'
            pgdn_metrics['security_grade'] = 'F'
            
        # Port exposure penalty
        if len(open_ports) > 5:
            penalty = (len(open_ports) - 5) * self.weights['open_ports']
            score -= penalty
            flags.append(f"Excessive port exposure: {len(open_ports)} ports")
            
        # Compliance scoring
        compliance_issues = len([f for f in flags if 'CRITICAL' in f])
        pgdn_metrics['compliance_score'] = max(0, 100 - (compliance_issues * 25))
        
        # Ensure score bounds
        score = max(0, min(100, score))
        
        # PGDN risk classification
        risk_level = self._calculate_pgdn_risk(score, pgdn_metrics)
        
        summary = f"PGDN Trust Score: {score}/100 (v{self.version}). Grade: {pgdn_metrics['security_grade']}. Risk: {risk_level}"

        return {
            "ip": scan_data.get("ip", "unknown"),
            "score": score,
            "flags": flags,
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat(),
            "hash": hashlib.sha256(json.dumps(scan_data, sort_keys=True).encode()).hexdigest(),
            "docker_exposure": scan_data.get("docker_exposure", {"exposed": False}),
            
            # PGDN-specific fields
            "pgdn_metrics": pgdn_metrics,
            "pgdn_risk_level": risk_level,
            "scorer_id": "pgdn.scoring.default_scorer.DefaultScorer",
            "enhanced_analysis": True
        }
    
    def _assess_vuln_severity(self, vuln_id, vuln_desc):
        """Assess vulnerability severity using PGDN proprietary logic."""
        vuln_text = f"{vuln_id} {vuln_desc}".lower()
        
        # PGDN enhanced severity assessment
        if any(keyword in vuln_text for keyword in ['critical', 'rce', 'remote code execution', 'unauthenticated']):
            return 'CRITICAL'
        elif any(keyword in vuln_text for keyword in ['high', 'privilege escalation', 'buffer overflow']):
            return 'HIGH'
        elif any(keyword in vuln_text for keyword in ['medium', 'dos', 'denial of service', 'xss']):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _calculate_pgdn_risk(self, score, metrics):
        """Calculate PGDN proprietary risk level."""
        if score >= 95 and metrics['security_grade'] in ['A+', 'A']:
            return 'MINIMAL'
        elif score >= 85 and metrics['security_grade'] in ['A+', 'A', 'B']:
            return 'LOW'
        elif score >= 70:
            return 'MODERATE'
        elif score >= 50:
            return 'HIGH'
        else:
            return 'CRITICAL'
