# PGDN Scoring Library

A comprehensive scoring library for DePIN (Decentralized Physical Infrastructure Network) infrastructure security assessment. This library provides advanced scoring algorithms to evaluate the security posture and trustworthiness of network nodes and infrastructure components.

## Overview

The PGDN Scoring Library offers enhanced scoring capabilities beyond basic security scans, incorporating proprietary algorithms and machine learning-based risk assessment to provide accurate trust scores for DePIN infrastructure.

## Features

### 🔒 **Enhanced Security Scoring**
- Comprehensive vulnerability assessment
- Docker security evaluation
- TLS/SSL configuration analysis
- Database exposure detection
- Port exposure analysis

### 🤖 **Machine Learning Enhanced**
- Behavioral anomaly detection
- Port pattern analysis
- Geographic risk assessment
- Security best practices recognition

### 📊 **Detailed Risk Analysis**
- Multi-tier risk classification (MINIMAL, LOW, MODERATE, HIGH, CRITICAL)
- Security grading system (A+ to F)
- Compliance scoring
- PGDN-specific risk metrics

## Installation

### From Source
```bash
git clone <repository-url>
cd pgdn_scoring_lib_example
pip install -e .
```

### Using pip (when published)
```bash
pip install pgdn-scoring
```

## Quick Start

### Basic Usage with Default Scorer

```python
from pgdn.scoring import DefaultScorer

# Initialize the scorer
scorer = DefaultScorer()

# Sample scan data
scan_data = {
    "ip": "192.168.1.100",
    "open_ports": [22, 80, 443],
    "tls": {
        "issuer": "Let's Encrypt",
        "expiry": "2025-12-31"
    },
    "vulns": {
        "CVE-2023-1234": "Medium severity vulnerability"
    }
}

# Get trust score
result = scorer.score(scan_data)
print(f"Trust Score: {result['score']}/100")
print(f"Risk Level: {result['pgdn_risk_level']}")
print(f"Security Grade: {result['pgdn_metrics']['security_grade']}")
```

### Advanced ML-Enhanced Scoring

```python
from pgdn.scoring import AdvancedScorer

# Initialize advanced scorer with ML capabilities
advanced_scorer = AdvancedScorer()

# Get enhanced scoring with ML analysis
result = advanced_scorer.score(scan_data)
print(f"ML-Enhanced Score: {result['score']}/100")
print(f"ML Risk Level: {result['ml_analysis']['ml_risk_level']}")
```

## Scoring Components

### Default Scorer Features

| Component | Weight | Description |
|-----------|---------|-------------|
| Docker Exposure | 35 | Penalizes exposed Docker sockets (2375/2376) |
| TLS Issues | 28 | Evaluates SSL/TLS configuration quality |
| Database Exposure | 30 | Detects exposed database ports |
| Vulnerabilities | 18 | Assesses known security vulnerabilities |
| SSH Exposure | 12 | Penalizes exposed SSH services |
| Port Exposure | 2/port | Penalty for excessive open ports |

### Advanced Scorer Enhancements

- **Port Pattern Analysis**: Detects suspicious port configurations
- **Geographic Risk Assessment**: Evaluates IP-based location risks
- **Behavioral Anomaly Detection**: Identifies unusual system behaviors
- **Security Best Practices**: Rewards good security configurations

## API Reference

### DefaultScorer

#### `score(scan_data: dict) -> dict`

Evaluates scan data and returns comprehensive trust metrics.

**Parameters:**
- `scan_data`: Dictionary containing scan results with keys:
  - `ip`: Target IP address
  - `open_ports`: List of open ports
  - `tls`: TLS configuration details
  - `vulns`: Dictionary of vulnerabilities

**Returns:**
Dictionary with scoring results including:
- `score`: Trust score (0-100)
- `flags`: List of security issues
- `pgdn_metrics`: Enhanced PGDN-specific metrics
- `pgdn_risk_level`: Risk classification
- `security_grade`: Letter grade (A+ to F)

### AdvancedScorer

Extends `DefaultScorer` with additional ML-based analysis.

#### `score(scan_data: dict) -> dict`

Same interface as DefaultScorer but includes ML enhancements in the response.

## Risk Classifications

| Score Range | Grade | Risk Level | Description |
|-------------|-------|------------|-------------|
| 95-100 | A+ | MINIMAL | Excellent security posture |
| 85-94 | A-B | LOW | Good security with minor issues |
| 70-84 | B-C | MODERATE | Acceptable with some concerns |
| 50-69 | C-D | HIGH | Significant security issues |
| 0-49 | D-F | CRITICAL | Severe security problems |

## Security Flags

The library identifies various security issues:

- **CRITICAL: Docker socket exposed (unencrypted)**: Port 2375 open
- **WARNING: Docker TLS socket exposed**: Port 2376 open  
- **SSH port exposed**: Port 22 or alternative SSH ports open
- **TLS configuration critical issues**: Missing or invalid TLS setup
- **CRITICAL: Database ports exposed**: Database services accessible
- **Vulnerability: [CVE-ID] ([SEVERITY])**: Known security vulnerabilities
- **Excessive port exposure**: Too many open ports detected

## Configuration

### Custom Weights

You can customize scoring weights by extending the DefaultScorer:

```python
class CustomScorer(DefaultScorer):
    def __init__(self):
        super().__init__()
        self.weights.update({
            'docker_exposure': 40,  # Increase Docker penalty
            'ssh_open': 15,         # Increase SSH penalty
        })
```

## Examples

### Example 1: Secure Infrastructure

```python
secure_scan = {
    "ip": "10.0.0.5",
    "open_ports": [443],
    "tls": {
        "issuer": "DigiCert",
        "expiry": "2026-01-15"
    },
    "vulns": {}
}

result = scorer.score(secure_scan)
# Expected: High score, A+ grade, MINIMAL risk
```

### Example 2: Vulnerable Infrastructure

```python
vulnerable_scan = {
    "ip": "192.168.1.50",
    "open_ports": [22, 80, 2375, 3306, 5432],
    "tls": {"issuer": "Self-signed"},
    "vulns": {
        "CVE-2023-0001": "Critical RCE vulnerability",
        "CVE-2023-0002": "High privilege escalation"
    }
}

result = scorer.score(vulnerable_scan)
# Expected: Low score, F grade, CRITICAL risk
```

## Development

### Setting up Development Environment

```bash
# Clone the repository
git clone <repository-url>
cd pgdn_scoring_lib_example

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .

# Install development dependencies (when available)
pip install pytest pytest-cov black flake8
```

### Running Tests

```bash
# Run tests (when test suite is available)
pytest tests/

# Run with coverage
pytest --cov=pgdn tests/
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions, issues, or contributions:

- **Author**: Simon Morley
- **Email**: sm@pgdn.network
- **Project**: PGDN DePIN Infrastructure Scanner

## Changelog

### Version 1.0.0 (Current)
- Initial release with DefaultScorer
- Advanced ML-enhanced scorer
- Comprehensive security analysis
- Risk classification system
- Security grading

---

**Note**: This library is designed for DePIN infrastructure security assessment. Ensure proper authorization before scanning any infrastructure you do not own or have explicit permission to test.
