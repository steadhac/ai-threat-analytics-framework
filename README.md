# 🛡️ AI Threat Analytics Framework

> A proof-of-concept framework demonstrating AI-powered security threat analysis and detection techniques.

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB.svg)](https://www.python.org/)
[![pytest](https://img.shields.io/badge/pytest-Latest-0A9EDC.svg)](https://pytest.org/)
[![pytest-html](https://img.shields.io/badge/pytest--html-Latest-0A9EDC.svg)](https://pytest-html.readthedocs.io/)
[![pytest-sugar](https://img.shields.io/badge/pytest--sugar-Latest-0A9EDC.svg)](https://github.com/Frozenball/pytest-sugar)
[![pytest-emoji](https://img.shields.io/badge/pytest--emoji-Latest-0A9EDC.svg)](https://github.com/LewisGaul/pytest-emoji)
[![PyYAML](https://img.shields.io/badge/PyYAML-YAML-CB171E.svg)](https://pyyaml.org/)
[![Statistics](https://img.shields.io/badge/Statistics-stdlib-3776AB.svg)](https://docs.python.org/3/library/statistics.html)
[![Regex](https://img.shields.io/badge/Regex-re-3776AB.svg)](https://docs.python.org/3/library/re.html)
[![Requests](https://img.shields.io/badge/Requests-HTTP-2E8555.svg)](https://requests.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🌟 Overview

**A comprehensive, security-hardened framework for AI-driven threat detection and analysis with production-grade testing, OWASP mitigations, and intelligent data processing.**

This framework demonstrates practical implementations of AI security concepts including threat classification, anomaly detection, LLM guardrails, smart autofill suggestions, and automated summarization. Built with fail-fast policies, comprehensive testing, detailed gap documentation, and data pipeline validation.

**Core Intelligence Systems:**
- 🤖 **Autofill Service** - Context-aware email/phone/address suggestions with confidence scoring and format validation
- 🎯 **Threat Classification** - Multi-class detection (phishing, malware, spam) with confidence thresholds
- 🛡️ **LLM Guardrails** - Prompt injection detection, jailbreak prevention, PII filtering
- 📝 **Summarization Engine** - Lossless threat report compression preserving critical context
- 📊 **Anomaly Detection** - Z-score statistical analysis with production noise tolerance (3% FP rate)

**Data Pipeline & Validation:**
- ✅ **Smart Data Validation** - Multi-stage filtering (null removal, status validation, quality gates)
- ✅ **Empty Dataset Rejection** - Fail-fast policy prevents ML model crashes from zero-record outputs
- ✅ **Format Validation** - Email, phone, address, JSON format checks before output
- ✅ **Synthetic vs Production Testing** - Perfect data (0% FP) vs real data with ±3 noise (3% FP tolerance)
- ✅ **End-to-End ML Integration** - Complete threat response automation pipeline

**Gap Documentation & Production Readiness:**
- 📋 **Synthetic vs Real Data Gap** - Identified: Threshold calibration (2.0 → 2.5) for noise tolerance
- 📋 **7-Step Improvement Roadmap** - Monitor production, measure FP rate, retrain thresholds, implement adaptive algorithms
- ✅ **30-Day Simulated Data** - Production-like dataset with ±3 Gaussian noise and legitimate spikes
- ✅ **Threshold Tuning** - THRESHOLD_SYNTHETIC=2.0 (perfect data) vs THRESHOLD_PRODUCTION=2.5 (real noise)

**Engineering Excellence:**
- ✅ **50+ Passing Tests** - AI tests (26 cases) + Pipeline tests (24+ cases) covering edge cases & boundary conditions
- ✅ **OWASP T1-T12 Coverage** - Complete mitigation mapping (input validation → threat prevention)
- ✅ **Fail-Fast Policies** - Empty datasets rejected, low-confidence suggestions blocked, null values caught
- ✅ **Gap Documentation** - Synthetic/production differences documented with actionable improvement steps
- ✅ **Production-Ready** - Threshold calibration, audit logging, graceful degradation, alert grouping
- ✅ **Zero Silent Failures** - All edge cases explicitly handled or documented with remediation paths

---
## 🏗️ Architecture

```mermaid
graph TB
    subgraph Input["Input Layer"]
        API["API/User Input"]
        Config["Config<br/>settings.yaml"]
    end

    subgraph Core["Core Modules"]
        AC["api_client.py<br/>HTTP Client"]
        Helper["helpers.py<br/>Utilities"]
        Logger["logger.py<br/>Logging"]
        Metrics["metrics.py<br/>Performance"]
        SecCheck["security_checks.py<br/>Validation"]
        
        AF["autofill_service.py<br/>Email Suggestions"]
        TC["threat_classifier.py<br/>Threat Detection"]
        TLA["threat_level_assessment.py<br/>Severity Classification"]
        GR["guardrails.py<br/>LLM Safety"]
        Sum["summarizer.py<br/>Text Summary"]
        AD["anomaly_utils.py<br/>Z-Score Analysis"]
    end

    subgraph ThreatResponse["Multi-Level Threat Response"]
        Block["🚫 BLOCKING<br/>CRITICAL (95%+)<br/>Preventive Action"]
        Alert["⚠️ ALERTING<br/>HIGH/MEDIUM<br/>Escalate Review"]
        Log["📋 LOGGING<br/>LOW Threats<br/>Monitoring"]
    end

    subgraph Testing["Test Layer"]
        subgraph AITests["AI Tests (26 cases)"]
            TAUnit["Unit Tests<br/>Autofill, Classification,<br/>Summarization"]
            TASecurity["Security Tests<br/>Injection, Guardrails,<br/>Core Patterns"]
            TAEdge["Edge Case Tests<br/>Whitespace, Case,<br/>Special Characters,<br/>Encoding (18 cases)"]
        end
        
        subgraph PipelineTests["Pipeline Tests (24+ cases)"]
            TPUnit["Unit Tests<br/>Anomaly Detection,<br/>Data Validation"]
            TPEdge["Edge Case Tests<br/>Threshold Sensitivity,<br/>Scale Independence"]
            TPInteg["Integration Tests<br/>ML Pipeline Flow<br/>with Threat Response"]
        end
        
        subgraph VulnMitigation["Vulnerability Coverage"]
            T1T4["T1-T4: Input Validation<br/>Resource Protection"]
            T5T8["T5-T8: Data Integrity<br/>Audit Trail"]
            T9T12["T9-T12: Execution Control<br/>Threat Prevention"]
        end
    end

    subgraph Output["Output Layer"]
        Results["Test Results"]
        Reports["HTML Reports<br/>Allure Reports<br/>Vulnerability Maps"]
        Logs["Logs & Metrics<br/>Threat Actions"]
    end

    API --> AC
    Config --> Core
    Logger --> Helper
    Metrics --> Helper
    SecCheck --> Helper
    
    AC --> AF
    AC --> TC
    TC --> TLA
    AC --> GR
    AC --> Sum
    AC --> AD
    
    TLA --> Block
    TLA --> Alert
    TLA --> Log
    
    AF --> TAUnit
    TC --> TAUnit
    TC --> TASecurity
    GR --> TASecurity
    GR --> TAEdge
    Sum --> TAUnit
    AD --> TPUnit
    AD --> TPEdge
    
    TAUnit --> Results
    TASecurity --> Results
    TAEdge --> Results
    TPUnit --> Results
    TPEdge --> Results
    TPInteg --> Results
    
    Block --> TPInteg
    Alert --> TPInteg
    Log --> TPInteg
    
    Results --> Reports
    Reports --> VulnMitigation
    Logger -.-> Logs
    ThreatResponse -.-> Logs
    style Input fill:#e1f5e1
    style Core fill:#e3f2fd
    style Testing fill:#fff3e0
    style AITests fill:#ffe0b2
    style PipelineTests fill:#ffe0b2
    style Output fill:#f3e5f5
```
## 🛡️ Threat Response Strategy
``` mermaid
graph LR
    Threat["Threat Detected"]
    
    Threat --> TLA["Threat Level<br/>Assessment"]
    
    TLA --> CRIT["CRITICAL?<br/>Confidence >90%"]
    TLA --> HIGH["HIGH/MEDIUM?<br/>Confidence 50-90%"]
    TLA --> LOW["LOW?<br/>Confidence <50%"]
    
    CRIT -->|YES| BLOCK["🚫 BLOCK<br/>Immediate Prevention<br/>- Block action<br/>- Escalate<br/>- Log alert"]
    
    HIGH -->|YES| ALERT["⚠️ ALERT<br/>Escalate for Review<br/>- Generate alert ID<br/>- Escalate to team<br/>- Create incident"]
    
    LOW -->|YES| LOGONLY["📋 LOG<br/>Monitor & Analyze<br/>- Write to audit log<br/>- Tag for batch analysis<br/>- Support ML retraining"]
    
    TLA -->|SAFE| NONE["✅ NO ACTION<br/>- Continue processing<br/>- Log normally"]
    
    BLOCK --> VulnMit1["T3: Jailbreak Prevention<br/>T10: Malware Prevention<br/>T11: Code Injection Prevention<br/>T12: Advanced Threats"]
    ALERT --> VulnMit2["T3: Jailbreak Detection<br/>T7: Accountability<br/>T8: Audit Trail"]
    LOGONLY --> VulnMit3["T1-T4: Input Protection<br/>T5: Error Prevention<br/>T6: Execution Isolation"]
    NONE --> VulnMit4["T1-T12: All Mitigations<br/>No false positives"]
    
    style Threat fill:#FFD700,stroke:#FF8C00,stroke-width:3px,color:#000,font-weight:bold
    style TLA fill:#87CEEB,stroke:#0047AB,stroke-width:3px,color:#000,font-weight:bold
    
    style CRIT fill:#FF6347,stroke:#DC143C,stroke-width:2px,color:#fff,font-weight:bold
    style HIGH fill:#FFA500,stroke:#FF8C00,stroke-width:2px,color:#000,font-weight:bold
    style LOW fill:#4169E1,stroke:#00008B,stroke-width:2px,color:#fff,font-weight:bold
    
    style BLOCK fill:#FF4444,stroke:#990000,stroke-width:3px,color:#fff,font-weight:bold
    style ALERT fill:#FFB347,stroke:#FF8C00,stroke-width:3px,color:#000,font-weight:bold
    style LOGONLY fill:#4169E1,stroke:#00008B,stroke-width:3px,color:#fff,font-weight:bold
    style NONE fill:#00DD00,stroke:#008800,stroke-width:3px,color:#000,font-weight:bold
    
    style VulnMit1 fill:#FF4444,stroke:#990000,stroke-width:2px,color:#fff
    style VulnMit2 fill:#FFB347,stroke:#FF8C00,stroke-width:2px,color:#000
    style VulnMit3 fill:#4169E1,stroke:#00008B,stroke-width:2px,color:#fff
    style VulnMit4 fill:#00DD00,stroke:#008800,stroke-width:2px,color:#000
```
## 🔒 Vulnerability Coverage Matrix

``` mermaid
graph TB
    subgraph T1T4["Input & Resource Protection"]
        T1["T1: Memory Poisoning<br/>word_count > 0"]
        T4["T4: Resource Overload<br/>Input validation"]
        T11["T11: Code Injection<br/>Execution control"]
    end
    
    subgraph T5T8["Data Integrity & Audit"]
        T2["T2: Tool Misuse<br/>Feature consistency"]
        T5["T5: Cascading Errors<br/>Feature isolation"]
        T6["T6: Intent Breaking<br/>Prediction isolation"]
        T8["T8: Repudiation<br/>Audit logging"]
    end
    
    subgraph T9T12["Execution & Threat Prevention"]
        T3["T3: Jailbreak<br/>Threat assessment"]
        T7["T7: Accountability<br/>Action logging"]
        T9["T9: Identity Spoofing<br/>Execution isolation"]
        T10["T10: Malware<br/>BLOCK action"]
        T12["T12: Advanced Attacks<br/>Multi-level response"]
    end
    
    style T1T4 fill:#00BFFF,stroke:#0066CC,stroke-width:3px,color:#000
    style T5T8 fill:#FF69B4,stroke:#FF1493,stroke-width:3px,color:#fff
    style T9T12 fill:#FF6347,stroke:#DC143C,stroke-width:3px,color:#fff
    
    style T1 fill:#00BFFF,stroke:#0066CC,stroke-width:2px,color:#000,font-weight:bold
    style T4 fill:#00BFFF,stroke:#0066CC,stroke-width:2px,color:#000,font-weight:bold
    style T11 fill:#00BFFF,stroke:#0066CC,stroke-width:2px,color:#000,font-weight:bold
    
    style T2 fill:#FF69B4,stroke:#FF1493,stroke-width:2px,color:#fff,font-weight:bold
    style T5 fill:#FF69B4,stroke:#FF1493,stroke-width:2px,color:#fff,font-weight:bold
    style T6 fill:#FF69B4,stroke:#FF1493,stroke-width:2px,color:#fff,font-weight:bold
    style T8 fill:#FF69B4,stroke:#FF1493,stroke-width:2px,color:#fff,font-weight:bold
    
    style T3 fill:#FF6347,stroke:#DC143C,stroke-width:2px,color:#fff,font-weight:bold
    style T7 fill:#FF6347,stroke:#DC143C,stroke-width:2px,color:#fff,font-weight:bold
    style T9 fill:#FF6347,stroke:#DC143C,stroke-width:2px,color:#fff,font-weight:bold
    style T10 fill:#FF6347,stroke:#DC143C,stroke-width:2px,color:#fff,font-weight:bold
    style T12 fill:#FF6347,stroke:#DC143C,stroke-width:2px,color:#fff,font-weight:bold
```
## 🚀 Features

| Feature | Description | Technology |
|---------|-------------|------------|
| 🤖 **Autofill Service** | Intelligent email suggestion generation | Pattern matching |
| 🎯 **Threat Classifier** | Phishing, malware, spam detection | Keyword analysis |
| 🛡️ **LLM Guardrails** | Prompt injection & PII filtering | Regex patterns |
| 📝 **Summarizer** | Automated report summarization | Extractive NLP |
| 📊 **Anomaly Detection** | Statistical outlier identification | Z-score analysis |
| 🔄 **Data Validation** | Pipeline quality checks | Data filtering |

---

## ⚡ Quick Start


### 1. Clone the repository
```bash
git clone https://github.com/steadhac/ai-threat-analytics-framework.git
cd ai-threat-analytics-framework
```
### 2. Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run Tests

### Primary Method: `python run_tests.py`
Use this for normal test execution. It's pre-configured via [setup.cfg](setup.cfg) with all project settings, automatically generates reports, and captures logs.

```bash
# Run all tests
python run_tests.py

# Clear cache, run all tests, generate and serve Allure report
pytest --cache-clear && pytest tests_ai/ tests_pipelines/ -v --alluredir=allure-results && allure serve allure-results

# Run specific test suite
python run_tests.py --suite ai
python run_tests.py --suite pipelines

# Run with options
python run_tests.py --coverage      # Generate coverage report
python run_tests.py -vv             # Verbose output
python run_tests.py --parallel 4    # Run in parallel (faster)
```
### Configuration: See setup.cfg for test discovery, logging, and markers configuration.

### Alternative Method: pytest directly
Use pytest when you need to run specific test files or have custom pytest requirements.
```bash
# Run specific test files
pytest tests_ai/test_classification.py -v
pytest tests_ai/test_llm_guardrails.py -v
pytest tests_pipelines/test_anomaly_detection.py -v
```
### 5. View Reports
```bash
# HTML Report (automatically generated)
open reports/test_results.html  # macOS
xdg-open reports/test_results.html  # Linux
start reports/test_results.html  # Windows


# Test Logs
cat reports/test_logs.txt

# Coverage Report
python run_tests.py --coverage
open htmlcov/index.html  # macOS
```
### Allure Reports (Alternative)

Generate and serve interactive Allure test reports for detailed test analytics and visualization.

#### Prerequisites
```bash
pip install allure-pytest  # Already in [requirements.txt](http://_vscodecontentref_/0)
```
**Generate Allure Results**
``` bash
# Run tests with Allure results generation
pytest --alluredir=reports/allure-results

```
**View Allure Report**
``` bash
# Start Allure server (opens in browser automatically)
allure serve reports/allure-results
```
This command will:

-Start a local web server on http://localhost:8080
-Open the Allure dashboard in your default browser
-Display detailed test metrics, timeline, error traces, and trends
-Press Ctrl+C to stop the server
-Generate Static Allure HTML (No Server)

**Generate Static Allure HTML (No Server)**
``` bash
# Generate standalone HTML report
allure generate reports/allure-results -o reports/allure-report

# View the report
open reports/allure-report/index.html  # macOS
xdg-open reports/allure-report/index.html  # Linux
start reports\allure-report\index.html  # Windows
```
### Project Structure

The project follows this directory structure:

ai-threat-analytics-framework/
``` tree
│
├── 📂 core/ # Core implementation modules
│ ├── init.py
│ ├── api_client.py # HTTP client for API calls
│ ├── helpers.py # Utility functions
│ ├── logger.py # Logging configuration
│ ├── metrics.py # Performance metrics
│ ├── security_checks.py # Security validation
│ ├── autofill_service.py # ⭐ AI email suggestions
│ ├── threat_classifier.py # ⭐ Threat classification engine
│ ├── guardrails.py # ⭐ LLM security guardrails
│ ├── summarizer.py # ⭐ Text summarization
│ ├── anomaly_utils.py # ⭐ Anomaly detection (z-score)
│ └── anomaly_improvement.py # Anomaly detection enhancements
│
├── 📂 tests_ai/ # AI/ML functionality tests
│ ├── init.py
│ ├── test_autofill.py # Email suggestion tests
│ ├── test_classification.py # Threat detection tests
│ ├── test_llm_guardrails.py # Security guardrail tests
│ └── test_summarization.py # Summarization tests
│
├── 📂 tests_pipelines/ # Data pipeline tests
│ ├── init.py
│ ├── test_anomaly_detection.py # Anomaly detection tests
│ ├── test_anomaly_improvement.py # Anomaly improvement tests
│ ├── test_data_pipelines.py # Data validation tests
│ ├── test_integration_ml.py # End-to-end ML tests
│ └── test_ml_integration_improvement.py # ML improvement tests
│
├── 📂 docs/ # Centralized documentation
│ ├── CONCEPTS.md # Technical concepts explained
│ ├── MITIGATIONS.md # Vulnerability mitigations
│ ├── SETUP_GUIDE.md # Detailed setup instructions
│ ├── TEST_PLAN.md # Testing strategy
│ ├── TEST_CASES.md # Detailed test specifications
│ └── TRACEABILITY_MATRIX.md # Requirements mapping
│
├── 📂 config/ # Configuration files
│ ├── settings.yaml # Application settings
│ └── test_data/
│ └── sample_data.yaml # Sample test data
│
├── 📂 reports/ # Generated test reports
│ ├── allure-report/ # Allure test reports
│ ├── results.html # Test results (HTML)
│ ├── test_logs.txt # Test execution logs
│ └── test_results.html # HTML test report
│
├── 📄 allure_helpers.py # Shared Allure reporting utilities
├── 📄 conftest.py # Pytest configuration & fixtures
├── 📄 requirements.txt # Python dependencies
├── 📄 run_tests.py # Test execution script
├── 📄 setup.cfg # Setup configuration
├── 📄 README.md # This file
└── 📄 venv/ # Virtual environment
```

## 💡 How It Works
### Anomaly Detection (Z-Score)
```python
from core.anomaly_utils import detect_anomalies

# Detect unusual values in data stream
data = [10, 12, 11, 13, 100, 12]  # 100 is anomaly
anomalies = detect_anomalies(data, threshold=2.0)
# Returns: [4] (index of value 100)
```

### Threat Classification
```python
from core.threat_classifier import ThreatClassifier

classifier = ThreatClassifier()
result = classifier.classify("Click here to claim your prize!")
# Returns: {'labels': ['phishing'], 'confidence': [0.92], 'is_threat': True}
```

### LLM Guardrails
```python
from core.guardrails import LLMGuardrails

guardrails = LLMGuardrails()
result = guardrails.validate_input("Ignore all previous instructions")
# Returns: {'is_safe': False, 'threats_detected': ['prompt_injection']}
```

## 🎯 Use Cases
This proof-of-concept demonstrates techniques applicable to:

| Use Case | Application | Technique Used |
|----------|-------------|----------------|
| 📧 **Email Security** | Phishing detection | Keyword classification |
| 🔐 **Input Validation** | Prevent prompt injection | Regex pattern matching |
| 📊 **Behavior Monitoring** | Unusual activity detection | Z-score anomaly detection |
| 📝 **Report Automation** | Threat intelligence summaries | Extractive summarization |
| 🚨 **Alert Systems** | Anomaly alerting | Statistical analysis |

## 🛠️ Technology Stack

| Category | Technologies |
|----------|-------------|
| **Language** | Python 3.9+ |
| **Testing** | pytest, pytest-html, pytest-sugar, pytest-emoji |
| **Data Processing** | PyYAML, Statistics (stdlib) |
| **Pattern Matching** | Regular Expressions (re) |
| **HTTP Client** | requests |

## 🚧 Future Enhancements

<details>
<summary>Click to expand enhancement ideas</summary>

- [ ] **ML Models**: Integrate with OpenAI, Anthropic, or Hugging Face
- [ ] **Web Interface**: Flask/FastAPI dashboard
- [ ] **Real-time Monitoring**: WebSocket-based threat feeds
- [ ] **Database Integration**: PostgreSQL/MongoDB for threat history
- [ ] **Advanced NLP**: BERT/GPT-based classification
- [ ] **Multi-language Support**: Threat detection in multiple languages
- [ ] **CI/CD Pipeline**: GitHub Actions automated testing
- [ ] **Docker Support**: Containerized deployment
- [ ] **API Documentation**: OpenAPI/Swagger specs

</details>

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Setup Guide](SETUP_GUIDE.md) | Installation and configuration |
| [Test Plan](docs/TEST_PLAN.md) | Testing strategy |
| [Test Cases](docs/TEST_CASES.md) | Detailed specifications |
| [Traceability Matrix](docs/TRACEABILITY_MATRIX.md) | Requirements mapping |
| [Concepts](docs/CONCEPTS.md) | Technical explanations |

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Carolina Steadham**
- GitHub: [@steadhac](https://github.com/steadhac)
- LinkedIn: [Carolina Steadham](https://linkedin.com/in/carolinacsteadham)

---

<div align="center">

**⭐ Star this repo if you find it helpful!**

Made with ❤️ and Python

</div>