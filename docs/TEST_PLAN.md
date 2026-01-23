# Test Plan - AI Threat Analytics Framework

## 1. Introduction

### 1.1 Purpose
This test plan defines the testing strategy, scope, and approach for the AI Threat Analytics Framework, including comprehensive parametrized testing for nondeterministic AI/ML systems.

### 1.2 Scope
- AI/ML threat classification tests (phishing, malware, spam detection)
- LLM security guardrails and prompt injection blocking
- Data pipeline validation and cleaning
- Anomaly detection with statistical analysis (Z-score)
- End-to-end ML pipeline integration
- Autofill and text summarization functionality
- LLM guardrails edge case testing (unusual inputs, special characters, encoding variations)

### 1.3 Test Objectives
- Verify threat classification accuracy across multiple threat types
- Validate LLM guardrails detect and block security attacks
- Ensure data pipelines handle clean and corrupted data appropriately
- Confirm anomaly detection works across different data scales and thresholds
- Validate end-to-end ML pipeline integration without data loss
- Test nondeterministic systems with parametrized test cases
- Ensure no false positives or silent failures

## 2. Test Strategy

### 2.1 Test Levels
- **Unit Tests**: Individual component testing (threat classifier, guardrails, anomaly detector)
- **Integration Tests**: Component interaction testing (data pipelines, ML pipeline flow)

### 2.2 Test Types
- **Functional Testing**: Verify correct behavior and output
- **Security Testing**: Prompt injection detection, guardrail effectiveness
- **Edge Case Testing**: Threshold sensitivity, data scale independence, mixed data quality
- **Nondeterminism Testing**: Parametrized tests for confidence scores and statistical thresholds

### 2.3 Test Approach
- Automated testing using pytest with parametrization
- Real logic implementation (no mocks - actual ML algorithms)
- Structured test data with synthetic anomaly injection
- Comprehensive logging for visibility into test execution
- HTML test reports with detailed coverage
- Parametrized tests for comprehensive scenario coverage

## 3. Test Environment

### 3.1 Requirements
- Python 3.9+
- Virtual environment (venv)
- Required packages in requirements.txt
- pytest with plugins (pytest-html, pytest-sugar, pytest-emoji)

### 3.2 Test Data
- **Baseline data**: Known-good clean datasets
- **Synthetic anomalies**: Intentionally injected outliers
- **Edge cases**: Boundary conditions, obfuscated attacks
- **Parametrized scenarios**: Multiple variations per test
- **Scale-independent data**: Various magnitude ranges

### 3.3 Test Execution Environment
```bash
source venv/bin/activate
pip install -r [requirements.txt](http://_vscodecontentref_/0)
```
## 4. Test Coverage

### 4.1 AI/ML Tests (tests_ai/)
Test File	Test Function	Type	Test Cases	Purpose
test_classification.py	test_phishing_classification()	Unit	1	Phishing detection accuracy
test_classification.py	test_malware_classification()	Unit	1	Malware detection accuracy
test_classification.py	test_spam_classification()	Unit	1	Spam detection accuracy
test_llm_guardrails.py	test_prompt_injection_blocking()	Security	2 (malicious + safe)	Injection attack blocking
test_llm_guardrails.py	test_llm_guardrails_multiple_scenarios()	Security	5 parametrized	Multiple attack patterns
test_llm_guardrails.py	test_llm_guardrails_core_patterns()	Security	4 parametrized	Core confirmed patterns
test_llm_guardrails.py	test_llm_guardrails_edge_cases()	Edge Case	18 parametrized	Edge case robustness (whitespace, case, special chars, obfuscation)
test_autofill.py	test_autofill_generation()	Unit	1	Email suggestion generation
test_summarization.py	test_summarization_accuracy()	Unit	1	Text summarization

Total AI Tests: 34 test cases

### 4.2 Data Pipeline Tests (tests_pipelines/)

Test File	Test Function	Type	Test Cases	Purpose
test_anomaly_detection.py	test_anomaly_detection()	Unit	1	Single anomaly detection
test_anomaly_detection.py	test_normal_data_no_anomalies()	Unit	1	False positive prevention
test_anomaly_detection.py	test_anomaly_detection_threshold_behavior()	Edge Case	3 parametrized	Threshold sensitivity
test_anomaly_detection.py	test_anomaly_detection_scale_independence()	Edge Case	3 parametrized	Scale robustness
test_data_pipelines.py	test_data_validation()	Unit	1	Data cleaning and filtering
test_data_pipelines.py	test_data_validation_multiple_scenarios()	Edge Case	3 parametrized	Various data quality levels
test_integration_ml.py	test_ml_pipeline_integration()	Integration	1	End-to-end pipeline flow
test_integration_ml.py	test_ml_pipeline_multiple_scenarios()	Integration	3 parametrized	Multiple threat types
Total Pipeline Tests: 16 test cases

### 4.3 Nondeterminism Testing Strategy
Parametrized tests validate nondeterministic outputs are controlled and predictable:

## 5. Test Schedule & Execution Time

Phase	Test Count	Duration	Status
AI/ML Tests	34 cases	~3-4 min	Core functionality + edge cases
Pipeline Tests	16 cases	~2-3 min	Data flow validation
Full Suite	50 total	~5-7 min	Comprehensive
HTML Report Generation	1	~30 sec	Documentation
Total expected execution: 5-7 minutes

## 6. Test Deliverables

Automated test execution: pytest suite with 50+ test cases
Test execution reports: HTML reports (test_results.html)
Code coverage reports: htmlcov/index.html
Test artifacts: Detailed logging output
Documentation: TEST_PLAN.md, TEST_CASES.md, TRACEABILITY_MATRIX.md

## 7. Entry/Exit Criteria

### 7.1 Entry Criteria

Python 3.9+ environment available
Virtual environment created and activated
All dependencies installed from requirements.txt
All test files present in tests_ai/ and tests_pipelines/

### 7.2 Exit Criteria

All 50+ test cases executed
Pass rate = 100% (no failures)
Test coverage ≥ 80% on core modules
HTML test report generated and reviewed
All assertions validated

## 8. Test Execution Commands

### 8.1 Setup
``` bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```
### 8.2 Run Tests
``` bash
# All tests with verbose output and emoji
pytest tests_ai/ tests_pipelines/ -v --emoji

# AI tests only
pytest tests_ai/ -v -s


# Pipeline tests only
pytest tests_pipelines/ -v -s

# Specific test file
pytest tests_ai/test_classification.py -v

# Specific parametrized test (shows all variations)
pytest tests_pipelines/test_anomaly_detection.py::test_anomaly_detection_threshold_behavior -v

# Generate HTML report
pytest --html=reports/test_results.html --self-contained-html -v

# Generate coverage report
pytest --cov=core --cov-report=html

# Run with detailed logging
pytest tests_ai/ tests_pipelines/ -v -s --tb=short
```
### 8.3 View Results
``` bash
# Open HTML test report
open reports/test_results.html  # macOS
xdg-open reports/test_results.html  # Linux
start reports/test_results.html  # Windows

# Open coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

## 9. Test Case Categories

### 9.1 Threat Classification Tests

Phishing detection: Email-based threat with urgency keywords
Malware detection: File/download-based threats
Spam detection: Marketing language and promotional patterns

### 9.2 LLM Guardrail Tests

Direct injection: "Ignore previous instructions..." pattern
System prompt attack: "Override system..." attempts
Politeness obfuscation: "Please ignore..." variations
Safe queries: Legitimate user requests

### 9.3 Anomaly Detection Tests

Threshold sensitivity: Same anomaly at different Z-score thresholds
Scale independence: Anomalies detected across 10x to 1000x value ranges
False positive prevention: Normal data produces no alarms
Multiple anomalies: Detects all injected outliers

### 9.4 Data Pipeline Tests

Data validation: Filters null values and invalid records
Quality scenarios: Handles clean, mixed, and corrupted data
Data integrity: All valid fields preserved through pipeline

### 9.5 ML Pipeline Integration Tests

Phishing flow: Raw text → features → threat prediction
Malware flow: Suspicious patterns → detection → alert
Spam flow: Marketing language → classification → filtering

## 10. Risk Mitigation

### 10.1 Identified Risks & Mitigations

Risk	Test Coverage	Mitigation
False negative (threat missed)	Classification and guardrail tests	Assertion on confidence thresholds
False positive (benign flagged)	Normal data tests	Assert zero anomalies on baseline
Silent data loss	Data pipeline tests	Assert count before/after filtering
Nondeterminism (unpredictable output)	Parametrized tests	Test all threshold/scale variations
Model degradation	Regression suite	100% pass rate requirement
Edge case failures	Scale and threshold tests	Boundary condition coverage

## 11. Notes & Assumptions

All tests use real implementations, not mocks
Test data is representative of actual threat patterns
Parametrized tests ensure comprehensive scenario coverage
Logging provides visibility into test execution flow
100% pass rate is required before deployment

---

## Acknowledgments

This comprehensive test plan, including the parametrized test strategy for nondeterministic AI/ML systems, was developed with the assistance of **Claude (Anthropic)**, an AI assistant. Claude provided expert guidance on:

- Test design patterns for ML/AI systems
- Parametrized testing strategies for nondeterministic outputs
- Documentation best practices
- Comprehensive test coverage planning
- LLM security guardrail testing approaches
- Statistical anomaly detection validation methods

**Created with the help of Claude - January 8, 2026**

---

**Last Updated**: January 22, 2026
**Test Framework**: pytest with plugins
**Total Test Cases**: 50+
**Expected Duration**: 5-7 minutes
**AI Assistant**: Claude (Anthropic)