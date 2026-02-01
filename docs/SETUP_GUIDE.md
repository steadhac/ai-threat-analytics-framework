# 🚀 Setup & Usage Guide

## AI Threat Analytics Framework

### Prerequisites

- ✅ Python 3.9+
- ✅ pip package manager
- ✅ Virtual environment (recommended)

---

## 📦 Installation

### 1. Clone Repository

```bash
cd /Users/carosteadham/ai-threat-analytics-framework
```
2. Create Virtual Environment
``` bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. Install Dependencies
``` bash
pip install -r requirements.txt
```
##🧪 Running Tests
Quick Start
``` bash
# Run all 31 tests
python run_tests.py

# Or with pytest directly
pytest -v
```
Run Specific Test Suites

``` bash
# AI tests only (10 tests)
python run_tests.py --suite ai

# Pipeline tests only (21 tests)
python run_tests.py --suite pipelines
```
Advanced Options
``` bash
# With coverage report
python run_tests.py --coverage

# Verbose output
python run_tests.py -vv

# Parallel execution (faster)
python run_tests.py --parallel 4

# Stop on first failure
pytest -x

# Run specific test file
pytest tests_ai/test_llm_guardrails.py -v

# Run with logging
pytest -v --log-cli-level=INFO
```
📊 Test Structure
All 31 Tests Are Local Implementations
No external API, no configuration, no tokens needed.

Tests validate:

✅ LLM Guardrails - Prompt injection & PII detection
✅ Threat Classification - Phishing, malware, spam detection
✅ Anomaly Detection - Z-score statistical analysis
✅ Autofill Service - Email suggestion generation
✅ Summarization - Text extraction & summarization
✅ Data Validation - Pipeline quality checks
✅ Integration - End-to-end ML workflows

``` bash
# List all available tests
pytest --collect-only -q

# Count tests by module
pytest tests_ai/ --collect-only -q | wc -l
pytest tests_pipelines/ --collect-only -q | wc -l
```
## 📈 Viewing Reports
HTML Report (Auto-generated)
``` bash
# View test results
open reports/test_results.html  # macOS
xdg-open reports/test_results.html  # Linux
start reports/test_results.html  # Windows
```
Test Logs
``` bash
cat reports/test_logs.txt
```
Coverage Report
``` bash
# Generate coverage
python run_tests.py --coverage

# View report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```
Allure Report (Interactive)
``` bash
# Generate Allure results
pytest --alluredir=reports/allure-results

# Serve report (opens in browser)
allure serve reports/allure-results

# Or generate static HTML
allure generate reports/allure-results -o reports/allure-report
open reports/allure-report/index.html  # macOS
```
## 🎯 Usage Examples
Example 1: Run All Tests
``` bash
========================== 31 passed in 0.39s ==========================
```
Example 2: Run AI Tests Only
``` bash
python run_tests.py --suite ai
```
Example 3: Run with Coverage
``` bash
python run_tests.py --coverage
```
Example 4: Run Tests in Parallel
``` bash
python run_tests.py --parallel 4
```
Example 5: Run Specific Test File
``` bash
pytest tests_ai/test_llm_guardrails.py -v
```
## 
🐛 Troubleshooting
Issue: Module Import Errors
``` bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```
Issue: Tests Not Collecting
``` bash
# Verify pytest can find tests
pytest --collect-only

# Check directory structure
ls tests_ai/ tests_pipelines/
```
Issue: Slow Test Execution
``` bash
# Run specific tests only
pytest tests_ai/test_classification.py

# Or run in parallel
python run_tests.py --parallel 4
```
Issue: Port Already in Use (Allure)
``` bash
# Kill the process using the port
lsof -i :8080 | grep LISTEN | awk '{print $2}' | xargs kill -9

# Or use a different port
allure serve reports/allure-results --port 8081
```
## 
🔧 Configuration
Test Configuration
See setup.cfg for:

Test discovery paths: testpaths = tests_ai tests_pipelines
Logging configuration
Coverage settings
Pytest markers and filtering
Project Settings
See settings.yaml for:

Application defaults
Test parameters
Performance thresholds

## ✨ Quick Reference
``` bash
# Full setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests (choose one)
python run_tests.py              # All tests
python run_tests.py --suite ai   # AI tests
python run_tests.py --coverage   # With coverage
pytest -v                        # Direct pytest
pytest tests_ai/ -v              # Specific module

# View reports
open reports/test_results.html   # HTML report
cat reports/test_logs.txt        # Test logs
open htmlcov/index.html          # Coverage
allure serve reports/allure-results  # Allure
```
