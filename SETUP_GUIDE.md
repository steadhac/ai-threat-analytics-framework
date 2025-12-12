# 🚀 Setup & Usage Guide

## AI & Threat Analytics Testing Framework

### Prerequisites

- ✅ Python 3.9+ (You have: Python 3.9.6)
- ✅ pip package manager
- ✅ API access (for full integration tests)

---

## 📦 Installation

### 1. Basic Setup (Already in place!)

```bash
cd /Users/carosteadham/selenium-testng-automation-framework/ai-threat-analytics-framework
```

### 2. Install All Dependencies

```bash
# Install all required packages
pip3 install -r requirements.txt
```

Or install just the essentials:

```bash
# Core testing dependencies
pip3 install pytest pytest-xdist pytest-cov pytest-timeout
pip3 install requests pyyaml numpy scipy scikit-learn jsonschema
```

### 3. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your settings
nano .env
```

Add your API token:
```bash
security-platform_API_TOKEN=your_actual_token_here
security-platform_API_BASE_URL=https://api.security-platform.ai
```

---

## 🧪 Running Tests

### Quick Test Commands

#### 1. Run Utility Tests (No API needed)
These tests validate the framework utilities without requiring API access:

```bash
# Test anomaly detection utilities ✅ WORKS NOW
python3 -m pytest tests_pipelines/test_anomaly_detection.py::test_anomaly_scoring_utility -v
python3 -m pytest tests_pipelines/test_anomaly_detection.py::test_behavioral_anomaly_utility -v

# Test security utilities
python3 -m pytest tests_ai/test_llm_guardrails.py -k "test_pii" -v --collect-only
```

#### 2. List All Available Tests

```bash
# See all 67 tests
python3 -m pytest --collect-only

# Count by category
python3 -m pytest --collect-only -q | grep "tests_ai" | wc -l
python3 -m pytest --collect-only -q | grep "tests_pipelines" | wc -l
```

#### 3. Run Full Test Suite (Requires API)

```bash
# Using the test runner
python3 run_tests.py --suite all --verbose

# Or with pytest directly
python3 -m pytest -v
```

#### 4. Run Specific Test Suites

```bash
# AI/ML tests only
python3 run_tests.py --suite ai --verbose

# Pipeline tests only
python3 run_tests.py --suite pipelines --verbose

# Security tests only
python3 run_tests.py --suite security --verbose

# Integration tests
python3 run_tests.py --suite integration --verbose
```

#### 5. Advanced Options

```bash
# Run with coverage report
python3 run_tests.py --suite all --coverage

# Run tests in parallel (4 workers)
python3 run_tests.py --suite all --parallel 4

# Run with Allure reporting
python3 run_tests.py --suite all --allure

# Run specific markers
python3 -m pytest -m "not slow" -v
```

---

## 📊 Test Categories

### ✅ Tests You Can Run Right Now (No API needed):

1. **Security Utilities**
   - PII detection
   - Prompt injection detection
   - Data validation

2. **Anomaly Detection Utilities**
   - Z-score calculations
   - Behavioral anomaly scoring
   - Drift detection algorithms

3. **Helper Functions**
   - Text normalization
   - Fuzzy matching
   - Schema validation

```bash
# Example: Run utility tests
python3 -m pytest \
  tests_pipelines/test_anomaly_detection.py::test_anomaly_scoring_utility \
  tests_pipelines/test_anomaly_detection.py::test_behavioral_anomaly_utility \
  -v
```

### 🔌 Tests Requiring API Connection:

1. **LLM Guardrails** (`tests_ai/test_llm_guardrails.py`)
   - Prompt injection blocking
   - PII leakage prevention
   - Content filtering

2. **Classification** (`tests_ai/test_classification.py`)
   - Model accuracy
   - Zero-shot classification
   - Multi-label classification

3. **Summarization** (`tests_ai/test_summarization.py`)
   - Quality metrics (ROUGE, BLEU)
   - Hallucination detection
   - Semantic similarity

4. **Autofill** (`tests_ai/test_autofill.py`)
   - Form detection
   - Field mapping
   - Security validation

5. **Data Pipelines** (`tests_pipelines/test_data_pipelines.py`)
   - ETL validation
   - Embedding generation
   - Schema compliance

6. **Threat Detection** (`tests_pipelines/test_anomaly_detection.py`)
   - Attack pattern detection
   - Behavioral analysis
   - Real-time monitoring

7. **Integration** (`tests_pipelines/test_integration_ml.py`)
   - End-to-end flows
   - Service integration
   - Performance testing

---

## 🎯 Usage Examples

### Example 1: Demo Mode (No API)

```bash
# Run utility tests to demonstrate framework capabilities
python3 -m pytest \
  tests_pipelines/test_anomaly_detection.py::test_anomaly_scoring_utility \
  tests_pipelines/test_anomaly_detection.py::test_behavioral_anomaly_utility \
  --verbose --tb=short
```

**Expected Output:**
```
tests_pipelines/test_anomaly_detection.py::test_anomaly_scoring_utility PASSED
tests_pipelines/test_anomaly_detection.py::test_behavioral_anomaly_utility PASSED

==================== 2 passed in 0.XX s ====================
```

### Example 2: With Mock API (Coming Soon)

You can create mock API responses for testing:

```python
# In conftest.py, add:
@pytest.fixture
def mock_api_client(monkeypatch):
    """Mock API client for testing without real API."""
    def mock_post(*args, **kwargs):
        return {"prediction": "test", "confidence": 0.9}
    
    monkeypatch.setattr("core.api_client.APIClient.post", mock_post)
```

### Example 3: Full Integration (With Real API)

```bash
# Set your API token
export security-platform_API_TOKEN="your-token-here"

# Run full test suite
python3 run_tests.py --suite all --coverage --parallel 4 --verbose

# Generate reports
python3 run_tests.py --suite all --allure
```

---

## 📈 Viewing Reports

### HTML Report

```bash
# Run tests with HTML output
python3 -m pytest --html=reports/results.html --self-contained-html

# Open report
open reports/results.html
```

### Coverage Report

```bash
# Generate coverage
python3 -m pytest --cov=core --cov=tests_ai --cov=tests_pipelines --cov-report=html

# View coverage
open htmlcov/index.html
```

### Allure Report (requires Allure CLI)

```bash
# Install Allure (macOS)
brew install allure

# Generate and serve report
python3 run_tests.py --suite all --allure
allure serve reports/allure-results
```

---

## 🐛 Troubleshooting

### Issue: Import Errors

```bash
# Solution: Install missing dependencies
pip3 install scikit-learn scipy jsonschema sentence-transformers
```

### Issue: API Connection Errors

```bash
# Check your environment
echo $security-platform_API_TOKEN

# Verify API endpoint in config
cat config/settings.yaml | grep base_url
```

### Issue: Tests Taking Too Long

```bash
# Run specific tests only
python3 -m pytest tests_ai/test_llm_guardrails.py::test_prompt_injection_detection

# Or skip slow tests
python3 -m pytest -m "not slow"
```

---

## 🔧 Configuration

### Update API Settings

Edit `config/settings.yaml`:

```yaml
api:
  base_url: "https://your-api.com"
  token: "${security-platform_API_TOKEN}"
  timeout: 30
```

### Adjust Test Thresholds

```yaml
thresholds:
  semantic_similarity: 0.7
  rouge_score: 0.45
  anomaly_score: 0.8
```

---

## 📚 Framework Structure

```
67 Total Tests Available:
  - 21 AI/ML Tests (tests_ai/)
  - 30 Pipeline Tests (tests_pipelines/)
  - 16 Integration Tests
```

### Test Breakdown:

- **LLM Guardrails**: 21 tests
- **Classification**: 13 tests
- **Summarization**: 11 tests
- **Autofill**: 16 tests
- **Data Pipelines**: 16 tests
- **Anomaly Detection**: 13 tests
- **Integration**: 11 tests

---

## ✨ Next Steps

1. **Install Dependencies**
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Set Up Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

3. **Run Demo Tests**
   ```bash
   python3 -m pytest tests_pipelines/test_anomaly_detection.py::test_anomaly_scoring_utility -v
   ```

4. **Configure API Endpoint**
   - Update `config/settings.yaml` with real API URL
   - Add API token to `.env`

5. **Run Full Suite**
   ```bash
   python3 run_tests.py --suite all --verbose --coverage
   ```

---

## 📞 Support

For issues or questions:
- Check the [README.md](README.md)
- Review test files for examples
- Check `conftest.py` for available fixtures

---

**Ready to test AI systems with confidence!** 🚀
