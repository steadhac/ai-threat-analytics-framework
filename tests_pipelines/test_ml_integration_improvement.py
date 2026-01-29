"""
Test suite for ML pipeline edge case handling improvements.

PROBLEM: Empty text causes crashes and undefined behavior

SOLUTION (3 Steps):
1. Add input validation - Check if text is empty/whitespace before processing
2. Return safe classification - Empty input = non-threat (status='invalid_input')
3. Validate with tests - Confirm empty text is handled gracefully, normal text still works

RESULT: Pipeline handles all inputs safely
- Empty text → Returns safe (no crash)
- Normal text → Works correctly with status='valid'
- Clear status indicators for debugging
- All scenarios tested and passing

Usage:
    pytest tests_pipelines/test_ml_integration_improvement.py -v
    pytest tests_pipelines/test_ml_integration_improvement.py::test_ml_pipeline_with_input_validation -v
    pytest tests_pipelines/test_ml_integration_improvement.py::test_ml_pipeline_improvement_scenarios -v
"""

import pytest
import logging
import allure
from .allure_helpers import attach_mitigation, attach_stage_details

logger = logging.getLogger(__name__)


def validate_and_extract_features(threat_text):
    """
    Improved feature extraction with input validation.
    
    Step 1: Check for empty/whitespace-only input
    Step 2: Return safe classification for invalid input
    Step 3: Process normal text with full feature extraction
    """
    # Step 1: Input Validation
    if not threat_text or not threat_text.strip():
        # Graceful degradation for invalid input
        return {
            'word_count': 0,
            'has_urgent_words': False,
            'is_threat': False,
            'status': 'invalid_input'
        }
    
    # Normal feature extraction path
    word_count = len(threat_text.split())
    has_urgent = 'click' in threat_text.lower() or \
                'download' in threat_text.lower() or \
                'immediately' in threat_text.lower()
    
    return {
        'word_count': word_count,
        'has_urgent_words': has_urgent,
        'is_threat': has_urgent,
        'status': 'valid'
    }


def take_threat_action(threat_text, features):
    """
    Take action when threat is detected.
    
    When threat detected (is_threat=True):
    - Generate unique alert ID
    - Log warning with alert details
    - Set escalation flag for review
    
    When no threat (is_threat=False):
    - Log safe classification
    - No escalation needed
    """
    if features['is_threat']:
        alert_id = f"ALERT_{len(threat_text)}_{features['word_count']}"
        action_result = {
            'action_taken': True,
            'alert_id': alert_id,
            'escalate': True,
            'log_message': f"Threat detected: {alert_id} - word_count={features['word_count']}"
        }
        logger.warning(action_result['log_message'])
        return action_result
    else:
        return {
            'action_taken': False,
            'alert_id': None,
            'escalate': False,
            'log_message': 'No threat detected - safe classification'
        }


@allure.feature("ML Pipeline")
@allure.story("Scenario-Based Validation")
@allure.title("ML Pipeline with Input Validation - Improved Handling")
def test_ml_pipeline_with_input_validation():
    """
    Test improved ML pipeline with input validation for edge cases.
    
    Status: - Pipeline handles edge cases gracefully
    
    Test Scenario:
        Empty text input ("") is processed safely
        - Returns word_count=0 (not undefined)
        - Returns is_threat=False (safe classification)
        - Returns status='invalid_input' (clear indicator)
        - No crashes or errors
    
    Expected Behavior:
        Input: ""
        Output: {
            'word_count': 0,
            'has_urgent_words': False,
            'is_threat': False,
            'status': 'invalid_input'
        }
    """
    logger.info("=" * 60)
    logger.info("TEST: ML Pipeline with Input Validation")
    
    allure.step("Step 1: Input Validation")
    logger.info("Implementing validation layer...")
    
    allure.step("Step 2: Test Empty Text")
    threat_text = ""
    features = validate_and_extract_features(threat_text)
    logger.info(f"Result: {features}")
    
    # Assertion 1: Status indicator
    assert features['status'] == 'invalid_input', \
        f"Expected status='invalid_input', got '{features['status']}'"
    logger.info("✓ Empty text recognized as invalid")
    
    # Assertion 2: Safe classification
    assert features['is_threat'] is False, \
        f"Empty input should be safe, got is_threat={features['is_threat']}"
    logger.info("✓ Empty text returns safe classification")
    
    # Assertion 3: Defined values
    assert features['word_count'] == 0 and isinstance(features['word_count'], int), \
        f"word_count should be 0 (int), got {features['word_count']}"
    logger.info("✓ All values defined (no undefined behavior)")
    
    allure.step("Step 3: Validate Threat Actions")
    action = take_threat_action(threat_text, features)
    assert action['action_taken'] is False, "No action for safe input"
    assert action['alert_id'] is None, "No alert ID for safe input"
    logger.info("✓ Threat actions working correctly")
    
    logger.info("✓ PASSED: Input validation verified")
    logger.info("=" * 60)


@pytest.mark.parametrize("threat_text,expected_status,expected_threat,scenario", [
    ("Click here to claim prize", "valid", True, "Phishing Detected"),
    ("Check out our products", "valid", False, "Benign Content"),
    ("Download this file immediately", "valid", True, "Malware Detected"),
    ("", "invalid_input", False, "Empty Text Handled"),
    ("   ", "invalid_input", False, "Whitespace Only Handled"),
])
@allure.feature("ML Pipeline")
@allure.story("Scenario-Based Validation")
@allure.title("Test ML Pipeline - {scenario}")
def test_ml_pipeline_improvement_scenarios(threat_text, expected_status, expected_threat, scenario):
    """
    Test improved ML pipeline across multiple scenarios.
    
    Validates:
    - Normal inputs work correctly (phishing, malware, benign)
    - Edge cases handled gracefully (empty, whitespace)
    - Status indicator shows validation result
    - Threat actions execute when threats detected
    """
    logger.info("=" * 60)
    logger.info(f"TEST: {scenario}")
    logger.info(f"Input: '{threat_text}' (len={len(threat_text)})")
    
    allure.step("Step 1: Validate Input")
    features = validate_and_extract_features(threat_text)
    logger.info(f"Result: {features}")
    
    allure.step("Step 2: Check Status and Classification")
    assert features['status'] == expected_status, \
        f"Expected status={expected_status}, got {features['status']}"
    assert features['is_threat'] == expected_threat, \
        f"Expected threat={expected_threat}, got {features['is_threat']}"
    logger.info("✓ Status and classification correct")
    
    allure.step("Step 3: Validate Threat Actions")
    action = take_threat_action(threat_text, features)
    
    if features['is_threat']:
        assert action['action_taken'] is True
        assert action['alert_id'] is not None
        logger.info("✓ Threat action executed")
    else:
        assert action['action_taken'] is False
        assert action['alert_id'] is None
        logger.info("✓ Safe input - no action taken")
    
    logger.info(f"✓ PASSED: {scenario}")
    logger.info("=" * 60)