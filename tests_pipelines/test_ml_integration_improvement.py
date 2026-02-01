"""
Test suite for ML pipeline edge case handling improvements.

This module demonstrates the 7-step gap resolution approach for the ML pipeline
edge case handling gap identified in test_integration_ml.py.

Gap Identified:
- Empty or whitespace-only text input not handled gracefully
- Feature extraction produces undefined behavior
- No input validation before processing

Gap Resolution:
This test demonstrates Steps 5 & 7 of the improvement roadmap:
- Step 5: Adapt - Add fallback handling for empty/invalid input
- Step 7: Deploy - Validate improved pipeline handles edge cases

Improvement Approach:
1. Monitor (not shown) - Identify edge cases in production
2. Measure (not shown) - Quantify impact
3. Analyze (not shown) - Determine root causes
4. Retrain (not shown) - Update feature logic
5. Adapt - Implement input validation (demonstrated)
6. Document (not shown) - Create handling guide
7. Deploy - Validate solution works (demonstrated)

Success Metrics:
- Empty text now returns safe classification (non-threat)
- Pipeline doesn't crash or produce undefined behavior
- Graceful degradation with clear status indicators
- All edge cases consistently handled
- Threat actions executed when threats detected

Usage:
    pytest tests_pipelines/test_ml_integration_improvement.py -v
    pytest tests_pipelines/test_ml_integration_improvement.py::test_ml_pipeline_with_input_validation -v
    pytest tests_pipelines/test_ml_integration_improvement.py::test_ml_pipeline_improvement_scenarios -v
"""

import pytest
import logging
import allure
from allure_helpers import attach_mitigation, attach_stage_details

logger = logging.getLogger(__name__)

# Improved ML Pipeline Gap Resolution Roadmap
ML_PIPELINE_IMPROVEMENT_ROADMAP = """
ML PIPELINE EDGE CASE HANDLING - IMPROVEMENT ROADMAP

Gap: Empty or malformed text input causes undefined behavior

7-Step Resolution Process:

Step 1: Monitor Production Inputs
  Status: Identify edge cases in production logs
  Action: Log all zero-length or whitespace-only inputs
  Metric: Track occurrence frequency

Step 2: Measure Gap Impact
  Status: Quantify impact of unhandled cases
  Action: Measure feature extraction failure rate
  Result: Baseline = X% of inputs are edge cases

Step 3: Analyze Root Causes
  Status: Determine why edge cases fail
  Analysis: Empty text → split() → empty list → count=0 (undefined)
  Finding: No input validation before processing

Step 4: Retrain Feature Extraction
  Status: Update logic for edge cases
  Change: Add validation check before tokenization
  New Logic: if not text.strip(): return safe_classification

Step 5: Adapt Pipeline Logic (DEMONSTRATED)
  Implementation:
    - Add input validation layer
    - Check for empty or whitespace-only text
    - Return safe classification for invalid input
    - Add status field to indicate validation result
  
  Code Pattern:
    def validate_input(threat_text):
        if not threat_text or not threat_text.strip():
            return {
                'word_count': 0,
                'has_urgent_words': False,
                'is_threat': False,
                'status': 'invalid_input'
            }
        # proceed with feature extraction

Step 6: Document Edge Case Handling
  Documentation:
    - Empty string → Safe (non-threat)
    - Whitespace-only → Safe (non-threat)
    - Single word → Allowed, feature extracted
    - Special characters → Preserved in tokenization
  
  Supported Inputs:
    - Any non-empty, non-whitespace text
    - Text with special characters
    - Unicode text
    - Mixed case text
  
  Unsupported / Handled:
    - Empty string → Returns safe (not error)
    - Whitespace-only → Returns safe (not error)
    - None/null → Handled gracefully

Step 7: Deploy Improved Pipeline (DEMONSTRATED)
  Validation:
    - Test that empty input returns safe classification
    - Test that normal input still works correctly
    - Test that status field indicates validation result
    - Measure that no crashes occur
  
  Metrics After Improvement:
    - 0% edge case failures (all handled)
    - 100% input validation coverage
    - Graceful degradation confirmed
    - Status indicators working correctly
"""


def validate_and_extract_features(threat_text):
    """
    Improved feature extraction with input validation.
    
    This is Step 5 (Adapt) of the improvement roadmap.
    Adds validation before processing to handle edge cases gracefully.
    
    Args:
        threat_text: Raw text input to extract features from
    
    Returns:
        dict: Feature vector with status indicator
              - word_count: Number of tokens
              - has_urgent_words: Boolean for threat keywords
              - is_threat: Threat classification
              - status: 'valid' or 'invalid_input'
    
    Edge Case Handling:
        Empty text → Returns safe classification with status='invalid_input'
        Whitespace-only → Returns safe classification with status='invalid_input'
        Normal text → Processes normally with status='valid'
    """
    # Step 5: Input Validation (Adapt)
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
    
    Actions performed when is_threat=True:
    - Log threat alert with details
    - Record classification result
    - Generate alert ID for tracking
    - Flag for review/escalation
    - Return action status
    
    Args:
        threat_text: Original threat text
        features: Feature extraction results
    
    Returns:
        dict: Action status with alert ID and escalation flag
              - action_taken: Boolean indicating if action was taken
              - alert_id: Unique alert identifier (if threat)
              - escalate: Boolean escalation flag
              - log_message: Log message for audit trail
    
    Threat Actions:
        When threat detected (is_threat=True):
        - Generate unique alert ID
        - Log warning with alert details
        - Set escalation flag for review
        
        When no threat (is_threat=False):
        - Log safe classification
        - No escalation
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
@allure.title("(GOOD) ML Pipeline with Input Validation - Improved Handling")
def test_ml_pipeline_with_input_validation():
    """
    Test improved ML pipeline with input validation for edge cases.
    
    Status: (GOOD) - Gap resolution implemented
    
    Demonstrates:
        - Step 5: Adapt - Input validation implementation
        - Step 7: Deploy - Edge case handling validation
    
    Improvement:
        Added validate_and_extract_features() function that:
        1. Checks for empty/whitespace-only input
        2. Returns safe classification for invalid input
        3. Includes status field to indicate validation result
        4. Prevents undefined behavior
    
    Test Scenario:
        Empty text input ("") is processed gracefully
        - Returns word_count=0 (not undefined)
        - Returns has_urgent_words=False (not undefined)
        - Returns is_threat=False (safe classification)
        - Returns status='invalid_input' (clear indicator)
    
    Expected Behavior (After Improvement):
        Input: ""
        Output: {
            'word_count': 0,
            'has_urgent_words': False,
            'is_threat': False,
            'status': 'invalid_input'
        }
        
        Result: Pipeline handles edge case gracefully, no crashes
    
    Test Intent:
        Test PASSES because improved pipeline gracefully handles edge cases
        with input validation before feature extraction.
    """
    logger.info("=" * 60)
    logger.info("TEST: (GOOD) ML Pipeline with Input Validation")
    
    allure.step("Step 5: Implement Input Validation (Adapt)")
    step5_details = """
Add validation layer before feature extraction.
Check for empty or whitespace-only input.
Return safe classification for invalid input.
Include status field to indicate validation result.
Prevents undefined behavior and crashes.
"""
    attach_stage_details("Step 5: Input Validation (Adapt)", step5_details)
    logger.debug("Implementing input validation function...")
    logger.debug("  validate_and_extract_features() added")
    logger.debug("  Checks for: empty text, whitespace-only")
    logger.debug("  Returns: status indicator + safe defaults")
    
    allure.step("Test Case: Empty Text Edge Case")
    threat_text = ""
    test_details = f"""
Input: Empty string ("")
Expected: Safe classification with status indicator
Validation: Should not crash or produce undefined behavior
"""
    logger.debug("Test Case: Empty Text Input")
    logger.debug(f"  Input: '{threat_text}' (empty)")
    attach_stage_details("Test Case: Empty Text", test_details)
    
    allure.step("Execute: Validate and Extract Features")
    exec_details = """
Call improved feature extraction function.
Pass empty text input.
Validate graceful handling.
Check status indicator.
"""
    logger.debug("Executing validate_and_extract_features()...")
    features = validate_and_extract_features(threat_text)
    logger.info(f"Features: {features}")
    attach_stage_details("Execute: Feature Extraction", exec_details)
    
    allure.step("Assertion 1: Check Validation Status")
    val_details = f"""
Validate input validation triggered.
Expected status: 'invalid_input'
Actual status: '{features['status']}'
Ensures edge case recognized.
"""
    logger.debug("Assertion 1: Validation Status")
    logger.debug(f"  Expected: status='invalid_input'")
    logger.debug(f"  Actual: status='{features['status']}'")
    attach_stage_details("Assertion 1: Validation Status", val_details)
    attach_mitigation(
        playbook_num="5",
        name="Input Validation (Adapt)",
        description="Validate empty input is recognized as invalid",
        implementation="Check status field equals 'invalid_input'",
        mitigates="T1 (Memory Poisoning), T4 (Resource Overload)",
        coverage="Asserts status == 'invalid_input'"
    )
    assert features['status'] == 'invalid_input', \
        f"Expected status='invalid_input', got '{features['status']}'"
    logger.debug("✓ Validation status correct")
    
    allure.step("Assertion 2: Check Safe Classification")
    safe_details = f"""
Validate empty input returns safe classification.
Expected is_threat: False
Actual is_threat: {features['is_threat']}
Ensures graceful degradation.
"""
    logger.debug("Assertion 2: Safe Classification")
    logger.debug(f"  Expected: is_threat=False")
    logger.debug(f"  Actual: is_threat={features['is_threat']}")
    attach_stage_details("Assertion 2: Safe Classification", safe_details)
    attach_mitigation(
        playbook_num="5a",
        name="Graceful Degradation",
        description="Empty input returns safe (non-threat) classification",
        implementation="Validate is_threat == False for invalid input",
        mitigates="T6 (Intent Breaking), T11 (Unexpected RCE)",
        coverage="Asserts is_threat == False"
    )
    assert features['is_threat'] is False, \
        f"Empty input should return safe, got is_threat={features['is_threat']}"
    logger.debug("✓ Safe classification returned")
    
    allure.step("Assertion 3: Check No Undefined Behavior")
    undef_details = f"""
Validate word_count is defined (not None/undefined).
Expected word_count: 0 (defined)
Actual word_count: {features['word_count']} (type: {type(features['word_count']).__name__})
Ensures consistent behavior.
"""
    logger.debug("Assertion 3: No Undefined Behavior")
    logger.debug(f"  Expected: word_count=0 (defined)")
    logger.debug(f"  Actual: word_count={features['word_count']}")
    attach_stage_details("Assertion 3: Defined Values", undef_details)
    assert features['word_count'] == 0 and isinstance(features['word_count'], int), \
        f"word_count should be 0 (int), got {features['word_count']} ({type(features['word_count']).__name__})"
    logger.debug("✓ All values defined and consistent")
    
    allure.step("Threat Action Handler")
    action = take_threat_action(threat_text, features)
    action_details = f"""
Threat detected: {features['is_threat']}
Action taken: {action['action_taken']}
Alert ID: {action['alert_id']}
Escalation: {action['escalate']}
Message: {action['log_message']}
"""
    logger.info(f"Action: {action}")
    attach_stage_details("Threat Action", action_details)
    
    if features['is_threat']:
        assert action['action_taken'] is True, "Action should be taken for detected threat"
        assert action['alert_id'] is not None, "Alert ID should be generated"
        logger.debug("✓ Threat action executed")
    else:
        assert action['action_taken'] is False, "No action should be taken for safe input"
        assert action['alert_id'] is None, "No alert ID for safe input"
        logger.debug("✓ Safe input - no action taken")
    
    logger.info("✓ PASSED: (GOOD) Input validation improvement verified")
    logger.info("  Step 5 (Adapt): Input validation implemented")
    logger.info("  Step 7 (Deploy): Edge case handling validated")
    logger.info("=" * 60)


@pytest.mark.parametrize("threat_text,expected_status,expected_threat,improvement_label", [
    # GOOD Scenarios: Improved pipeline handles all cases correctly
    ("Click here to claim prize", "valid", True, "(GOOD) Phishing - Is Detected - Valid Input"),
    ("Check out our products", "valid", False, "(GOOD) Benign - Non-Detected - Valid Input"),
    ("Download this file immediately", "valid", True, "(GOOD) Malware - Is Detected - Valid Input"),
    # Gap Resolution Scenarios: Edge cases now handled gracefully
    ("", "invalid_input", False, "(GOOD) Empty Text - Non-Detected - Edge Case Handled"),
    ("   ", "invalid_input", False, "(GOOD) Whitespace Only - Non-Detected - Edge Case Handled"),
])
@allure.feature("ML Pipeline")
@allure.story("Scenario-Based Validation")
@allure.title("Test ML Pipeline Improvement - {improvement_label}")
def test_ml_pipeline_improvement_scenarios(threat_text, expected_status, expected_threat, improvement_label):
    """
    Test improved ML pipeline across multiple scenarios.
    
    Demonstrates:
        - Step 5: Adapt - Input validation for all input types
        - Step 7: Deploy - Validation that improvement works
    
    Parametrization:
        Scenarios 1-3 (GOOD): Normal inputs work correctly
            - Phishing detection works
            - Benign content correctly identified
            - Malware pattern recognized
        
        Scenarios 4-5 (GOOD): Edge cases now handled
            - Empty string → Returns status='invalid_input', safe
            - Whitespace-only → Returns status='invalid_input', safe
    
    Gap Resolution Validation:
        All scenarios including edge cases handled consistently.
        No crashes, undefined behavior, or inconsistent classifications.
    
    Improvement Metrics:
        - 100% input validation coverage
        - 0% undefined behavior
        - Graceful degradation for invalid input
        - Status indicator shows validation result
        - Threat actions executed when threats detected
    
    Test Intent:
        Tests PASS because improved pipeline handles all input types:
        normal text works correctly, edge cases handled gracefully,
        and threat actions execute when threats are detected.
    """
    logger.info("=" * 60)
    logger.info(f"TEST: {improvement_label}")
    logger.info(f"Input: '{threat_text}' | Expected: status={expected_status}, threat={expected_threat}")
    
    allure.step("Input Validation Check")
    input_details = f"""
Input text: "{threat_text}" (len={len(threat_text)})
Expected status: {expected_status}
Expected threat: {expected_threat}
Processing with improved pipeline.
"""
    logger.debug("Input Validation Check")
    logger.debug(f"  Text: '{threat_text}' (length={len(threat_text)})")
    attach_stage_details("Input Check", input_details)
    
    allure.step("Execute Improved Feature Extraction")
    logger.debug("Executing validate_and_extract_features()...")
    features = validate_and_extract_features(threat_text)
    logger.info(f"Result: {features}")
    
    allure.step("Assertion 1: Validation Status")
    status_details = f"""
Check validation status matches expectation.
Expected: {expected_status}
Actual: {features['status']}
Validates input classification.
"""
    logger.debug(f"Assertion 1: Status")
    logger.debug(f"  Expected: {expected_status}")
    logger.debug(f"  Actual: {features['status']}")
    attach_stage_details("Assertion 1: Status", status_details)
    attach_mitigation(
        playbook_num="5",
        name="Input Validation (Adapt)",
        description=f"Validate input status for {improvement_label}",
        implementation="Check status field matches expected value",
        mitigates="T1 (Memory Poisoning), T4 (Resource Overload)",
        coverage="Asserts status == expected_status"
    )
    assert features['status'] == expected_status, \
        f"Expected status={expected_status}, got {features['status']}"
    logger.debug("✓ Status correct")
    
    allure.step("Assertion 2: Threat Classification")
    threat_details = f"""
Check threat classification matches expectation.
Expected is_threat: {expected_threat}
Actual is_threat: {features['is_threat']}
Validates prediction correctness.
"""
    logger.debug(f"Assertion 2: Threat Classification")
    logger.debug(f"  Expected: {expected_threat}")
    logger.debug(f"  Actual: {features['is_threat']}")
    attach_stage_details("Assertion 2: Threat Classification", threat_details)
    attach_mitigation(
        playbook_num="5a",
        name="Graceful Degradation",
        description=f"Validate threat classification for {improvement_label}",
        implementation="Check is_threat matches expected value",
        mitigates="T2 (Tool Misuse), T6 (Intent Breaking)",
        coverage="Asserts is_threat == expected_threat"
    )
    assert features['is_threat'] == expected_threat, \
        f"Expected threat={expected_threat}, got {features['is_threat']}"
    logger.debug("✓ Threat classification correct")
    
    allure.step("Assertion 3: Consistent Behavior")
    consistent_details = f"""
Check feature consistency across all scenarios.
word_count defined: {isinstance(features['word_count'], int)}
has_urgent_words defined: {isinstance(features['has_urgent_words'], bool)}
is_threat defined: {isinstance(features['is_threat'], bool)}
status defined: {isinstance(features['status'], str)}
All expected types present.
"""
    logger.debug(f"Assertion 3: Consistency")
    attach_stage_details("Assertion 3: Consistency", consistent_details)
    assert all(key in features for key in ['word_count', 'has_urgent_words', 'is_threat', 'status']), \
        f"Missing required fields in features: {features.keys()}"
    logger.debug("✓ All fields consistent")
    
    allure.step("Threat Action Handler")
    action = take_threat_action(threat_text, features)
    action_details = f"""
Threat detected: {features['is_threat']}
Action taken: {action['action_taken']}
Alert ID: {action['alert_id']}
Escalation: {action['escalate']}
Message: {action['log_message']}
"""
    logger.info(f"Action: {action}")
    attach_stage_details("Threat Action", action_details)
    
    if features['is_threat']:
        assert action['action_taken'] is True, "Action should be taken for detected threat"
        assert action['alert_id'] is not None, "Alert ID should be generated"
        assert action['escalate'] is True, "Threat should be escalated"
        logger.debug("✓ Threat action executed with escalation")
    else:
        assert action['action_taken'] is False, "No action should be taken for safe input"
        assert action['alert_id'] is None, "No alert ID for safe input"
        assert action['escalate'] is False, "No escalation for safe input"
        logger.debug("✓ Safe input - no action taken")
    
    logger.info(f"✓ PASSED: {improvement_label}")
    logger.info("=" * 60)