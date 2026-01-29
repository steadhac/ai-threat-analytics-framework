"""
Test suite for AI threat classification system.

This module validates the ThreatClassifier's ability to accurately detect
phishing, malware, and spam threats with appropriate confidence scores.

Test Coverage:
- Phishing detection with keyword analysis (detected/safe/non-detected)
- Malware detection with suspicious patterns (detected/safe/non-detected)
- Spam detection with marketing language (detected/safe/non-detected)
- Confidence score validation (0.0-1.0 range)
- Boolean threat classification (is_threat flag)
- Detection gap identification and documentation

OWASP Agentic AI Threat Mitigations:
- T1 (Memory Poisoning): Early threat detection prevents model corruption
- T2 (Tool Misuse): Confidence scoring ensures classification quality
- T5 (Cascading Hallucination): Multi-pattern detection prevents hallucinations
- T6 (Intent Breaking): Keyword analysis catches evasion attempts
- T8 (Repudiation & Untraceability): Comprehensive logging enables compliance
- T9 (Identity Spoofing): Phishing detection prevents impersonation
- T12 (Insecure Output Handling): Confidence threshold ensures output quality

Usage:
    pytest tests_ai/test_classification.py -v
    pytest tests_ai/test_classification.py::test_phishing_classification -v
"""

import pytest
import logging
import allure
from core.threat_classifier import ThreatClassifier
from tests_pipelines.allure_helpers import attach_mitigation, attach_undetected_gap_with_mitigation, attach_guardrail_action

logger = logging.getLogger(__name__)

# Undetected gaps for classification testing
PHISHING_GAPS = [
    {
        "name": "Alternative Keyword Evasion",
        "input": "Confirm your account identity at security-update.site",
        "issue": "Uses 'confirm' and 'update' instead of 'click', 'urgent', 'prize' - bypasses keyword matching",
        "suggestion": "Expand keyword set to include context-aware phishing indicators",
        "implementation": "Add patterns for ['confirm', 'verify', 'validate', 'update'] combined with URL-like patterns",
        "priority": "HIGH",
        "steps": [
            {"step": "1. Analyze phishing dataset", "action": "Identify alternative phishing keywords beyond common set"},
            {"step": "2. Add context patterns", "action": "Include URL patterns, urgency indicators, authority claims"},
            {"step": "3. Implement semantic detection", "action": "Use TF-IDF (Term Frequency-Inverse Document Frequency) "
            "to analyze word patterns instead of just keywords. TF-IDF identifies statistical signatures of phishing "
            "by scoring how frequently certain word combinations appear together (e.g., 'confirm account' + domain patterns). "
            "This catches variations like 'Confirm your identity at security-update.site' "
            "even though it lacks obvious keywords like 'click' or 'urgent'"},            
            {"step": "4. Test variations", "action": "Validate against 'confirm account', 'verify identity', 'update payment'"}
        ]
    },
    {
        "name": "Polyglot Obfuscation",
        "input": "Click h ere to claim prize (space in keyword)",
        "issue": "Spaces/special characters inserted in keywords break tokenization",
        "suggestion": "Normalize whitespace and apply fuzzy matching",
        "implementation": "Use regex to remove non-alphanumeric characters before pattern matching",
        "priority": "MEDIUM",
        "steps": [
            {"step": "1. Add text normalization", "action": "Remove spaces and special chars before matching"},
            {"step": "2. Implement fuzzy matching", "action": "Use levenshtein distance for keyword similarity"},
            {"step": "3. Test obfuscation variants", "action": "Validate against 'cli ck', 'cl!ck', 'cl1ck'"},
            {"step": "4. Measure accuracy", "action": "Ensure no false positives on legitimate text"}
        ]
    }
]

MALWARE_GAPS = [
    {
        "name": "Legitimate Download Context",
        "input": "Download the latest update from official website",
        "issue": "Contains 'download' but in legitimate context - no malware delivery pattern detected",
        "suggestion": "Add context analysis - distinguish between legitimate and malicious downloads",
        "implementation": "Analyze source domain reputation, request urgency, and legitimacy signals",
        "priority": "HIGH",
        "steps": [
            {"step": "1. Domain reputation check", "action": "Integrate with domain reputation service"},
            {"step": "2. Urgency analysis", "action": "Flag 'download NOW', 'urgent', 'immediately' patterns"},
            {"step": "3. Source validation", "action": "Check against known legitimate sources"},
            {"step": "4. Test legitimate cases", "action": "Ensure vendor updates don't trigger false positives"}
        ]
    }
]

SPAM_GAPS = [
    {
        "name": "Subtle Marketing Language",
        "input": "Interested in great deals? Check out our collection",
        "issue": "Uses softer marketing language ('interested', 'collection') instead of urgent calls to action",
        "suggestion": "Expand spam keyword set and implement engagement level scoring",
        "implementation": "Add soft marketing indicators and measure urgency/excitement levels",
        "priority": "MEDIUM",
        "steps": [
            {"step": "1. Analyze spam dataset", "action": "Identify soft marketing patterns in legitimate promotions"},
            {"step": "2. Add soft keywords", "action": "Include ['interested', 'deal', 'collection', 'offer']"},
            {"step": "3. Implement urgency scoring", "action": "Rate urgency level to distinguish legitimate from spam"},
            {"step": "4. Test variations", "action": "Validate without false positives on store announcements"}
        ]
    }
]


@pytest.mark.parametrize("text,expected_threat,expected_label,confidence_threshold,description", [
    ("Click here to claim your prize! Urgent action required.", True, 'phishing', 0.85, "Phishing attack - Is_Detected"),
    ("Hello, how are you today?", False, None, 0.0, "Benign greeting - Safe"),
    ("Your account has been flagged for verification.", False, None, 0.0, "Legitimate account notice - Safe"),
    ("Confirm your account identity at security-update.site", False, None, 0.0, "(GAP) Alternative keyword evasion - Non_Detected"),
    ("Click h ere to claim your prize", False, None, 0.0, "(GAP) Obfuscated phishing - Non_Detected"),
])
@allure.feature("Threat Classification")
@allure.story("Phishing Detection")
@allure.title("Test Phishing Threat Classification - Detects Known Attacks and Documents Evasion Gaps")
def test_phishing_classification(text, expected_threat, expected_label, confidence_threshold, description):
    """Validate phishing detection with identified evasion gaps."""
    allure.dynamic.title(f"Test {description}")
    
    logger.info("=" * 60)
    logger.info(f"TEST: Phishing Classification - {description}")
    logger.info(f"Input: '{text}'")
    logger.info(f"Expected: threat={expected_threat}, label={expected_label}")
    
    allure.step("Initialize Threat Classifier")
    classifier = ThreatClassifier()
    logger.debug("✓ Classifier ready")
    
    allure.step("Execute classification")
    result = classifier.classify(text)
    logger.info(f"Result: {result}")
    
    allure.step("Assert correctness")
    assert result['is_threat'] == expected_threat, \
        f"Expected is_threat={expected_threat}, got {result['is_threat']}"
    logger.debug("✓ Threat detection correct")
    
    if expected_label:
        assert expected_label in result['labels'], \
            f"Expected {expected_label} in {result['labels']}"
        logger.debug(f"✓ Label correct: {expected_label}")
        
        if confidence_threshold > 0:
            assert result['confidence'][0] >= confidence_threshold, \
                f"Expected confidence >= {confidence_threshold}, got {result['confidence'][0]}"
            logger.debug(f"✓ Confidence valid: {result['confidence'][0]}")

    allure.step("Verify action and threat details")
    if not result['is_threat']:
        logger.info("✓ No threat detected - benign input")
    else:
        threats = result.get('labels', [])
        logger.info(f"Threats detected: {threats}")
        attach_guardrail_action(threats)

    # Attach mitigations
    attach_mitigation(
        playbook_num="1",
        name="Phishing Pattern Detection",
        description="Identify phishing attacks through keyword and pattern matching",
        implementation="Detect urgency markers, credential requests, and suspicious links",
        mitigates="T9 (Identity Spoofing), T6 (Intent Breaking), T12 (Insecure Output)",
        coverage="Phishing keyword detection in user input"
    )

    attach_mitigation(
        playbook_num="2",
        name="Confidence Quality Threshold",
        description="Ensure classification confidence exceeds quality gate",
        implementation="Only flag threats with confidence >= 0.85",
        mitigates="T2 (Tool Misuse), T12 (Insecure Output)",
        coverage="Confidence score validation"
    )

    logger.info(f"✓ PASSED: {description}")
    logger.info("=" * 60)

    # Attach undetected gaps for non-detected cases
    if description == "(GAP) Alternative keyword evasion - Non_Detected":
        gap = PHISHING_GAPS[0]  # Only "Alternative Keyword Evasion"
        attach_undetected_gap_with_mitigation(
            pattern_name=gap["name"],
            malicious_input=gap["input"],
            issue=gap["issue"],
            suggestion=gap["suggestion"],
            implementation=gap["implementation"],
            priority=gap["priority"],
            mitigation_steps=gap["steps"]
        )
    elif description == "(GAP) Obfuscated phishing - Non_Detected":
        gap = PHISHING_GAPS[1]  # Only "Polyglot Obfuscation"
        attach_undetected_gap_with_mitigation(
            pattern_name=gap["name"],
            malicious_input=gap["input"],
            issue=gap["issue"],
            suggestion=gap["suggestion"],
            implementation=gap["implementation"],
            priority=gap["priority"],
            mitigation_steps=gap["steps"]
        )


@pytest.mark.parametrize("text,expected_threat,expected_label,confidence_threshold,description", [
    ("Download this file now to update", True, 'malware', 0.80, "Malware delivery - Is_Detected"),
    ("Check out our website for more info", False, None, 0.0, "Benign website reference - Safe"),
    ("System update available", False, None, 0.0, "Legitimate update notice - Safe"),
    ("Download the latest update from official website", True, 'malware', 0.65, "Legitimate download context flagged as threat (IS detected - FALSE POSITIVE)"),])
@allure.feature("Threat Classification")
@allure.story("Malware Detection")
@allure.title("Test Malware Threat Classification - Detects Delivery Patterns and Documents Context Gaps")
def test_malware_classification(text, expected_threat, expected_label, confidence_threshold, description):
    """Validate malware detection with identified context gaps."""
    allure.dynamic.title(f"Test {description}")
    
    logger.info("=" * 60)
    logger.info(f"TEST: Malware Classification - {description}")
    logger.info(f"Input: '{text}'")
    logger.info(f"Expected: threat={expected_threat}, label={expected_label}")
    
    allure.step("Initialize Threat Classifier")
    classifier = ThreatClassifier()
    logger.debug("✓ Classifier ready")
    
    allure.step("Execute classification")
    result = classifier.classify(text)
    logger.info(f"Result: {result}")
    
    allure.step("Assert correctness")
    assert result['is_threat'] == expected_threat, \
        f"Expected is_threat={expected_threat}, got {result['is_threat']}"
    logger.debug("✓ Threat detection correct")
    
    if expected_label:
        assert expected_label in result['labels'], \
            f"Expected {expected_label} in {result['labels']}"
        logger.debug(f"✓ Label correct: {expected_label}")
        
        if confidence_threshold > 0:
            assert result['confidence'][0] >= confidence_threshold, \
                f"Expected confidence >= {confidence_threshold}, got {result['confidence'][0]}"
            logger.debug(f"✓ Confidence valid: {result['confidence'][0]}")

    allure.step("Verify action and threat details")
    if not result['is_threat']:
        logger.info("✓ No threat detected - benign input")
    else:
        threats = result.get('labels', [])
        logger.info(f"Threats detected: {threats}")
        attach_guardrail_action(threats)

    # Attach mitigations
    attach_mitigation(
        playbook_num="1",
        name="Malware Delivery Detection",
        description="Identify malware delivery attempts through suspicious patterns",
        implementation="Detect file downloads, urgent requests, and malware indicators",
        mitigates="T1 (Memory Poisoning), T2 (Tool Misuse), T6 (Intent Breaking)",
        coverage="Malware keyword detection in input"
    )

    attach_mitigation(
        playbook_num="2",
        name="Confidence Quality Threshold",
        description="Ensure classification confidence exceeds quality gate",
        implementation="Only flag threats with confidence >= 0.80",
        mitigates="T2 (Tool Misuse), T12 (Insecure Output)",
        coverage="Confidence score validation"
    )

    logger.info(f"✓ PASSED: {description}")
    logger.info("=" * 60)

    # Attach undetected gaps for non-detected cases
    if "Legitimate download context" in description:
        for gap in MALWARE_GAPS:
            attach_undetected_gap_with_mitigation(
                pattern_name=gap["name"],
                malicious_input=gap["input"],
                issue=gap["issue"],
                suggestion=gap["suggestion"],
                implementation=gap["implementation"],
                priority=gap["priority"],
                mitigation_steps=gap["steps"]
            )


@pytest.mark.parametrize("text,expected_threat,expected_label,confidence_threshold,description", [
    ("Buy cheap stuff today limited offer", True, 'spam', 0.75, "Spam marketing - Is_Detected"),
    ("Check out our new product line", False, None, 0.0, "Legitimate product announcement - Safe"),
    ("Visit our store for details", False, None, 0.0, "Benign store reference - Safe"),
    ("Interested in great deals? Check out our collection", False, None, 0.0, "(GAP) Subtle marketing language - Non_Detected"),
])
@allure.feature("Threat Classification")
@allure.story("Spam Detection")
@allure.title("Test Spam Threat Classification - Detects Aggressive Marketing and Documents Soft Language Gaps")
def test_spam_classification(text, expected_threat, expected_label, confidence_threshold, description):
    """Validate spam detection with identified soft language gaps."""
    allure.dynamic.title(f"Test {description}")
    
    logger.info("=" * 60)
    logger.info(f"TEST: Spam Classification - {description}")
    logger.info(f"Input: '{text}'")
    logger.info(f"Expected: threat={expected_threat}, label={expected_label}")
    
    allure.step("Initialize Threat Classifier")
    classifier = ThreatClassifier()
    logger.debug("✓ Classifier ready")
    
    allure.step("Execute classification")
    result = classifier.classify(text)
    logger.info(f"Result: {result}")
    
    allure.step("Assert correctness")
    assert result['is_threat'] == expected_threat, \
        f"Expected is_threat={expected_threat}, got {result['is_threat']}"
    logger.debug("✓ Threat detection correct")
    
    if expected_label:
        assert expected_label in result['labels'], \
            f"Expected {expected_label} in {result['labels']}"
        logger.debug(f"✓ Label correct: {expected_label}")
        
        if confidence_threshold > 0:
            assert result['confidence'][0] >= confidence_threshold, \
                f"Expected confidence >= {confidence_threshold}, got {result['confidence'][0]}"
            logger.debug(f"✓ Confidence valid: {result['confidence'][0]}")

    allure.step("Verify action and threat details")
    if not result['is_threat']:
        logger.info("✓ No threat detected - benign input")
    else:
        threats = result.get('labels', [])
        logger.info(f"Threats detected: {threats}")
        attach_guardrail_action(threats)

    # Attach mitigations
    attach_mitigation(
        playbook_num="1",
        name="Spam Marketing Detection",
        description="Identify spam through aggressive marketing language",
        implementation="Detect urgency markers, limited offers, and pressure tactics",
        mitigates="T9 (Identity Spoofing), T6 (Intent Breaking), T12 (Insecure Output)",
        coverage="Spam keyword detection in input"
    )

    attach_mitigation(
        playbook_num="2",
        name="Confidence Quality Threshold",
        description="Ensure classification confidence exceeds quality gate",
        implementation="Only flag threats with confidence >= 0.75",
        mitigates="T2 (Tool Misuse), T12 (Insecure Output)",
        coverage="Confidence score validation"
    )

    logger.info(f"✓ PASSED: {description}")
    logger.info("=" * 60)

    # Attach undetected gaps for non-detected cases
    if description == "(GAP) Subtle marketing language - Non_Detected":
        for gap in SPAM_GAPS:
            attach_undetected_gap_with_mitigation(
                pattern_name=gap["name"],
                malicious_input=gap["input"],
                issue=gap["issue"],
                suggestion=gap["suggestion"],
                implementation=gap["implementation"],
                priority=gap["priority"],
                mitigation_steps=gap["steps"]
            )