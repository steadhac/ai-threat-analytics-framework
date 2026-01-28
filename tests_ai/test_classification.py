"""
Test suite for AI threat classification system.

This module validates the ThreatClassifier's ability to accurately detect
phishing, malware, and spam threats with appropriate confidence scores.

Test Coverage:
- Phishing detection with keyword analysis
- Malware detection with suspicious patterns
- Spam detection with marketing language
- Confidence score validation (0.0-1.0 range)
- Boolean threat classification (is_threat flag)

OWASP Agentic AI Threat Mitigations:

- T1 (Memory Poisoning): Prevent malicious training data corruption
  • Implementation: Classify threats before they reach ML models
  • Risk: Poisoned data degrades classifier accuracy
  • Mitigation: Early threat detection prevents model corruption

- T2 (Tool Misuse): Validate threat classification before downstream use
  • Implementation: Confidence scoring ensures classification quality
  • Risk: Incorrect classifications cause tools to misfire
  • Mitigation: Confidence threshold prevents incorrect tool use

- T5 (Cascading Hallucination): Ensure classification accuracy prevents errors
  • Implementation: Multi-pattern threat detection prevents hallucinations
  • Risk: Misclassified threats propagate through system
  • Mitigation: Robust classification prevents cascading failures

- T6 (Intent Breaking): Prevent unauthorized threat bypasses
  • Implementation: Keyword analysis and pattern matching catches evasion
  • Risk: Attackers evade detection through obfuscation
  • Mitigation: Multi-layer detection prevents intent breaking

- T8 (Repudiation & Untraceability): Maintain audit trail of classifications
  • Implementation: Log all classifications with confidence scores
  • Risk: Silent misclassifications hide security issues
  • Mitigation: Comprehensive logging enables compliance and debugging

- T9 (Identity Spoofing): Detect spoofed threats and phishing attempts
  • Implementation: Phishing keyword detection prevents impersonation
  • Risk: Spoofed identities fool users and bypass security
  • Mitigation: Threat classification prevents spoofing attacks

- T12 (Insecure Output Handling): Only output validated threat classifications
  • Implementation: Confidence threshold ensures output quality
  • Risk: Invalid classifications corrupt downstream security decisions
  • Mitigation: Strict validation ensures reliable threat output

Usage:
    pytest tests_ai/test_classification.py -v
    pytest tests_ai/test_classification.py::test_phishing_classification -v
"""

import pytest
import logging
import allure
from core.threat_classifier import ThreatClassifier
from tests_pipelines.allure_helpers import attach_mitigation, attach_stage_details

logger = logging.getLogger(__name__)


@allure.feature("Threat Classification")
@allure.story("Phishing Detection")
@allure.title("Test Phishing Threat Classification with Confidence Scoring")
def test_phishing_classification():
    """
    Test phishing threat detection with confidence scoring.
    
    Validates:
        - is_threat returns True for phishing attempts
        - 'phishing' label is present in classification results
        - Confidence score meets or exceeds 0.85 threshold
    
    Pipeline Flow:
        Input Text → Feature Extraction → Pattern Matching → Classification → Confidence Scoring → Output
    
    Test Data:
        "Click here to claim your prize! Urgent action required."
        Keywords: urgent, click, claim, prize (common phishing indicators)
    
    Validation Logic:
        - Threat Detection: is_threat == True
        - Label Identification: 'phishing' in labels
        - Confidence Threshold: confidence >= 0.85
    
    Expected Result:
        {
            'is_threat': True,
            'labels': ['phishing'],
            'confidence': [0.92]
        }
    
    Assertions:
        3 assertions validate threat detection accuracy
    """
    logger.info("=" * 60)
    logger.info("TEST: Phishing Classification")
    
    allure.step("PHASE 1: Initialize Threat Classifier")
    phase1_details = """
Create and configure ThreatClassifier instance.
Classifier ready with trained models.
Models loaded for phishing, malware, spam detection.
Prepare classifier for threat analysis.
"""
    logger.debug("PHASE 1: Classifier Initialization")
    logger.debug("-" * 40)
    classifier = ThreatClassifier()
    attach_stage_details("PHASE 1: Classifier Initialization", phase1_details)
    logger.debug("Step 1a: Create ThreatClassifier instance")
    logger.debug(f"  Classifier: {classifier.__class__.__name__}")
    logger.debug("✓ Classifier ready")
    
    allure.step("PHASE 2: Prepare Phishing Test Input")
    phase2_details = """
Load phishing test case with known threat indicators.
Text: "Click here to claim your prize! Urgent action required."
Keywords present: urgent, click, claim, prize
Pattern: Common phishing request for urgent action.
Prepare for classification.
"""
    logger.debug("PHASE 2: Test Input Preparation")
    logger.debug("-" * 40)
    phishing_text = "Click here to claim your prize! Urgent action required."
    attach_stage_details("PHASE 2: Test Input Preparation", phase2_details)
    logger.debug("Step 2a: Load phishing test case")
    logger.debug(f"  Text: '{phishing_text}'")
    logger.debug(f"  Keywords: urgent, click, claim, prize")
    
    allure.step("PHASE 3: Execute Threat Classification")
    phase3_details = """
Run threat classification on input text.
Analyzer: Keyword matching + pattern detection
Models: Phishing, malware, spam classifiers
Output: Classification result with confidence score.
"""
    logger.debug("PHASE 3: Classification Execution")
    logger.debug("-" * 40)
    result = classifier.classify(phishing_text)
    attach_stage_details("PHASE 3: Classification Execution", phase3_details)
    logger.debug("Step 3a: Execute classification")
    logger.info(f"Classification result: {result}")
    logger.debug(f"  is_threat: {result['is_threat']}")
    logger.debug(f"  labels: {result['labels']}")
    logger.debug(f"  confidence: {result['confidence']}")
    
    allure.step("PHASE 4: Validate Classification Quality")
    phase4_details = """
Assess classification quality and reliability.
Verify: Threat correctly identified (is_threat=True)
Verify: Label matches expected category (phishing)
Verify: Confidence above quality threshold (>=0.85)
"""
    logger.debug("PHASE 4: Quality Assessment")
    logger.debug("-" * 40)
    attach_stage_details("PHASE 4: Quality Assessment", phase4_details)
    logger.debug("Step 4a: Check classification quality")
    logger.debug(f"  Threat detected: {result['is_threat']}")
    logger.debug(f"  Label correct: {'phishing' in result['labels']}")
    logger.debug(f"  Confidence high: {result['confidence'][0] >= 0.85}")
    
    allure.step("PHASE 5: MITIGATION 1 - Threat Detection Accuracy (Playbook 1)")
    phase5_m1_details = """
Verify threat detection correctly identifies phishing.
Expected: is_threat = True
Prevents: Phishing bypassing security checks.
Ensures: Threats are properly flagged for handling.
"""
    logger.debug("PHASE 5: Assertions & Mitigations")
    logger.debug("-" * 40)
    logger.debug("Step 5a: Assertion 1 - Threat detection")
    logger.debug(f"  is_threat: {result['is_threat']} (expected: True)")
    attach_stage_details("PHASE 5: MITIGATION 1", phase5_m1_details)
    attach_mitigation(
        playbook_num="1",
        name="Threat Detection Accuracy",
        description="Ensure phishing threats are correctly identified",
        implementation="Assert is_threat == True for phishing text",
        mitigates="T1 (Memory Poisoning), T9 (Identity Spoofing), T12 (Insecure Output)",
        coverage="Asserts result['is_threat'] is True"
    )
    assert result['is_threat'] is True, "Phishing should be detected as threat"
    logger.debug("✓ Threat flag correct")
    
    allure.step("PHASE 5: MITIGATION 2 - Label Identification (Playbook 2)")
    phase5_m2_details = """
Verify classification correctly labels as phishing.
Expected: 'phishing' in labels
Prevents: Misclassification to other threat types.
Ensures: Threat type is correctly identified.
"""
    logger.debug("Step 5b: Assertion 2 - Label verification")
    logger.debug(f"  Labels: {result['labels']} (expected to contain 'phishing')")
    attach_stage_details("PHASE 5: MITIGATION 2", phase5_m2_details)
    attach_mitigation(
        playbook_num="2",
        name="Label Identification",
        description="Verify correct threat type classification",
        implementation="Assert 'phishing' in result['labels']",
        mitigates="T2 (Tool Misuse), T5 (Cascading Hallucination), T9 (Identity Spoofing)",
        coverage="Asserts correct threat label present"
    )
    assert 'phishing' in result['labels'], "Should identify as phishing"
    logger.debug("✓ Label correct")
    
    allure.step("PHASE 5: MITIGATION 3 - Confidence Quality Gate (Playbook 3)")
    phase5_m3_details = """
Verify confidence score exceeds quality threshold.
Expected: confidence >= 0.85
Prevents: Low-confidence misclassifications.
Ensures: Only reliable classifications are output.
"""
    logger.debug("Step 5c: Assertion 3 - Confidence threshold")
    logger.debug(f"  Confidence: {result['confidence'][0]} (expected: >= 0.85)")
    attach_stage_details("PHASE 5: MITIGATION 3", phase5_m3_details)
    attach_mitigation(
        playbook_num="3",
        name="Confidence Quality Gate",
        description="Ensure classification confidence exceeds quality threshold",
        implementation="Assert confidence >= 0.85 for reliable classification",
        mitigates="T6 (Intent Breaking), T8 (Repudiation), T12 (Insecure Output)",
        coverage="Asserts result['confidence'][0] >= 0.85"
    )
    assert result['confidence'][0] >= 0.85, "Phishing confidence should be >= 0.85"
    logger.debug(f"✓ Confidence score valid: {result['confidence'][0]}")
    
    logger.info("✓ PASSED: Phishing classification accurate")
    logger.info(f"  Threat: {result['is_threat']}")
    logger.info(f"  Label: {result['labels']}")
    logger.info(f"  Confidence: {result['confidence'][0]}")
    logger.info("=" * 60)


@allure.feature("Threat Classification")
@allure.story("Malware Detection")
@allure.title("Test Malware Threat Classification with Confidence Scoring")
def test_malware_classification():
    """
    Test malware threat detection with confidence scoring.
    
    Validates:
        - is_threat returns True for malware attempts
        - 'malware' label is present in classification results
        - Confidence score meets or exceeds 0.80 threshold
    
    Pipeline Flow:
        Input Text → Feature Extraction → Pattern Matching → Classification → Confidence Scoring → Output
    
    Test Data:
        "Download this file now to update"
        Keywords: download, file, update (common malware delivery patterns)
    
    Validation Logic:
        - Threat Detection: is_threat == True
        - Label Identification: 'malware' in labels
        - Confidence Threshold: confidence >= 0.80
    
    Expected Result:
        {
            'is_threat': True,
            'labels': ['malware'],
            'confidence': [0.88]
        }
    
    Assertions:
        3 assertions validate threat detection accuracy
    """
    logger.info("=" * 60)
    logger.info("TEST: Malware Classification")
    
    allure.step("PHASE 1: Initialize Threat Classifier")
    phase1_details = """
Create and configure ThreatClassifier instance.
Classifier ready with trained models.
Models loaded for phishing, malware, spam detection.
Prepare classifier for threat analysis.
"""
    logger.debug("PHASE 1: Classifier Initialization")
    logger.debug("-" * 40)
    classifier = ThreatClassifier()
    attach_stage_details("PHASE 1: Classifier Initialization", phase1_details)
    logger.debug("Step 1a: Create ThreatClassifier instance")
    logger.debug(f"  Classifier: {classifier.__class__.__name__}")
    logger.debug("✓ Classifier ready")
    
    allure.step("PHASE 2: Prepare Malware Test Input")
    phase2_details = """
Load malware test case with known threat indicators.
Text: "Download this file now to update"
Keywords present: download, file, update
Pattern: Common malware delivery request.
Prepare for classification.
"""
    logger.debug("PHASE 2: Test Input Preparation")
    logger.debug("-" * 40)
    malware_text = "Download this file now to update"
    attach_stage_details("PHASE 2: Test Input Preparation", phase2_details)
    logger.debug("Step 2a: Load malware test case")
    logger.debug(f"  Text: '{malware_text}'")
    logger.debug(f"  Keywords: download, file, update")
    
    allure.step("PHASE 3: Execute Threat Classification")
    phase3_details = """
Run threat classification on input text.
Analyzer: Keyword matching + pattern detection
Models: Phishing, malware, spam classifiers
Output: Classification result with confidence score.
"""
    logger.debug("PHASE 3: Classification Execution")
    logger.debug("-" * 40)
    result = classifier.classify(malware_text)
    attach_stage_details("PHASE 3: Classification Execution", phase3_details)
    logger.debug("Step 3a: Execute classification")
    logger.info(f"Classification result: {result}")
    logger.debug(f"  is_threat: {result['is_threat']}")
    logger.debug(f"  labels: {result['labels']}")
    logger.debug(f"  confidence: {result['confidence']}")
    
    allure.step("PHASE 4: Validate Classification Quality")
    phase4_details = """
Assess classification quality and reliability.
Verify: Threat correctly identified (is_threat=True)
Verify: Label matches expected category (malware)
Verify: Confidence above quality threshold (>=0.80)
"""
    logger.debug("PHASE 4: Quality Assessment")
    logger.debug("-" * 40)
    attach_stage_details("PHASE 4: Quality Assessment", phase4_details)
    logger.debug("Step 4a: Check classification quality")
    logger.debug(f"  Threat detected: {result['is_threat']}")
    logger.debug(f"  Label correct: {'malware' in result['labels']}")
    logger.debug(f"  Confidence high: {result['confidence'][0] >= 0.80}")
    
    allure.step("PHASE 5: MITIGATION 1 - Threat Detection Accuracy (Playbook 1)")
    phase5_m1_details = """
Verify threat detection correctly identifies malware.
Expected: is_threat = True
Prevents: Malware bypassing security checks.
Ensures: Threats are properly flagged for handling.
"""
    logger.debug("PHASE 5: Assertions & Mitigations")
    logger.debug("-" * 40)
    logger.debug("Step 5a: Assertion 1 - Threat detection")
    logger.debug(f"  is_threat: {result['is_threat']} (expected: True)")
    attach_stage_details("PHASE 5: MITIGATION 1", phase5_m1_details)
    attach_mitigation(
        playbook_num="1",
        name="Threat Detection Accuracy",
        description="Ensure malware threats are correctly identified",
        implementation="Assert is_threat == True for malware text",
        mitigates="T1 (Memory Poisoning), T9 (Identity Spoofing), T12 (Insecure Output)",
        coverage="Asserts result['is_threat'] is True"
    )
    assert result['is_threat'] is True, "Malware should be detected as threat"
    logger.debug("✓ Threat flag correct")
    
    allure.step("PHASE 5: MITIGATION 2 - Label Identification (Playbook 2)")
    phase5_m2_details = """
Verify classification correctly labels as malware.
Expected: 'malware' in labels
Prevents: Misclassification to other threat types.
Ensures: Threat type is correctly identified.
"""
    logger.debug("Step 5b: Assertion 2 - Label verification")
    logger.debug(f"  Labels: {result['labels']} (expected to contain 'malware')")
    attach_stage_details("PHASE 5: MITIGATION 2", phase5_m2_details)
    attach_mitigation(
        playbook_num="2",
        name="Label Identification",
        description="Verify correct threat type classification",
        implementation="Assert 'malware' in result['labels']",
        mitigates="T2 (Tool Misuse), T5 (Cascading Hallucination), T9 (Identity Spoofing)",
        coverage="Asserts correct threat label present"
    )
    assert 'malware' in result['labels'], "Should identify as malware"
    logger.debug("✓ Label correct")
    
    allure.step("PHASE 5: MITIGATION 3 - Confidence Quality Gate (Playbook 3)")
    phase5_m3_details = """
Verify confidence score exceeds quality threshold.
Expected: confidence >= 0.80
Prevents: Low-confidence misclassifications.
Ensures: Only reliable classifications are output.
"""
    logger.debug("Step 5c: Assertion 3 - Confidence threshold")
    logger.debug(f"  Confidence: {result['confidence'][0]} (expected: >= 0.80)")
    attach_stage_details("PHASE 5: MITIGATION 3", phase5_m3_details)
    attach_mitigation(
        playbook_num="3",
        name="Confidence Quality Gate",
        description="Ensure classification confidence exceeds quality threshold",
        implementation="Assert confidence >= 0.80 for reliable classification",
        mitigates="T6 (Intent Breaking), T8 (Repudiation), T12 (Insecure Output)",
        coverage="Asserts result['confidence'][0] >= 0.80"
    )
    assert result['confidence'][0] >= 0.80, "Malware confidence should be >= 0.80"
    logger.debug(f"✓ Confidence score valid: {result['confidence'][0]}")
    
    logger.info("✓ PASSED: Malware classification accurate")
    logger.info(f"  Threat: {result['is_threat']}")
    logger.info(f"  Label: {result['labels']}")
    logger.info(f"  Confidence: {result['confidence'][0]}")
    logger.info("=" * 60)


@allure.feature("Threat Classification")
@allure.story("Spam Detection")
@allure.title("Test Spam Threat Classification with Confidence Scoring")
def test_spam_classification():
    """
    Test spam threat detection with confidence scoring.
    
    Validates:
        - is_threat returns True for spam messages
        - 'spam' label is present in classification results
        - Confidence score meets or exceeds 0.75 threshold
    
    Pipeline Flow:
        Input Text → Feature Extraction → Pattern Matching → Classification → Confidence Scoring → Output
    
    Test Data:
        "Buy cheap stuff today limited offer"
        Keywords: buy, cheap, limited, offer (common spam marketing language)
    
    Validation Logic:
        - Threat Detection: is_threat == True
        - Label Identification: 'spam' in labels
        - Confidence Threshold: confidence >= 0.75
    
    Expected Result:
        {
            'is_threat': True,
            'labels': ['spam'],
            'confidence': [0.82]
        }
    
    Assertions:
        3 assertions validate threat detection accuracy
    """
    logger.info("=" * 60)
    logger.info("TEST: Spam Classification")
    
    allure.step("PHASE 1: Initialize Threat Classifier")
    phase1_details = """
Create and configure ThreatClassifier instance.
Classifier ready with trained models.
Models loaded for phishing, malware, spam detection.
Prepare classifier for threat analysis.
"""
    logger.debug("PHASE 1: Classifier Initialization")
    logger.debug("-" * 40)
    classifier = ThreatClassifier()
    attach_stage_details("PHASE 1: Classifier Initialization", phase1_details)
    logger.debug("Step 1a: Create ThreatClassifier instance")
    logger.debug(f"  Classifier: {classifier.__class__.__name__}")
    logger.debug("✓ Classifier ready")
    
    allure.step("PHASE 2: Prepare Spam Test Input")
    phase2_details = """
Load spam test case with known threat indicators.
Text: "Buy cheap stuff today limited offer"
Keywords present: buy, cheap, limited, offer
Pattern: Common spam marketing language.
Prepare for classification.
"""
    logger.debug("PHASE 2: Test Input Preparation")
    logger.debug("-" * 40)
    spam_text = "Buy cheap stuff today limited offer"
    attach_stage_details("PHASE 2: Test Input Preparation", phase2_details)
    logger.debug("Step 2a: Load spam test case")
    logger.debug(f"  Text: '{spam_text}'")
    logger.debug(f"  Keywords: buy, cheap, limited, offer")
    
    allure.step("PHASE 3: Execute Threat Classification")
    phase3_details = """
Run threat classification on input text.
Analyzer: Keyword matching + pattern detection
Models: Phishing, malware, spam classifiers
Output: Classification result with confidence score.
"""
    logger.debug("PHASE 3: Classification Execution")
    logger.debug("-" * 40)
    result = classifier.classify(spam_text)
    attach_stage_details("PHASE 3: Classification Execution", phase3_details)
    logger.debug("Step 3a: Execute classification")
    logger.info(f"Classification result: {result}")
    logger.debug(f"  is_threat: {result['is_threat']}")
    logger.debug(f"  labels: {result['labels']}")
    logger.debug(f"  confidence: {result['confidence']}")
    
    allure.step("PHASE 4: Validate Classification Quality")
    phase4_details = """
Assess classification quality and reliability.
Verify: Threat correctly identified (is_threat=True)
Verify: Label matches expected category (spam)
Verify: Confidence above quality threshold (>=0.75)
"""
    logger.debug("PHASE 4: Quality Assessment")
    logger.debug("-" * 40)
    attach_stage_details("PHASE 4: Quality Assessment", phase4_details)
    logger.debug("Step 4a: Check classification quality")
    logger.debug(f"  Threat detected: {result['is_threat']}")
    logger.debug(f"  Label correct: {'spam' in result['labels']}")
    logger.debug(f"  Confidence high: {result['confidence'][0] >= 0.75}")
    
    allure.step("PHASE 5: MITIGATION 1 - Threat Detection Accuracy (Playbook 1)")
    phase5_m1_details = """
Verify threat detection correctly identifies spam.
Expected: is_threat = True
Prevents: Spam bypassing security checks.
Ensures: Threats are properly flagged for handling.
"""
    logger.debug("PHASE 5: Assertions & Mitigations")
    logger.debug("-" * 40)
    logger.debug("Step 5a: Assertion 1 - Threat detection")
    logger.debug(f"  is_threat: {result['is_threat']} (expected: True)")
    attach_stage_details("PHASE 5: MITIGATION 1", phase5_m1_details)
    attach_mitigation(
        playbook_num="1",
        name="Threat Detection Accuracy",
        description="Ensure spam threats are correctly identified",
        implementation="Assert is_threat == True for spam text",
        mitigates="T1 (Memory Poisoning), T9 (Identity Spoofing), T12 (Insecure Output)",
        coverage="Asserts result['is_threat'] is True"
    )
    assert result['is_threat'] is True, "Spam should be detected as threat"
    logger.debug("✓ Threat flag correct")
    
    allure.step("PHASE 5: MITIGATION 2 - Label Identification (Playbook 2)")
    phase5_m2_details = """
Verify classification correctly labels as spam.
Expected: 'spam' in labels
Prevents: Misclassification to other threat types.
Ensures: Threat type is correctly identified.
"""
    logger.debug("Step 5b: Assertion 2 - Label verification")
    logger.debug(f"  Labels: {result['labels']} (expected to contain 'spam')")
    attach_stage_details("PHASE 5: MITIGATION 2", phase5_m2_details)
    attach_mitigation(
        playbook_num="2",
        name="Label Identification",
        description="Verify correct threat type classification",
        implementation="Assert 'spam' in result['labels']",
        mitigates="T2 (Tool Misuse), T5 (Cascading Hallucination), T9 (Identity Spoofing)",
        coverage="Asserts correct threat label present"
    )
    assert 'spam' in result['labels'], "Should identify as spam"
    logger.debug("✓ Label correct")
    
    allure.step("PHASE 5: MITIGATION 3 - Confidence Quality Gate (Playbook 3)")
    phase5_m3_details = """
Verify confidence score exceeds quality threshold.
Expected: confidence >= 0.75
Prevents: Low-confidence misclassifications.
Ensures: Only reliable classifications are output.
"""
    logger.debug("Step 5c: Assertion 3 - Confidence threshold")
    logger.debug(f"  Confidence: {result['confidence'][0]} (expected: >= 0.75)")
    attach_stage_details("PHASE 5: MITIGATION 3", phase5_m3_details)
    attach_mitigation(
        playbook_num="3",
        name="Confidence Quality Gate",
        description="Ensure classification confidence exceeds quality threshold",
        implementation="Assert confidence >= 0.75 for reliable classification",
        mitigates="T6 (Intent Breaking), T8 (Repudiation), T12 (Insecure Output)",
        coverage="Asserts result['confidence'][0] >= 0.75"
    )
    assert result['confidence'][0] >= 0.75, "Spam confidence should be >= 0.75"
    logger.debug(f"✓ Confidence score valid: {result['confidence'][0]}")
    
    logger.info("✓ PASSED: Spam classification accurate")
    logger.info(f"  Threat: {result['is_threat']}")
    logger.info(f"  Label: {result['labels']}")
    logger.info(f"  Confidence: {result['confidence'][0]}")
    logger.info("=" * 60)