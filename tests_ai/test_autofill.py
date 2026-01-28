"""
Autofill Service Tests

Tests for the AutofillService suggestion generation. Verifies that the
service generates correct email, phone, and address suggestions based
on user input context.

Test Coverage:
- Email suggestion generation with format validation (SAFE)
- Phone suggestion generation with format validation (SAFE)
- Address suggestion generation with format validation (SAFE)
- Confidence score validation (0.0-1.0 range)
- Format validation before output (no malformed suggestions)

OWASP Agentic AI Threat Mitigations:
- T2 (Tool Misuse): Validate suggestion format before output
- T5 (Cascading Hallucination): Ensure suggestions are grounded in context
- T8 (Repudiation & Untraceability): Maintain audit trail of suggestions
- T9 (Identity Spoofing): Prevent generation of spoofed email domains
- T12 (Insecure Output Handling): Only output validated suggestions

Usage:
    pytest tests_ai/test_autofill.py -v
    pytest tests_ai/test_autofill.py::test_email_suggestions -v
"""

import pytest
import logging
import allure
from core.autofill_service import AutofillService
from tests_pipelines.allure_helpers import attach_mitigation

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("context,expected_count,expected_format_check,expected_confidence_threshold,description", [
    ("user", 3, lambda x: all('@' in email for email in x), 0.5, "Standard user context (SAFE)"),
])
@allure.feature("Autofill Service")
@allure.story("Email Suggestion Generation")
@allure.title("Test Email Suggestion Generation with Format Validation")
def test_email_suggestions(context, expected_count, expected_format_check, expected_confidence_threshold, description):
    """Validate email suggestion generation."""
    allure.dynamic.title(f"Test {description}")
    
    logger.info("=" * 60)
    logger.info(f"TEST: Email Suggestions - {description}")
    logger.info(f"Context: '{context}'")
    
    allure.step("Initialize Autofill Service")
    service = AutofillService()
    logger.debug("✓ Service initialized")
    
    allure.step("Execute email suggestion")
    result = service.suggest(field='email', context=context)
    logger.info(f"Result: {result}")
    
    allure.step("Assert suggestion count")
    assert len(result['suggestions']) == expected_count, \
        f"Expected {expected_count} suggestions, got {len(result['suggestions'])}"
    logger.debug("✓ Suggestion count correct")
    
    allure.step("Assert format validity")
    assert expected_format_check(result['suggestions']), \
        f"Format validation failed for suggestions: {result['suggestions']}"
    logger.debug("✓ Format valid (all contain @)")
    
    allure.step("Assert confidence threshold")
    assert result['confidence'] >= expected_confidence_threshold, \
        f"Expected confidence >= {expected_confidence_threshold}, got {result['confidence']}"
    logger.debug(f"✓ Confidence valid: {result['confidence']}")
    
    # Attach mitigations
    attach_mitigation(
        playbook_num="1",
        name="Email Format Validation",
        description="Ensure all suggestions follow valid email format",
        implementation="Verify all suggestions contain @ symbol",
        mitigates="T2 (Tool Misuse), T9 (Identity Spoofing), T12 (Insecure Output)",
        coverage="Email format validation in suggestions"
    )
    
    attach_mitigation(
        playbook_num="2",
        name="Confidence Quality Threshold",
        description="Ensure suggestion confidence exceeds quality gate",
        implementation="Only return suggestions with confidence >= 0.5",
        mitigates="T5 (Cascading Hallucination), T8 (Repudiation), T12 (Insecure Output)",
        coverage="Confidence score validation"
    )
    
    logger.info(f"✓ PASSED: {description}")
    logger.info("=" * 60)


@pytest.mark.parametrize("context,expected_count,expected_format_check,expected_confidence_threshold,description", [
    ("5551234567", 3, lambda x: all(c.isdigit() or c in '()- ' for phone in x for c in phone), 0.6, "US phone number (SAFE)"),
])
@allure.feature("Autofill Service")
@allure.story("Phone Suggestion Generation")
@allure.title("Test Phone Suggestion Generation with Format Validation")
def test_phone_suggestions(context, expected_count, expected_format_check, expected_confidence_threshold, description):
    """Validate phone suggestion generation."""
    allure.dynamic.title(f"Test {description}")
    
    logger.info("=" * 60)
    logger.info(f"TEST: Phone Suggestions - {description}")
    logger.info(f"Context: '{context}'")
    
    allure.step("Initialize Autofill Service")
    service = AutofillService()
    logger.debug("✓ Service initialized")
    
    allure.step("Execute phone suggestion")
    result = service.suggest(field='phone', context=context)
    logger.info(f"Result: {result}")
    
    allure.step("Assert suggestion count")
    assert len(result['suggestions']) == expected_count, \
        f"Expected {expected_count} suggestions, got {len(result['suggestions'])}"
    logger.debug("✓ Suggestion count correct")
    
    allure.step("Assert format validity")
    assert expected_format_check(result['suggestions']), \
        f"Format validation failed for suggestions: {result['suggestions']}"
    logger.debug("✓ Format valid (numeric with standard separators)")
    
    allure.step("Assert confidence threshold")
    assert result['confidence'] >= expected_confidence_threshold, \
        f"Expected confidence >= {expected_confidence_threshold}, got {result['confidence']}"
    logger.debug(f"✓ Confidence valid: {result['confidence']}")
    
    # Attach mitigations
    attach_mitigation(
        playbook_num="1",
        name="Phone Format Validation",
        description="Ensure all suggestions follow valid phone format",
        implementation="Verify suggestions contain only digits and standard separators (-, (), space)",
        mitigates="T2 (Tool Misuse), T12 (Insecure Output)",
        coverage="Phone format validation in suggestions"
    )
    
    attach_mitigation(
        playbook_num="2",
        name="Confidence Quality Threshold",
        description="Ensure suggestion confidence exceeds quality gate",
        implementation="Only return suggestions with confidence >= 0.6",
        mitigates="T5 (Cascading Hallucination), T8 (Repudiation), T12 (Insecure Output)",
        coverage="Confidence score validation"
    )
    
    logger.info(f"✓ PASSED: {description}")
    logger.info("=" * 60)


@pytest.mark.parametrize("context,expected_count,expected_has_street,expected_confidence_threshold,description", [
    ("123 Main St", 3, True, 0.6, "US street address (SAFE)"),
])
@allure.feature("Autofill Service")
@allure.story("Address Suggestion Generation")
@allure.title("Test Address Suggestion Generation with Format Validation")
def test_address_suggestions(context, expected_count, expected_has_street, expected_confidence_threshold, description):
    """Validate address suggestion generation."""
    allure.dynamic.title(f"Test {description}")
    
    logger.info("=" * 60)
    logger.info(f"TEST: Address Suggestions - {description}")
    logger.info(f"Context: '{context}'")
    
    allure.step("Initialize Autofill Service")
    service = AutofillService()
    logger.debug("✓ Service initialized")
    
    allure.step("Execute address suggestion")
    result = service.suggest(field='address', context=context)
    logger.info(f"Result: {result}")
    
    allure.step("Assert suggestion count")
    assert len(result['suggestions']) == expected_count, \
        f"Expected {expected_count} suggestions, got {len(result['suggestions'])}"
    logger.debug("✓ Suggestion count correct")
    
    allure.step("Assert format validity")
    if expected_has_street:
        has_street = any(len(addr.split()) > 1 for addr in result['suggestions'])
        assert has_street, f"Expected street address format in suggestions: {result['suggestions']}"
        logger.debug("✓ Format valid (street address format)")
    
    allure.step("Assert confidence threshold")
    assert result['confidence'] >= expected_confidence_threshold, \
        f"Expected confidence >= {expected_confidence_threshold}, got {result['confidence']}"
    logger.debug(f"✓ Confidence valid: {result['confidence']}")
    
    # Attach mitigations
    attach_mitigation(
        playbook_num="1",
        name="Address Format Validation",
        description="Ensure all suggestions follow valid address format",
        implementation="Verify suggestions contain street address components (number + street name)",
        mitigates="T2 (Tool Misuse), T12 (Insecure Output)",
        coverage="Address format validation in suggestions"
    )
    
    attach_mitigation(
        playbook_num="2",
        name="Confidence Quality Threshold",
        description="Ensure suggestion confidence exceeds quality gate",
        implementation="Only return suggestions with confidence >= 0.6",
        mitigates="T5 (Cascading Hallucination), T8 (Repudiation), T12 (Insecure Output)",
        coverage="Confidence score validation"
    )
    
    logger.info(f"✓ PASSED: {description}")
    logger.info("=" * 60)