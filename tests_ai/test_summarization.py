"""
Threat Summarizer Tests

Tests for the ThreatSummarizer extractive summarization. Verifies that the
summarizer reduces verbose threat reports to essential information while
maintaining key details like threat type and compression ratio.

Test Coverage:
- Malware threat keywords preserved in summary 
- Phishing report compression works normally 
- Account compromise context lost in compression (GAP)
- Compression ratio validation
- Summary length constraint enforcement

OWASP Agentic AI Threat Mitigations:
- T2 (Tool Misuse): Ensure summarization preserves critical threat details
- T5 (Cascading Hallucination): Prevent critical information loss in summaries
- T8 (Repudiation & Untraceability): Maintain threat context in compressed output
- T12 (Insecure Output Handling): Validate summary quality before returning

Usage:
    pytest tests_ai/test_summarization.py -v
    pytest tests_ai/test_summarization.py::test_threat_summarization -v
"""

import pytest
import logging
import allure
from core.summarizer import ThreatSummarizer
from tests_pipelines.allure_helpers import attach_undetected_gap_with_mitigation

logger = logging.getLogger(__name__)

# Detection gaps for summarization testing
SUMMARIZATION_GAPS = [
    {
        "name": "Subtle Threat Context Loss",
        "input": "Report with implied threat that needs inference: 'Unusual login from unknown device. Account access pattern changed.'",
        "issue": "Extractive summarization removes contextual sentences, losing threat severity assessment",
        "suggestion": "Implement semantic preservation for threat context",
        "implementation": "Use abstractive summarization or smart sentence scoring to preserve threat implications",
        "priority": "HIGH",
        "steps": [
            {
                "step": "1. Analyze threat datasets", 
                "action": "Identify patterns where threat context is implicit. Example: 'Unusual login' + 'Pattern changed' together = compromise, but individually = normal. Build dataset of real threat reports that lose meaning when compressed."
            },
            {
                "step": "2. Implement smart sentence scoring", 
                "action": "Score sentences by threat importance, not just keyword presence. Don't count 'malware'=10 points. Instead measure how each sentence relates to the overall threat story. 'Failed auth' + 'Credential compromise' together = high threat because they connect."
            },
            {
                "step": "3. Use abstractive methods", 
                "action": "Consider AI language rewriting (transformer-based) to generate new summary sentences rather than copying existing ones. Instead of extracting 'Failed attempts. Possible compromise. Immediate action.' rewrite as 'Credential compromise likely from repeated failures - immediate action.' Same length, all threat context preserved."
            },
            {
                "step": "4. Test threat loss scenarios", 
                "action": "Validate that threat severity isn't reduced by compression. Run on edge cases where threats are subtle. Verify 'compromise' still appears after summarization. Build test suite with implicit threat patterns to prevent regressions."
            }
        ]
    }
]


@pytest.mark.parametrize("report,max_length,should_preserve_threat,expected_ratio_threshold,description", [
    (
        "Critical security incident: Multiple malware infections detected across enterprise network. Immediate containment required. IT team initiated incident response protocol.",
        100,
        True,
        0.75,
        "Malware threat keywords preserved in summary "
    ),
    (
        "A critical phishing attack was detected targeting enterprise users. The attack used sophisticated social engineering techniques. Multiple employees reported suspicious emails. The security team has implemented additional safeguards.",
        100,
        True,
        0.8,
        "Phishing report compression works normally "
    ),
    (
        "Unusual login from unknown device. Account access pattern changed. Multiple failed authentication attempts detected. Possible credential compromise. Immediate action required.",
        80,
        False,
        0.7,
        "Account compromise context lost in compression (GAP)"
    ),
])
@allure.feature("Threat Summarizer")
@allure.story("Report Summarization")
@allure.title("Test Threat Report Summarization with Quality Validation")
def test_threat_summarization(report, max_length, should_preserve_threat, expected_ratio_threshold, description):
    """Validate threat report summarization with compression and context preservation."""
    allure.dynamic.title(f"Test {description}")
    
    logger.info("=" * 60)
    logger.info(f"TEST: Threat Summarization - {description}")
    logger.info(f"Original length: {len(report)}, Max length: {max_length}")
    
    allure.step("Initialize Threat Summarizer")
    summarizer = ThreatSummarizer()
    logger.debug("✓ Summarizer initialized")
    
    allure.step("Execute summarization")
    result = summarizer.summarize(report, max_length=max_length)
    logger.info(f"Summary: {result['summary']}")
    logger.info(f"Summary length: {result['summary_length']}")
    logger.info(f"Compression ratio: {result['compression_ratio']:.2f}")
    
    allure.step("Assert length constraint")
    assert result['summary_length'] <= max_length, \
        f"Summary exceeds max_length: {result['summary_length']} > {max_length}"
    logger.debug("✓ Length constraint satisfied")
    
    allure.step("Assert compression achieved")
    if result['original_length'] > max_length:
        assert result['summary_length'] < result['original_length'], \
            f"Summary not compressed: {result['summary_length']} >= {result['original_length']}"
        logger.debug("✓ Compression achieved")
    else:
        logger.debug(f"ℹ Report fits within limit ({result['original_length']} <= {max_length}), no compression needed")
    
    allure.step("Assert compression ratio")
    if result['original_length'] > max_length:
        assert result['compression_ratio'] < expected_ratio_threshold, \
            f"Compression ratio too high: {result['compression_ratio']:.2f} >= {expected_ratio_threshold}"
        logger.debug(f"✓ Compression ratio valid: {result['compression_ratio']:.2f}")
    else:
        logger.debug(f"ℹ Report fits within limit, no compression needed: {result['compression_ratio']:.2f}")
    
    if should_preserve_threat:
        allure.step("Assert threat keyword preserved")
        summary_lower = result['summary'].lower()
        threat_preserved = any(keyword in summary_lower for keyword in ['phishing', 'attack', 'detected', 'suspicious', 'threat', 'malware'])
        assert threat_preserved, \
            f"Threat keyword not preserved in summary: {result['summary']}"
        logger.debug("✓ Threat keyword preserved")
    
    logger.info(f"✓ PASSED: {description}")
    logger.info("=" * 60)
    
    allure.step("Display Summarization Results")
    results_text = f"""
ORIGINAL REPORT ({result['original_length']} chars):
{report}

GENERATED SUMMARY ({result['summary_length']} chars):
{result['summary']}

COMPRESSION METRICS:
- Compression ratio: {result['compression_ratio']:.2f}
- Characters reduced: {result['original_length'] - result['summary_length']}
- Threat keywords preserved: {should_preserve_threat}
"""
    allure.attach(results_text, name="Summarization Results", attachment_type=allure.attachment_type.TEXT)
    
    # Attach gaps for context loss cases
    if "context lost" in description:
        for gap in SUMMARIZATION_GAPS:
            attach_undetected_gap_with_mitigation(
                pattern_name=gap["name"],
                malicious_input=gap["input"],
                issue=gap["issue"],
                suggestion=gap["suggestion"],
                implementation=gap["implementation"],
                priority=gap["priority"],
                mitigation_steps=gap["steps"]
            )