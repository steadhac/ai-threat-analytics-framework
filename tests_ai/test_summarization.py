"""
Threat Summarizer Tests


Tests for the ThreatSummarizer extractive summarization. Verifies that the
summarizer reduces verbose threat reports to essential information while
maintaining key details like threat type and compression ratio.
"""

from core.summarizer import ThreatSummarizer


def test_threat_report_summarization():
    """
    Test that threat reports are summarized within length constraints.
    
    Verifies:
    - Summary length does not exceed max_length parameter
    - Summary is shorter than original report
    - Compression ratio is less than 1.0 (reduction achieved)
    - Key threat type keyword preserved in summary
    
    Example:
        Input: Long 200+ character threat report
        max_length: 100 characters
        Output: Compressed summary with key threat details
        
    Assertions:
    - result['summary_length'] <= 100: Enforces length limit
    - summary_length < original_length: Confirms compression occurred
    - compression_ratio < 1.0: Validates compression ratio metric
    - 'phishing' in summary: Ensures threat type preserved
    
    Algorithm:
        Extractive summarization (greedy sentence selection):
        1. Split report into sentences
        2. Add sentences in order until reaching max_length
        3. Return first N sentences that fit limit
        
    Expected Behavior:
        - Report includes threat type: "phishing attack detected"
        - Report includes response: "security team has implemented"
        - Summary captures first sentences up to 100 chars
        - Threat type keyword preserved in summary
    """
    summarizer = ThreatSummarizer()
    
    long_report = """
    A critical phishing attack was detected targeting enterprise users. 
    The attack used sophisticated social engineering techniques. 
    Multiple employees reported suspicious emails. 
    The security team has implemented additional safeguards.
    """
    
    result = summarizer.summarize(long_report, max_length=100)
    
    assert result['summary_length'] <= 100
    assert result['summary_length'] < result['original_length']
    assert result['compression_ratio'] < 1.0
    assert 'phishing' in result['summary'].lower()