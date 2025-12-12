from core.summarizer import ThreatSummarizer


def test_threat_report_summarization():
    """Test AI summarizes threat reports"""
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