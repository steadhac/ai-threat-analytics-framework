from core.threat_classifier import ThreatClassifier


def test_phishing_classification():
    """Test AI classifies phishing threats correctly"""
    classifier = ThreatClassifier()
    
    phishing_text = "Click here to claim your prize! Urgent action required."
    result = classifier.classify(phishing_text)
    
    assert result['is_threat'] is True
    assert 'phishing' in result['labels']
    assert result['confidence'][0] >= 0.85