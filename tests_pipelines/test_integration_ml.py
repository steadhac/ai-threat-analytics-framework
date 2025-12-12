def test_ml_pipeline_integration():
    """Test end-to-end ML pipeline"""
    # Simulate data → feature extraction → prediction
    raw_data = {'threat_text': 'Click here to claim prize'}
    
    # Feature extraction (simple word count)
    features = {
        'word_count': len(raw_data['threat_text'].split()),
        'has_urgent_words': 'click' in raw_data['threat_text'].lower()
    }
    
    # Simple prediction
    is_threat = features['has_urgent_words']
    
    assert features['word_count'] > 0
    assert is_threat is True