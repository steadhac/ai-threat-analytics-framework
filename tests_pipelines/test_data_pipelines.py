def test_data_validation():
    """Test data validation and cleaning"""
    raw_data = [
        {'id': 1, 'value': 100, 'status': 'valid'},
        {'id': 2, 'value': None, 'status': 'invalid'},
        {'id': 3, 'value': 200, 'status': 'valid'}
    ]
    
    # Filter valid records
    valid_data = [d for d in raw_data if d['status'] == 'valid' and d['value'] is not None]
    
    assert len(valid_data) == 2
    assert all(d['value'] is not None for d in valid_data)