from core.autofill_service import AutofillService


def test_autofill_email_suggestions():
    """Test AI autofill generates email suggestions"""
    service = AutofillService()
    
    result = service.suggest(field='email', context='user')
    
    assert len(result['suggestions']) == 3
    assert all('@' in email for email in result['suggestions'])
    assert result['confidence'] > 0.5
    assert 'user@gmail.com' in result['suggestions']