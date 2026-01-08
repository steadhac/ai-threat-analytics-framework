"""
Autofill Service Tests


Tests for the AutofillService suggestion generation. Verifies that the
service generates correct email, phone, and address suggestions based
on user input context.
"""

from core.autofill_service import AutofillService


def test_autofill_email_suggestions():
    """
    Test that email suggestions are generated with correct domains.
    
    Verifies:
    - Exactly 3 email suggestions generated
    - All suggestions contain @ symbol (valid email format)
    - Confidence score above 0.5 threshold
    - Gmail domain is included in suggestions
    
    Example:
        Input: context='user'
        Output: ['user@gmail.com', 'user@company.com', 'user@outlook.com']
    
    Assertions:
    - len(suggestions) == 3: Expects 3 domain variants per context
    - all('@' in email): Validates email format
    - confidence > 0.5: Ensures confidence is meaningful
    - 'user@gmail.com' in suggestions: Gmail is most common provider
    """
    service = AutofillService()
    result = service.suggest(field='email', context='user')
    
    assert len(result['suggestions']) == 3
    assert all('@' in email for email in result['suggestions'])
    assert result['confidence'] > 0.5
    assert 'user@gmail.com' in result['suggestions']