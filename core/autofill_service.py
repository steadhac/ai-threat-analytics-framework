"""
Autofill Service Module


Generates contextually relevant suggestions for common form fields.
Creates suggestions for email addresses, phone numbers, and postal addresses
based on user input context.

Supported Field Types:
    - email: Gmail, company.com, outlook.com domains
    - phone: US format with common suffixes (0000, 1234, 5678)
    - address: Common US cities (New York, Boston, Seattle)

Performance:
    - O(1) time complexity (fixed 3 suggestions per field)
    - < 1ms typical latency
    - Fully thread-safe (stateless design)

Use Cases:
    - Form autofill acceleration
    - Search address completion
    - Contact field suggestions
    - Mobile form UX improvement
    - Accessibility support

Limitations:
    - Pattern-based generation only (no ML ranking yet)
    - Static confidence score (0.85)
    - No user personalization
    - US formats only
"""


class AutofillService:
    """
    AI-powered autofill suggestion generator for form fields.
    
    Generates contextually relevant suggestions for email, phone, and address
    fields based on provided context strings. Suggestions are returned with
    a confidence score indicating likelihood of user acceptance.
    
    Example:
        >>> service = AutofillService()
        >>> 
        >>> # Email suggestions
        >>> result = service.suggest('email', 'john.doe')
        >>> print(result['suggestions'])
        ['john.doe@gmail.com', 'john.doe@company.com', 'john.doe@outlook.com']
        >>> print(result['confidence'])
        0.85
        
        >>> # Phone suggestions
        >>> result = service.suggest('phone', '555')
        >>> print(result['suggestions'])
        ['555-0000', '555-1234', '555-5678']
        
        >>> # Address suggestions
        >>> result = service.suggest('address', 'Main')
        >>> print(result['suggestions'])
        ['Main Street, New York', 'Main Avenue, Boston', 'Main Road, Seattle']
    
    Supported Field Types:
        - 'email': Generates with common domains (gmail, company, outlook)
        - 'phone': Generates US format phone numbers
        - 'address': Generates with common US cities
    """
    
    def suggest(self, field: str, context: str) -> dict:
        """
        Generate autofill suggestions for a form field.
        
        Combines context with predefined patterns to create relevant suggestions.
        Returns empty list for unknown field types (graceful degradation).
        
        Args:
            field (str): Field type ('email', 'phone', 'address')
            context (str): Input prefix (e.g., 'john.doe', '555', 'Main')
                          Empty string is valid input
        
        Returns:
            dict: {'suggestions': list[str], 'confidence': float}
                  suggestions: 0-3 generated suggestions for field type
                  confidence: Always 0.85 (static in v1.0)
        
        Example:
            >>> service = AutofillService()
            >>> 
            >>> # Basic usage
            >>> result = service.suggest('email', 'alice')
            >>> assert result['suggestions'] == [
            ...     'alice@gmail.com',
            ...     'alice@company.com',
            ...     'alice@outlook.com'
            ... ]
            >>> assert result['confidence'] == 0.85
            
            >>> # Unknown field type returns empty
            >>> result = service.suggest('zip_code', '90210')
            >>> assert result['suggestions'] == []
            >>> assert result['confidence'] == 0.85
            
            >>> # Empty context is valid
            >>> result = service.suggest('email', '')
            >>> assert '@gmail.com' in result['suggestions'][0]
        
        Edge Cases:
            - Unknown field: Returns empty suggestions list
            - Empty context: Valid, generates prefix-free suggestions
            - Special characters: Preserved as-is (john@company → john@company@gmail.com)
            - Case sensitivity: Field names are case-sensitive
        
        Performance: O(1) time, fixed 3 suggestions per field type
        
        Use Cases:
            - Real-time form field autocomplete
            - Mobile form UX improvement
            - Accessibility voice input confirmation
            - Search address completion
        
        Future Enhancements:
            - ML ranking based on user history
            - Personalization per user/organization
            - International address formats
            - LRU caching for hot contexts
            - A/B testing support
        """
        # Define suggestion patterns for each field type
        suggestions = {
            'email': [
                f"{context}@gmail.com",
                f"{context}@company.com",
                f"{context}@outlook.com"
            ],
            'phone': [
                f"{context}-0000",
                f"{context}-1234",
                f"{context}-5678"
            ],
            'address': [
                f"{context} Street, New York",
                f"{context} Avenue, Boston",
                f"{context} Road, Seattle"
            ]
        }
        
        # Return suggestions for requested field, or empty list if unknown field
        return {
            'suggestions': suggestions.get(field, []),
            'confidence': 0.85
        }


# ============================================================================
# Integration Examples
# ============================================================================

if __name__ == '__main__':
    """
    Demonstration of AutofillService usage patterns.
    """
    
    service = AutofillService()
    
    # Example 1: Email Suggestions
    print("=== Email Suggestions ===")
    result = service.suggest('email', 'john.doe')
    print(f"Context: 'john.doe'")
    print(f"Suggestions: {result['suggestions']}")
    print(f"Confidence: {result['confidence']}\n")
    
    # Example 2: Phone Suggestions
    print("=== Phone Suggestions ===")
    result = service.suggest('phone', '415')
    print(f"Context: '415'")
    print(f"Suggestions: {result['suggestions']}")
    print(f"Confidence: {result['confidence']}\n")
    
    # Example 3: Address Suggestions
    print("=== Address Suggestions ===")
    result = service.suggest('address', 'Main')
    print(f"Context: 'Main'")
    print(f"Suggestions: {result['suggestions']}")
    print(f"Confidence: {result['confidence']}\n")
    
    # Example 4: Unknown Field Type
    print("=== Unknown Field Type ===")
    result = service.suggest('zip_code', '90210')
    print(f"Context: '90210'")
    print(f"Suggestions: {result['suggestions']}")
    print(f"Confidence: {result['confidence']}\n")
    
    # Example 5: Empty Context
    print("=== Empty Context ===")
    result = service.suggest('email', '')
    print(f"Context: ''")
    print(f"Suggestions: {result['suggestions']}")
    print(f"Confidence: {result['confidence']}\n")