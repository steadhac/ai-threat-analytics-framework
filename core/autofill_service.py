class AutofillService:
    """AI-powered autofill suggestions"""
    
    def suggest(self, field, context):
        """Generate autofill suggestions based on field type and context"""
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
        
        return {
            'suggestions': suggestions.get(field, []),
            'confidence': 0.85
        }