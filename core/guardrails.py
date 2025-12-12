import re


class LLMGuardrails:
    """Real LLM security guardrails"""
    
    def validate_input(self, text):
        """Validate user input for security threats"""
        threats = []
        
        # Check for prompt injection
        prompt_patterns = [
            r'ignore\s+(previous|all)\s+instructions',
            r'disregard\s+all\s+rules',
            r'reveal\s+system\s+prompt'
        ]
        for pattern in prompt_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append('prompt_injection')
                break
        
        # Check for code injection
        code_patterns = [r'<script.*?>', r'javascript:', r'onerror=']
        for pattern in code_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append('code_injection')
                break
        
        # Check for SQL injection
        sql_patterns = [r"'.*OR.*=", r'DROP\s+TABLE', r';\s*DELETE']
        for pattern in sql_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append('sql_injection')
                break
        
        return {
            'is_safe': len(threats) == 0,
            'threats_detected': threats
        }
    
    def sanitize_output(self, text):
        """Remove PII from output"""
        # Email pattern
        text = re.sub(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            '[EMAIL_REDACTED]',
            text
        )
        
        # SSN pattern
        text = re.sub(
            r'\b\d{3}-\d{2}-\d{4}\b',
            '[SSN_REDACTED]',
            text
        )
        
        # Phone pattern
        text = re.sub(
            r'\b\d{3}-\d{3}-\d{4}\b',
            '[PHONE_REDACTED]',
            text
        )
        
        return {
            'sanitized_text': text,
            'pii_removed': '[REDACTED]' in text
        }