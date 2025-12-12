# core/security_checks.py
"""
Security validation utilities for AI systems.
Includes PII detection, data leakage checks, and guardrail validation.
"""
import re
from typing import List, Dict, Any, Tuple
import hashlib


# PII patterns
PII_PATTERNS = {
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'api_key': r'\b[A-Za-z0-9_-]{32,}\b',
}


def contains_pii(text: str) -> bool:
    """
    Check if text contains Personally Identifiable Information (PII).
    
    Args:
        text: Text to check
        
    Returns:
        True if PII detected
    """
    if not text:
        return False
    
    for pattern_name, pattern in PII_PATTERNS.items():
        if re.search(pattern, text):
            return True
    
    return False


def detect_pii_detailed(text: str) -> List[Dict[str, Any]]:
    """
    Detect and return detailed PII findings.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of PII findings with type and redacted value
    """
    findings = []
    
    for pattern_name, pattern in PII_PATTERNS.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            findings.append({
                'type': pattern_name,
                'value': match.group(0),
                'start': match.start(),
                'end': match.end(),
                'redacted': redact_sensitive_data(match.group(0))
            })
    
    return findings


def redact_sensitive_data(text: str) -> str:
    """
    Redact sensitive data from text.
    
    Args:
        text: Text containing sensitive data
        
    Returns:
        Redacted text
    """
    for pattern_name, pattern in PII_PATTERNS.items():
        text = re.sub(pattern, f'[REDACTED_{pattern_name.upper()}]', text)
    
    return text


def check_prompt_injection(prompt: str) -> Tuple[bool, str]:
    """
    Check if prompt contains injection attempts.
    
    Args:
        prompt: User prompt to check
        
    Returns:
        Tuple of (is_malicious, reason)
    """
    # Injection patterns
    injection_patterns = [
        (r'ignore\s+(all\s+)?previous\s+instructions?', 'instruction_override'),
        (r'reveal\s+(password|credential|secret|token|key)', 'credential_request'),
        (r'(admin|root|system)\s+(password|credential|access)', 'privilege_escalation'),
        (r'<script|javascript:', 'xss_attempt'),
        (r'(union\s+select|drop\s+table|delete\s+from)', 'sql_injection'),
        (r'(tell|show)\s+me\s+(anything|everything)\s+about', 'data_exfiltration'),
        (r'bypass\s+(security|policy|restriction|limit)', 'security_bypass'),
        (r'\$\{.*\}|%\{.*\}', 'template_injection'),
    ]
    
    prompt_lower = prompt.lower()
    
    for pattern, reason in injection_patterns:
        if re.search(pattern, prompt_lower):
            return True, reason
    
    return False, "safe"


def validate_model_access(model_id: str, allowed_models: List[str]) -> bool:
    """
    Validate if model access is allowed.
    
    Args:
        model_id: Model identifier being accessed
        allowed_models: List of allowed model IDs
        
    Returns:
        True if access is allowed
    """
    return model_id in allowed_models


def check_data_leakage(training_data: List[str], test_data: List[str]) -> Dict[str, Any]:
    """
    Check for data leakage between training and test sets.
    
    Args:
        training_data: Training dataset samples
        test_data: Test dataset samples
        
    Returns:
        Leakage analysis results
    """
    # Create hashes for faster comparison
    training_hashes = {hashlib.md5(sample.encode()).hexdigest() for sample in training_data}
    test_hashes = {hashlib.md5(sample.encode()).hexdigest() for sample in test_data}
    
    # Find duplicates
    duplicates = training_hashes.intersection(test_hashes)
    leakage_count = len(duplicates)
    leakage_ratio = leakage_count / len(test_data) if test_data else 0
    
    return {
        'has_leakage': leakage_count > 0,
        'leakage_count': leakage_count,
        'leakage_ratio': leakage_ratio,
        'total_training': len(training_data),
        'total_test': len(test_data)
    }


def validate_encryption(data: bytes, expected_algorithm: str = 'AES-256') -> bool:
    """
    Validate that data appears to be properly encrypted.
    
    Args:
        data: Data bytes to check
        expected_algorithm: Expected encryption algorithm
        
    Returns:
        True if data appears encrypted
    """
    if not data:
        return False
    
    # Check entropy (encrypted data should have high entropy)
    entropy = calculate_entropy(data)
    
    # Encrypted data typically has entropy > 7.5 (out of 8)
    return entropy > 7.5


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    
    Args:
        data: Data bytes
        
    Returns:
        Entropy value (0-8)
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    
    for count in byte_counts:
        if count > 0:
            probability = count / data_len
            entropy -= probability * (probability.bit_length() - 1)
    
    return entropy


def check_token_exposure(text: str) -> List[str]:
    """
    Check for exposed authentication tokens in text.
    
    Args:
        text: Text to scan
        
    Returns:
        List of potentially exposed tokens
    """
    token_patterns = [
        r'Bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',  # JWT
        r'sk-[A-Za-z0-9]{32,}',  # API keys
        r'[A-Za-z0-9_-]{40,}',  # Generic long tokens
    ]
    
    exposed_tokens = []
    
    for pattern in token_patterns:
        matches = re.findall(pattern, text)
        exposed_tokens.extend(matches)
    
    return exposed_tokens


def validate_guardrails(response: Dict[str, Any], required_guardrails: List[str]) -> Dict[str, bool]:
    """
    Validate that required guardrails are present in API response.
    
    Args:
        response: API response dictionary
        required_guardrails: List of required guardrail indicators
        
    Returns:
        Dictionary mapping guardrail names to validation status
    """
    results = {}
    
    for guardrail in required_guardrails:
        if guardrail == "content_filter":
            results[guardrail] = response.get("content_filtered", False) or \
                                response.get("safety_check", False)
        elif guardrail == "rate_limit":
            results[guardrail] = "rate_limit" in response or "x-rate-limit" in response
        elif guardrail == "audit_log":
            results[guardrail] = response.get("audit_logged", False) or \
                                response.get("request_id") is not None
        else:
            results[guardrail] = guardrail in response
    
    return results
