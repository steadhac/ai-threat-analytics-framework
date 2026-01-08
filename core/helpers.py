"""
Helpers Module


Utility functions for text processing, data transformation, JSON handling,
and resilience patterns. Provides common operations across the threat analytics
framework including string manipulation, data validation, schema checking,
timestamp parsing, and retry logic with exponential backoff.

Core Utilities:
    - Text Processing: normalize_text(), truncate_text(), fuzzy_match()
    - JSON Handling: parse_json_safe(), extract_json_from_text()
    - Data Transformation: flatten_dict(), compare_dicts(), batch_list()
    - Validation: validate_schema()
    - Time Parsing: parse_timestamp()
    - Resilience: retry_with_backoff() decorator

Performance:
    - All functions O(n) linear time complexity
    - No external dependencies beyond stdlib
    - Suitable for preprocessing pipelines and data validation

Integration Points:
    - Used by threat_classifier.py for text normalization
    - Used by security_checks.py for JSON parsing and schema validation
    - Used by api_client.py and throughout framework for retry logic
"""

import json
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
from difflib import SequenceMatcher
from functools import wraps
import time


def normalize_text(text: str, lowercase: bool = True, remove_punctuation: bool = False) -> str:
    """
    Normalize text by removing extra whitespace and optionally converting case.
    
    Performs whitespace normalization (multiple spaces → single space), handles
    newlines/tabs, and optionally converts to lowercase and removes punctuation.
    Useful preprocessing for threat classification and text comparison.
    
    Args:
        text (str): Input text to normalize
        lowercase (bool): Convert to lowercase (default: True)
        remove_punctuation (bool): Remove punctuation marks (default: False)
    
    Returns:
        str: Normalized text
    
    Example:
        >>> normalize_text("Hello   WORLD!")
        'hello world!'
        >>> normalize_text("Test\n\nMuliple   Spaces", lowercase=False)
        'Test Muliple Spaces'
    """
    # Collapse whitespace
    text = ' '.join(text.split())
    
    if lowercase:
        text = text.lower()
    
    if remove_punctuation:
        text = re.sub(r'[^\w\s]', '', text)
    
    return text


def fuzzy_match(str1: str, str2: str, threshold: float = 0.8) -> bool:
    """
    Check if two strings match with similarity above threshold.
    
    Uses Ratcliff/Obershelp algorithm (SequenceMatcher) to compute similarity
    ratio. Returns True if similarity >= threshold. Useful for detecting similar
    threat patterns or matching user inputs with known attack signatures.
    
    Args:
        str1 (str): First string
        str2 (str): Second string
        threshold (float): Similarity threshold 0.0-1.0 (default: 0.8)
    
    Returns:
        bool: True if similarity >= threshold
    
    Example:
        >>> fuzzy_match("phishing", "phising", threshold=0.8)
        True
        >>> fuzzy_match("malware", "benign", threshold=0.8)
        False
    """
    ratio = SequenceMatcher(None, str1, str2).ratio()
    return ratio >= threshold


def fuzzy_similarity(str1: str, str2: str) -> float:
    """
    Compute similarity ratio between two strings (0.0-1.0).
    
    Returns exact similarity score without threshold. Useful for ranking
    matches or displaying confidence scores.
    
    Args:
        str1 (str): First string
        str2 (str): Second string
    
    Returns:
        float: Similarity ratio 0.0-1.0
    
    Example:
        >>> fuzzy_similarity("test", "test")
        1.0
        >>> fuzzy_similarity("abc", "abd")
        0.667
    """
    return SequenceMatcher(None, str1, str2).ratio()


def parse_json_safe(text: str, default: Any = None) -> Any:
    """
    Safely parse JSON with fallback to default value on error.
    
    Attempts JSON parsing; returns default value (None by default) if parsing
    fails. Useful for handling untrusted JSON input without raising exceptions.
    
    Args:
        text (str): JSON string to parse
        default (Any): Value to return on parse error (default: None)
    
    Returns:
        Any: Parsed JSON object or default value
    
    Example:
        >>> parse_json_safe('{"key": "value"}')
        {'key': 'value'}
        >>> parse_json_safe('invalid json', default={})
        {}
    """
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default


def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """
    Extract first JSON object from mixed text content.
    
    Uses regex to find JSON-like patterns and attempts parsing. Returns first
    valid JSON object found, or None if no valid JSON. Useful for extracting
    structured data from LLM responses or log entries.
    
    Args:
        text (str): Text potentially containing JSON
    
    Returns:
        dict: First JSON object found, or None
    
    Example:
        >>> extract_json_from_text('Found threat: {"type": "phishing"}')
        {'type': 'phishing'}
    """
    # Find potential JSON objects (curly braces)
    json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
    matches = re.finditer(json_pattern, text)
    
    for match in matches:
        result = parse_json_safe(match.group())
        if result is not None:
            return result
    
    return None


def flatten_dict(nested_dict: Dict, parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """
    Flatten nested dictionary using dot notation for keys.
    
    Recursively flattens nested dicts into single-level dict with dot-separated
    keys. Useful for converting nested configs/logs into flat structures for
    CSV export or database storage.
    
    Args:
        nested_dict (dict): Nested dictionary
        parent_key (str): Parent key prefix (internal use)
        sep (str): Separator for nested keys (default: '.')
    
    Returns:
        dict: Flattened dictionary with dot-separated keys
    
    Example:
        >>> nested = {"threat": {"type": "phishing", "score": 0.92}}
        >>> flatten_dict(nested)
        {'threat.type': 'phishing', 'threat.score': 0.92}
    """
    items = []
    for k, v in nested_dict.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def compare_dicts(dict1: Dict, dict2: Dict) -> Dict[str, Any]:
    """
    Compare two dictionaries and return added, removed, and modified keys.
    
    Returns structure: {"added": {...}, "removed": {...}, "modified": {...}}
    Useful for detecting configuration changes, audit logs, or version diffs.
    
    Args:
        dict1 (dict): First dictionary
        dict2 (dict): Second dictionary
    
    Returns:
        dict: Differences with 'added', 'removed', 'modified' keys
    
    Example:
        >>> old = {"a": 1, "b": 2}
        >>> new = {"a": 1, "c": 3}
        >>> compare_dicts(old, new)
        {'added': {'c': 3}, 'removed': {'b': 2}, 'modified': {}}
    """
    added = {k: v for k, v in dict2.items() if k not in dict1}
    removed = {k: v for k, v in dict1.items() if k not in dict2}
    modified = {
        k: {'old': dict1[k], 'new': dict2[k]} 
        for k in dict1 if k in dict2 and dict1[k] != dict2[k]
    }
    
    return {'added': added, 'removed': removed, 'modified': modified}


def validate_schema(data: Any, schema: Dict[str, type]) -> Tuple[bool, List[str]]:
    """
    Validate data against schema (dict of key: type mappings).
    
    Checks if data is dict with required keys having correct types.
    Returns (is_valid, error_list). Useful for input validation before
    processing threat data or API requests.
    
    Args:
        data (Any): Data to validate
        schema (dict): Schema as {key: expected_type, ...}
    
    Returns:
        tuple: (is_valid, error_list)
    
    Example:
        >>> schema = {"text": str, "score": float}
        >>> validate_schema({"text": "threat", "score": 0.9}, schema)
        (True, [])
        >>> validate_schema({"text": "threat"}, schema)
        (False, ['Missing key: score'])
    """
    errors = []
    
    if not isinstance(data, dict):
        return False, ["Data must be a dictionary"]
    
    for key, expected_type in schema.items():
        if key not in data:
            errors.append(f"Missing key: {key}")
        elif not isinstance(data[key], expected_type):
            errors.append(f"Key '{key}': expected {expected_type.__name__}, got {type(data[key]).__name__}")
    
    return len(errors) == 0, errors


def truncate_text(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate text to maximum length with optional suffix.
    
    Returns original text if shorter than max_length; otherwise truncates
    and appends suffix. Useful for logging long threat reports or API responses.
    
    Args:
        text (str): Text to truncate
        max_length (int): Maximum length including suffix (default: 100)
        suffix (str): Text to append when truncated (default: '...')
    
    Returns:
        str: Truncated text
    
    Example:
        >>> truncate_text("This is a long threat report...", max_length=20)
        'This is a long th...'
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse timestamp string in multiple formats.
    
    Attempts to parse common ISO 8601 and Unix formats. Returns datetime object
    or None if parsing fails. Supports 5 common formats.
    
    Args:
        timestamp_str (str): Timestamp string
    
    Returns:
        datetime: Parsed datetime or None
    
    Example:
        >>> parse_timestamp("2026-01-08T15:30:00Z")
        datetime.datetime(2026, 1, 8, 15, 30)
        >>> parse_timestamp("1641667800")
        datetime.datetime(2026, 1, 8, 15, 30)
    """
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",           # 2026-01-08T15:30:00Z
        "%Y-%m-%dT%H:%M:%S",            # 2026-01-08T15:30:00
        "%Y-%m-%d %H:%M:%S",            # 2026-01-08 15:30:00
        "%Y-%m-%d",                     # 2026-01-08
    ]
    
    # Try standard formats
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue
    
    # Try Unix timestamp
    try:
        return datetime.fromtimestamp(float(timestamp_str))
    except (ValueError, TypeError):
        pass
    
    return None


def batch_list(items: List[Any], batch_size: int) -> List[List[Any]]:
    """
    Split list into batches of specified size.
    
    Useful for processing large datasets in chunks, e.g., batch threat
    classification API requests or bulk data operations.
    
    Args:
        items (list): Items to batch
        batch_size (int): Size of each batch
    
    Returns:
        list: List of batches (last batch may be smaller)
    
    Example:
        >>> batch_list([1, 2, 3, 4, 5], 2)
        [[1, 2], [3, 4], [5]]
    """
    return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]


def retry_with_backoff(max_retries: int = 3, initial_delay: float = 1.0) -> Callable:
    """
    Decorator for exponential backoff retry logic.
    
    Retries function on any exception with exponential backoff:
    delay = initial_delay * (2 ^ attempt). Useful for resilient API calls
    or intermittent failure handling.
    
    Args:
        max_retries (int): Maximum retry attempts (default: 3)
        initial_delay (float): Initial delay in seconds (default: 1.0)
    
    Returns:
        function: Decorator
    
    Example:
        >>> @retry_with_backoff(max_retries=3, initial_delay=1.0)
        ... def call_api(endpoint):
        ...     return requests.get(endpoint)
        >>> 
        >>> result = call_api("https://api.example.com/threats")
    
    Delay Pattern:
        - Attempt 1: 1.0 seconds
        - Attempt 2: 2.0 seconds
        - Attempt 3: 4.0 seconds
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries:
                        raise
                    time.sleep(delay)
                    delay *= 2
        return wrapper
    return decorator


# ============================================================================
# Integration Examples
# ============================================================================

if __name__ == '__main__':
    """
    Demonstration of helpers module utilities.
    """
    
    # Example 1: Text Normalization
    print("=== Text Normalization ===")
    messy_text = "Click   HERE!!!  To  Claim  Prize!!!"
    normalized = normalize_text(messy_text)
    print(f"Original: {messy_text}")
    print(f"Normalized: {normalized}\n")
    
    # Example 2: Fuzzy Matching
    print("=== Fuzzy Matching ===")
    phishing_variants = ["verify account", "verifyaccount", "verify account"]
    for variant in phishing_variants:
        match = fuzzy_match("verify account", variant, threshold=0.8)
        print(f"'{variant}' matches: {match}")
    print()
    
    # Example 3: JSON Extraction
    print("=== JSON Extraction ===")
    text_with_json = 'Threat detected: {"type": "phishing", "score": 0.92}'
    extracted = extract_json_from_text(text_with_json)
    print(f"Extracted: {extracted}\n")
    
    # Example 4: Dictionary Flattening
    print("=== Dictionary Flattening ===")
    threat_report = {
        "threat": {"type": "phishing", "confidence": 0.92},
        "timestamp": "2026-01-08T15:30:00Z"
    }
    flattened = flatten_dict(threat_report)
    print(f"Original: {threat_report}")
    print(f"Flattened: {flattened}\n")
    
    # Example 5: Schema Validation
    print("=== Schema Validation ===")
    schema = {"text": str, "confidence": float}
    valid_data = {"text": "threat", "confidence": 0.95}
    invalid_data = {"text": "threat"}
    
    is_valid, errors = validate_schema(valid_data, schema)
    print(f"Valid data: {is_valid}")
    
    is_valid, errors = validate_schema(invalid_data, schema)
    print(f"Invalid data: {is_valid}, Errors: {errors}\n")
    
    # Example 6: Batching
    print("=== Batching ===")
    threats = list(range(1, 8))
    batches = batch_list(threats, batch_size=3)
    print(f"Threats: {threats}")
    print(f"Batches: {batches}\n")
    
    # Example 7: Retry Decorator
    print("=== Retry with Backoff ===")
    call_count = 0
    
    @retry_with_backoff(max_retries=2, initial_delay=0.1)
    def flaky_operation():
        global call_count
        call_count += 1
        if call_count < 3:
            raise ConnectionError("Network unavailable")
        return "Success!"
    
    result = flaky_operation()
    print(f"Result: {result} (took {call_count} attempts)")