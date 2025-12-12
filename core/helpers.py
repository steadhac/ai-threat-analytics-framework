# core/helpers.py
"""
Helper utilities for parsing, normalization, and fuzzy comparison.
"""
import re
import json
from typing import Any, Dict, List, Optional, Tuple
from difflib import SequenceMatcher
from datetime import datetime


def normalize_text(text: str, lowercase: bool = True, remove_punctuation: bool = False) -> str:
    """
    Normalize text for comparison.
    
    Args:
        text: Input text
        lowercase: Convert to lowercase
        remove_punctuation: Remove punctuation marks
        
    Returns:
        Normalized text
    """
    if lowercase:
        text = text.lower()
    
    if remove_punctuation:
        text = re.sub(r'[^\w\s]', ' ', text)
    
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text


def fuzzy_match(str1: str, str2: str, threshold: float = 0.8) -> bool:
    """
    Perform fuzzy string matching.
    
    Args:
        str1: First string
        str2: Second string
        threshold: Similarity threshold (0-1)
        
    Returns:
        True if strings match above threshold
    """
    ratio = SequenceMatcher(None, str1, str2).ratio()
    return ratio >= threshold


def fuzzy_similarity(str1: str, str2: str) -> float:
    """
    Calculate fuzzy similarity between strings.
    
    Args:
        str1: First string
        str2: Second string
        
    Returns:
        Similarity ratio (0-1)
    """
    return SequenceMatcher(None, str1, str2).ratio()


def parse_json_safe(text: str, default: Any = None) -> Any:
    """
    Safely parse JSON, returning default on error.
    
    Args:
        text: JSON text
        default: Default value on parse error
        
    Returns:
        Parsed JSON or default value
    """
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default


def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """
    Extract JSON object from text containing other content.
    
    Args:
        text: Text potentially containing JSON
        
    Returns:
        Extracted JSON dictionary or None
    """
    # Try to find JSON object boundaries
    json_match = re.search(r'\{.*\}', text, re.DOTALL)
    if json_match:
        return parse_json_safe(json_match.group(0))
    
    return None


def flatten_dict(nested_dict: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """
    Flatten nested dictionary.
    
    Args:
        nested_dict: Nested dictionary
        parent_key: Parent key prefix
        sep: Separator for nested keys
        
    Returns:
        Flattened dictionary
    """
    items = []
    
    for key, value in nested_dict.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key
        
        if isinstance(value, dict):
            items.extend(flatten_dict(value, new_key, sep=sep).items())
        else:
            items.append((new_key, value))
    
    return dict(items)


def compare_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two dictionaries and return differences.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary
        
    Returns:
        Dictionary with added, removed, and modified keys
    """
    flat1 = flatten_dict(dict1)
    flat2 = flatten_dict(dict2)
    
    all_keys = set(flat1.keys()) | set(flat2.keys())
    
    added = {k: flat2[k] for k in flat2.keys() - flat1.keys()}
    removed = {k: flat1[k] for k in flat1.keys() - flat2.keys()}
    modified = {k: {'old': flat1[k], 'new': flat2[k]} 
                for k in all_keys if k in flat1 and k in flat2 and flat1[k] != flat2[k]}
    
    return {
        'added': added,
        'removed': removed,
        'modified': modified,
        'unchanged_count': len(all_keys) - len(added) - len(removed) - len(modified)
    }


def validate_schema(data: Dict[str, Any], schema: Dict[str, type]) -> Tuple[bool, List[str]]:
    """
    Validate data against a simple schema.
    
    Args:
        data: Data dictionary to validate
        schema: Schema dictionary mapping keys to expected types
        
    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []
    
    for key, expected_type in schema.items():
        if key not in data:
            errors.append(f"Missing required key: {key}")
        elif not isinstance(data[key], expected_type):
            errors.append(f"Invalid type for {key}: expected {expected_type.__name__}, got {type(data[key]).__name__}")
    
    return len(errors) == 0, errors


def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate text to maximum length.
    
    Args:
        text: Input text
        max_length: Maximum length
        suffix: Suffix to add when truncated
        
    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse timestamp from various formats.
    
    Args:
        timestamp_str: Timestamp string
        
    Returns:
        Datetime object or None
    """
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%fZ',
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue
    
    return None


def batch_list(items: List[Any], batch_size: int) -> List[List[Any]]:
    """
    Split list into batches.
    
    Args:
        items: List of items
        batch_size: Size of each batch
        
    Returns:
        List of batches
    """
    return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]


def retry_with_backoff(func, max_retries: int = 3, initial_delay: float = 1.0):
    """
    Decorator for retrying functions with exponential backoff.
    
    Args:
        func: Function to retry
        max_retries: Maximum number of retries
        initial_delay: Initial delay in seconds
        
    Returns:
        Wrapped function
    """
    import time
    from functools import wraps
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        delay = initial_delay
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    time.sleep(delay)
                    delay *= 2  # Exponential backoff
        
        raise last_exception
    
    return wrapper
