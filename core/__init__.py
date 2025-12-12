"""Core utilities for AI/ML testing framework."""

from .api_client import APIClient
from .logger import get_logger, log_metric, log_test_result
from .metrics import (
    compute_classification_metrics,
    semantic_similarity,
    rouge_score,
    bleu_score
)
from .anomaly_utils import detect_anomalies
from .security_checks import (
    contains_pii,
    check_prompt_injection,
    validate_guardrails,
    redact_sensitive_data
)
from .helpers import (
    normalize_text,
    fuzzy_match,
    parse_json_safe,
    compare_dicts
)

__all__ = [
    'APIClient',
    'get_logger',
    'log_metric',
    'log_test_result',
    'compute_classification_metrics',
    'semantic_similarity',
    'rouge_score',
    'bleu_score',
    'detect_anomalies',
    'contains_pii',
    'check_prompt_injection',
    'validate_guardrails',
    'redact_sensitive_data',
    'normalize_text',
    'fuzzy_match',
    'parse_json_safe',
    'compare_dicts',
]