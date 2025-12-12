# core/logger.py
"""
Structured logging module for ML observability.
Supports JSON logging and integration with monitoring systems.
"""
import logging
import json
import sys
from datetime import datetime
from typing import Any, Dict


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, "extra_data"):
            log_data["extra"] = record.extra_data
            
        return json.dumps(log_data)


def get_logger(name: str, level: str = "INFO", json_format: bool = False) -> logging.Logger:
    """
    Get configured logger instance.
    
    Args:
        name: Logger name (usually __name__)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: If True, use JSON formatting for logs
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    logger.setLevel(getattr(logging, level.upper()))
    
    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, level.upper()))
    
    # Set formatter
    if json_format:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger


def log_metric(logger: logging.Logger, metric_name: str, value: Any, metadata: Dict[str, Any] = None):
    """
    Log a metric with optional metadata.
    
    Args:
        logger: Logger instance
        metric_name: Name of the metric
        value: Metric value
        metadata: Additional metadata dictionary
    """
    log_data = {
        "metric": metric_name,
        "value": value,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if metadata:
        log_data.update(metadata)
    
    logger.info(f"METRIC: {json.dumps(log_data)}")


def log_test_result(logger: logging.Logger, test_name: str, status: str, duration: float, details: Dict[str, Any] = None):
    """
    Log test execution result.
    
    Args:
        logger: Logger instance
        test_name: Name of the test
        status: Test status (PASSED, FAILED, SKIPPED)
        duration: Test execution duration in seconds
        details: Additional test details
    """
    log_data = {
        "test": test_name,
        "status": status,
        "duration_seconds": duration,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if details:
        log_data["details"] = details
    
    logger.info(f"TEST_RESULT: {json.dumps(log_data)}")
