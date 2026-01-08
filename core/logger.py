# core/logger.py
"""
Structured logging module for ML observability and system monitoring.

This module provides enterprise-grade logging infrastructure for AI systems:
- JSON-formatted logs for machine parsing
- Structured logging (key-value pairs)
- Integration with monitoring/observability platforms
- Test result tracking and metrics logging
- Exception handling and context preservation

Purpose:
    Enable visibility into system behavior through structured logs
    Support monitoring, debugging, and compliance auditing
    Machine-readable format for log aggregation (ELK, Splunk, etc.)
    Trace execution flow and measure performance

Key Features:
    1. JSON Formatter: Converts logs to JSON for machine parsing
    2. Structured Logging: Key-value pairs instead of unstructured text
    3. Metadata Support: Extra context (user_id, request_id, etc.)
    4. Exception Tracking: Full stack traces in logs
    5. Metric Logging: Performance and business metrics
    6. Test Result Logging: Test execution tracking

Log Destinations:
    - Console (stdout): Real-time visibility
    - Log aggregation (optional): ELK, Splunk, CloudWatch
    - Monitoring systems: Parse JSON for alerts/dashboards
    - Audit trails: Compliance and forensics

Use Cases:
    - Debug application issues (check logs)
    - Monitor performance (track metrics)
    - Audit security events (trace access)
    - Test reporting (track test results)
    - Compliance (maintain audit trail)
    - Incident response (reconstruct events)

Log Levels:
    DEBUG: Low-level diagnostic information
    INFO: Informational messages (normal flow)
    WARNING: Warning conditions (potential issues)
    ERROR: Error conditions (failures, exceptions)
    CRITICAL: Critical conditions (system failure)

Integration Examples:
    - ELK Stack: Parse JSON logs, create dashboards
    - Splunk: Index and search structured logs
    - CloudWatch: AWS log aggregation
    - Datadog: APM and monitoring
    - Sentry: Error tracking and reporting

Compliance:
    - GDPR: Log retention policies (delete old logs)
    - HIPAA: Audit trails for access control
    - PCI-DSS: Security event logging
    - SOX: Financial activity audit logs
"""

import logging
import json
import sys
from datetime import datetime
from typing import Any, Dict


class JSONFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging.
    
    Converts Python logging records to JSON format for machine parsing.
    Enables integration with log aggregation and monitoring platforms.
    
    Output Format:
        {
            "timestamp": "2026-01-08T15:30:45.123456Z",
            "level": "INFO",
            "logger": "core.threat_classifier",
            "message": "Classification completed",
            "module": "threat_classifier",
            "function": "classify",
            "line": 42,
            "extra": {"threat_type": "phishing", "confidence": 0.92}
        }
    
    Advantages Over Plain Text:
        - Machine parseable (no regex needed)
        - Structured data (easily indexed)
        - Consistent format (all logs have same structure)
        - Metadata preserved (function name, line number, etc.)
        - Integrates with log aggregation platforms
    
    Use Cases:
        - Production logging (ELK, Splunk integration)
        - Monitoring dashboards (parse JSON metrics)
        - Automated alerts (regex-free log analysis)
        - Debugging (structured context)
        - Compliance auditing (machine-readable trails)
    
    Fields Included:
        - timestamp: ISO 8601 format (UTC)
        - level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        - logger: Logger name (usually module path)
        - message: Log message
        - module: Python module name
        - function: Function/method name
        - line: Line number in source code
        - exception: Stack trace (if error occurred)
        - extra: Additional metadata (if provided)
    
    Example Output:
        >>> logger = get_logger("core.classifier", json_format=True)
        >>> logger.info("Processing threat", extra={"threat_id": "TH001"})
        # Outputs:
        # {"timestamp": "2026-01-08T15:30:45.123456Z", "level": "INFO", 
        #  "logger": "core.classifier", "message": "Processing threat", 
        #  "module": "classifier", "function": "<module>", "line": 1,
        #  "extra": {"threat_id": "TH001"}}
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record as JSON string.
        
        Converts standard Python logging record to JSON with structured fields
        for machine parsing and log aggregation platform integration.
        
        Parameters:
            record (logging.LogRecord): Log record from Python logging system
        
        Returns:
            str: JSON-formatted log entry (single line)
        
        Processing Steps:
            1. Extract timestamp (UTC, ISO 8601 format)
            2. Get log level, logger name, message
            3. Extract source location (module, function, line)
            4. Add exception info if error occurred
            5. Add extra fields if provided
            6. Serialize to JSON string
        
        Timestamp:
            - UTC time (not local time)
            - ISO 8601 format (2026-01-08T15:30:45.123456Z)
            - Sortable and comparable
            - Compatible with log aggregation platforms
        
        Exception Handling:
            If record.exc_info is present (error/exception):
            - Includes full stack trace
            - Formatted as readable string
            - Preserved for debugging
        
        Extra Metadata:
            If record.extra_data exists (custom context):
            - Included in "extra" field
            - Dictionary of key-value pairs
            - Examples: user_id, request_id, threat_id
        
        Examples:
            >>> record = logging.LogRecord(
            ...     name="test_logger",
            ...     level=logging.INFO,
            ...     pathname="test.py",
            ...     lineno=10,
            ...     msg="Test message",
            ...     args=(),
            ...     exc_info=None
            ... )
            >>> formatter = JSONFormatter()
            >>> json_str = formatter.format(record)
            >>> json_obj = json.loads(json_str)
            >>> json_obj["level"]
            'INFO'
        
        Performance:
            - Time: O(1) for normal logs, O(n) for exceptions (n = stack depth)
            - Space: JSON string length typically 200-500 bytes
        
        Log Aggregation Compatibility:
            - ELK Stack: Parse JSON, create indexes on fields
            - Splunk: Recognize JSON format automatically
            - CloudWatch: Store as JSON, query with JSONPath
            - Datadog: Auto-parse, create metrics from fields
        """
        # Build base log data structure
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",  # UTC, ISO 8601
            "level": record.levelname,                         # INFO, ERROR, etc.
            "logger": record.name,                             # Logger name
            "message": record.getMessage(),                    # Formatted message
            "module": record.module,                           # Module name
            "function": record.funcName,                       # Function name
            "line": record.lineno                              # Line number
        }
        
        # Add exception info if this is an error/exception log
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra custom fields if provided
        if hasattr(record, "extra_data"):
            log_data["extra"] = record.extra_data
        
        # Serialize to JSON and return as single line
        return json.dumps(log_data)


def get_logger(name: str, level: str = "INFO", json_format: bool = False) -> logging.Logger:
    """
    Get or create a configured logger instance.
    
    Factory function to create consistent logger configuration across application.
    Supports both plain text and JSON formatted logging.
    
    Parameters:
        name (str): Logger name (usually __name__ from calling module)
                   Examples: "core.classifier", "tests.test_anomaly", "__main__"
                   Namespace separators (dots) create logger hierarchy
        
        level (str, optional): Logging level threshold
                              Default: "INFO"
                              Options: "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
                              Only logs at this level or higher are emitted
        
        json_format (bool, optional): Output format
                                     Default: False (plain text)
                                     True: JSON format (for log aggregation)
                                     False: Human-readable text format
    
    Returns:
        logging.Logger: Configured logger instance
    
    Logging Levels (in order of severity):
        DEBUG (10): Detailed diagnostic information
                   Use for: Variable values, function calls, flow tracking
                   Typical: Development and troubleshooting
        
        INFO (20): Informational messages (normal operation)
                   Use for: Key events, milestones, important actions
                   Typical: Production monitoring
        
        WARNING (30): Warning conditions (potential issues)
                      Use for: Deprecated features, performance issues, retries
                      Typical: Production alerts
        
        ERROR (40): Error conditions (operation failed)
                    Use for: Exceptions, failed requests, invalid data
                    Typical: Production errors
        
        CRITICAL (50): Critical conditions (system failing)
                       Use for: System shutdown, data loss, complete failure
                       Typical: Emergency alerts
    
    Output Formats:
        
        Plain Text (json_format=False):
        "2026-01-08 15:30:45,123 - core.classifier - INFO - Classification complete"
        Advantages: Human-readable, easy to read in terminal
        Disadvantages: Hard to parse, limited structure
        
        JSON (json_format=True):
        {"timestamp":"2026-01-08T15:30:45.123456Z","level":"INFO",...}
        Advantages: Machine-parseable, log aggregation compatible
        Disadvantages: Less readable, longer lines
    
    Examples:
        >>> # Create logger for module
        >>> logger = get_logger(__name__)
        >>> logger.info("Processing started")
        
        >>> # Create JSON-formatted logger for production
        >>> logger = get_logger("core.classifier", level="INFO", json_format=True)
        >>> logger.warning("Unusual pattern detected")
        
        >>> # Debug-level logger for development
        >>> logger = get_logger("tests", level="DEBUG")
        >>> logger.debug("Entering classification")
    
    Handler Configuration:
        - Console Handler: Writes to stdout (terminal)
        - Single Handler: Avoids duplicate logs
        - Dynamic Level: Set at logger creation time
        - Idempotent: Multiple calls with same name return same logger
    
    Logger Naming Convention:
        Use Python module paths:
        - "core.classifier": Logger in core/classifier.py
        - "tests.test_anomaly": Logger in tests/test_anomaly.py
        - "__main__": Logger in main script
        Benefits: Hierarchical organization, easy filtering
    
    Duplicate Handler Prevention:
        - Checks if logger already has handlers
        - Returns existing logger if already configured
        - Prevents duplicate logs in output
        - Python logging best practice
    
    Performance:
        - First call: ~5ms (handler creation, formatting setup)
        - Subsequent calls: < 1ms (returns cached logger)
        - Recommended: Create loggers at module level (once per module)
    
    Best Practices:
        1. Create loggers at module level: logger = get_logger(__name__)
        2. Use appropriate levels (DEBUG for dev, INFO for production)
        3. Reuse logger instances (don't recreate in functions)
        4. Use JSON format in production, plain text in development
        5. Include context in messages (what failed, why, next steps)
    
    Integration Examples:
        
        Development:
        >>> logger = get_logger(__name__, level="DEBUG")
        >>> logger.debug("Entering classify function")
        
        Production (ELK integration):
        >>> logger = get_logger("core.classifier", json_format=True)
        >>> logger.info("Classification complete", 
        ...             extra={"threat_id": "TH001", "confidence": 0.92})
        
        Testing:
        >>> logger = get_logger("tests.test_classifier", level="DEBUG")
        >>> logger.info("Test case executed")
    
    Related Functions:
        - log_metric(): Log performance metrics
        - log_test_result(): Log test execution results
    """
    # Get logger instance (Python logging creates if not exists)
    logger = logging.getLogger(name)
    
    # Avoid adding duplicate handlers if already configured
    if logger.handlers:
        return logger
    
    # Set logger level (minimum severity to process)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Create console handler (stdout)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, level.upper()))
    
    # Create and attach formatter
    if json_format:
        # JSON format for log aggregation platforms
        formatter = JSONFormatter()
    else:
        # Plain text format for human reading
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger


def log_metric(logger: logging.Logger, metric_name: str, value: Any, metadata: Dict[str, Any] = None):
    """
    Log a performance or business metric.
    
    Structured metric logging for monitoring systems and dashboards.
    Use this for quantitative measurements that should be tracked over time.
    
    Parameters:
        logger (logging.Logger): Logger instance (from get_logger)
        
        metric_name (str): Name of the metric being logged
                          Should be consistent/standard
                          Examples: "classification_latency_ms", "threat_count", "api_calls"
        
        value (Any): Metric value (typically numeric)
                    Examples: 145.2 (milliseconds), 42 (count), 0.92 (score)
                    Can be any JSON-serializable type
        
        metadata (Dict[str, Any], optional): Additional context
                                            Default: None
                                            Examples: {"model": "phishing_v1", "user_id": "USER123"}
                                            Used for: Filtering, grouping, drill-down
    
    Returns:
        None (side effect: logs metric)
    
    Metric Structure:
        {
            "metric": "classification_latency_ms",
            "value": 145.2,
            "timestamp": "2026-01-08T15:30:45.123456Z",
            "model": "phishing_v1",
            "user_id": "USER123"
        }
    
    Metric Types:
        
        Counter: Monotonically increasing value
        - Examples: total_classifications, requests_processed
        - Typical: Count things (each log entry is +1)
        - Monitoring: Rate of increase (requests per second)
        
        Gauge: Value that goes up and down
        - Examples: queue_depth, memory_usage, active_users
        - Typical: Current status
        - Monitoring: Peaks, valleys, trends
        
        Histogram/Timing: Distribution of values
        - Examples: response_time_ms, latency_percentile
        - Typical: Performance measurements
        - Monitoring: Percentiles (p50, p95, p99)
    
    Common Metrics:
        - Latency: How long operations take
        - Throughput: Operations per second
        - Error Rate: Failures / total
        - Queue Depth: Items waiting
        - Memory/CPU: Resource usage
        - Success Rate: Successful operations / total
    
    Examples:
        >>> logger = get_logger("core.classifier", json_format=True)
        
        >>> # Log classification latency
        >>> log_metric(logger, "classification_latency_ms", 145.2,
        ...            metadata={"model": "phishing_v1"})
        
        >>> # Log threat count
        >>> log_metric(logger, "threats_detected", 42,
        ...            metadata={"threat_type": "phishing", "hour": "2026-01-08T15"})
        
        >>> # Log API latency
        >>> log_metric(logger, "api_response_time_ms", 234.5,
        ...            metadata={"endpoint": "/classify", "status": 200})
    
    Monitoring Integration:
        
        ELK Stack:
        - Parse JSON logs
        - Extract metric field
        - Create time-series graphs
        - Alert on thresholds
        
        Datadog:
        - Auto-detect metrics
        - Create dashboards
        - Set anomaly detection
        - Correlate with errors
        
        CloudWatch:
        - Ingest as custom metrics
        - Create alarms
        - Build dashboards
        - Calculate statistics
    
    Metadata Guidelines:
        - Include context for filtering/grouping
        - Standard keys (model, version, environment)
        - Avoid personal data (PII, secrets)
        - Keep to reasonable size (< 1KB)
        - Use consistent naming
    
    Performance Metrics to Track:
        - Inference latency: Time to run model
        - Queue depth: Items waiting for processing
        - Cache hit rate: % of requests served from cache
        - Error rate: % of failed requests
        - Memory usage: System memory consumption
        - GPU utilization: GPU usage percentage
    
    Business Metrics to Track:
        - Threats detected: Count of identified threats
        - False positives: Incorrect detections
        - Model accuracy: % of correct classifications
        - User satisfaction: Rating/feedback scores
        - Cost: Infrastructure cost
    
    Log Format:
        Output: "METRIC: {json_data}"
        Prefix: "METRIC:" for easy filtering/parsing
        Format: JSON string of metric data
        Parseable: Standard log aggregation can extract
    
    Querying Examples:
        
        ELK: Find classification latencies
        {"level": "INFO", "message": "METRIC:*classification_latency*"}
        
        CloudWatch Insights:
        fields @timestamp, metric, value
        | filter ispresent(metric)
        | stats avg(value) by metric
        
        Grep (command line):
        grep "METRIC:*classification" logs.txt
    
    Related Functions:
        - log_test_result(): Log test metrics
        - get_logger(): Get logger instance
    
    Testing:
        - Unit test: test_log_metric()
        - Verify: JSON structure, timestamp, metadata included
        - Edge cases: None metadata, special characters, large values
    """
    # Build metric data structure
    log_data = {
        "metric": metric_name,                                      # Metric name
        "value": value,                                             # Metric value
        "timestamp": datetime.utcnow().isoformat() + "Z"            # UTC timestamp
    }
    
    # Add metadata if provided
    if metadata:
        log_data.update(metadata)  # Merge metadata fields
    
    # Log with METRIC prefix for easy filtering
    logger.info(f"METRIC: {json.dumps(log_data)}")


def log_test_result(logger: logging.Logger, test_name: str, status: str, duration: float, details: Dict[str, Any] = None):
    """
    Log test execution result.
    
    Structured logging for test results enabling test tracking and analysis.
    Use this to log test pass/fail status with execution metrics.
    
    Parameters:
        logger (logging.Logger): Logger instance (from get_logger)
        
        test_name (str): Name of the test
                        Should match test function name
                        Examples: "test_phishing_classification", "test_data_validation"
        
        status (str): Test outcome
                     Must be one of: "PASSED", "FAILED", "SKIPPED"
                     PASSED: Test completed successfully
                     FAILED: Test failed (assertion, exception)
                     SKIPPED: Test was skipped (condition not met)
        
        duration (float): Test execution time in seconds
                         Precision: Microseconds (use time.perf_counter())
                         Examples: 0.001234 (1.234 ms), 0.142 (142 ms)
        
        details (Dict[str, Any], optional): Additional test information
                                           Default: None
                                           Examples: {"error": "AssertionError", "line": 42}
                                           Used for: Debugging failures
    
    Returns:
        None (side effect: logs test result)
    
    Test Result Structure:
        {
            "test": "test_phishing_classification",
            "status": "PASSED",
            "duration_seconds": 0.0456,
            "timestamp": "2026-01-08T15:30:45.123456Z",
            "error": "AssertionError: expected True",
            "assertion_details": "Confidence score < threshold"
        }
    
    Status Values:
        
        "PASSED": Test succeeded
        - All assertions passed
        - No exceptions raised
        - Expected behavior confirmed
        
        "FAILED": Test failed
        - Assertion failed (actual ≠ expected)
        - Exception raised
        - Unexpected behavior detected
        
        "SKIPPED": Test was not executed
        - Condition not met (e.g., dependency unavailable)
        - Test marked as skip
        - Environment doesn't support test
    
    Duration Measurement:
        Best practice: Use time.perf_counter()
        import time
        start = time.perf_counter()
        # run test
        duration = time.perf_counter() - start
        
        Alternatives:
        - time.time(): Wall clock (less precise)
        - unittest built-in: Automatic timing
        - pytest: Use pytest fixtures for timing
    
    Examples:
        >>> logger = get_logger("tests", json_format=True)
        >>> import time
        
        >>> # Successful test
        >>> start = time.perf_counter()
        >>> # ... run test ...
        >>> duration = time.perf_counter() - start
        >>> log_test_result(logger, "test_phishing_classification", 
        ...                 "PASSED", duration)
        
        >>> # Failed test with error details
        >>> try:
        ...     # ... run test ...
        ... except AssertionError as e:
        ...     log_test_result(logger, "test_malware_detection",
        ...                     "FAILED", duration,
        ...                     details={"error": str(e), "line": 42})
        
        >>> # Skipped test
        >>> log_test_result(logger, "test_requires_gpu",
        ...                 "SKIPPED", 0.0,
        ...                 details={"reason": "GPU not available"})
    
    Details Field Usage:
        When test fails, include debugging info:
        - error: Exception message or assertion error
        - expected: Expected value
        - actual: Actual value
        - line: Line number of failure
        - assertion: Assertion that failed
        
        Example:
        details = {
            "error": "AssertionError",
            "expected": 0.92,
            "actual": 0.75,
            "assertion": "confidence >= 0.90"
        }
    
    Test Reporting Integration:
        
        HTML Reports:
        - Parse JSON logs
        - Create test pass/fail summary
        - Show execution time
        - List failure details
        
        CI/CD Pipeline:
        - Log results to file
        - Aggregate results
        - Fail pipeline if tests fail
        - Generate reports
        
        Test Dashboards:
        - Track test success rate over time
        - Identify flaky tests
        - Performance trends
        - Regression detection
    
    Test Metrics:
        - Pass Rate: (PASSED / TOTAL) * 100
        - Failure Rate: (FAILED / TOTAL) * 100
        - Skip Rate: (SKIPPED / TOTAL) * 100
        - Average Duration: Mean execution time
        - Slowest Tests: Tests taking longest
        - Fastest Tests: Quick feedback tests
    
    Typical Test Logging Pattern:
        import time
        import logging
        
        logger = logging.getLogger(__name__)
        
        def my_test():
            start = time.perf_counter()
            try:
                # Test code here
                assert condition, "Failure message"
                status = "PASSED"
            except Exception as e:
                status = "FAILED"
                details = {"error": str(e)}
            finally:
                duration = time.perf_counter() - start
                log_test_result(logger, "my_test", status, duration, details)
    
    Log Format:
        Output: "TEST_RESULT: {json_data}"
        Prefix: "TEST_RESULT:" for easy filtering
        Format: JSON string with all test metadata
        Parseable: Standard log tools can extract/filter
    
    Querying Examples:
        
        Find all failed tests:
        grep "TEST_RESULT:*FAILED" logs.txt
        
        ELK: Failing tests
        {"status": "FAILED"}
        
        Find slow tests (> 1 second):
        grep "TEST_RESULT:" logs.txt | jq 'select(.duration_seconds > 1)'
    
    Related Functions:
        - log_metric(): Log performance metrics
        - get_logger(): Get logger instance
    
    Testing:
        - Unit test: test_log_test_result()
        - Verify: JSON structure, all fields included
        - Edge cases: Very fast tests (<1ms), details with special chars
    """
    # Build test result data structure
    log_data = {
        "test": test_name,                                          # Test name
        "status": status,                                           # PASSED/FAILED/SKIPPED
        "duration_seconds": duration,                               # Execution time
        "timestamp": datetime.utcnow().isoformat() + "Z"            # UTC timestamp
    }
    
    # Add test details if provided (e.g., error message, assertions)
    if details:
        log_data["details"] = details  # Merge details into result
    
    # Log with TEST_RESULT prefix for easy filtering
    logger.info(f"TEST_RESULT: {json.dumps(log_data)}")