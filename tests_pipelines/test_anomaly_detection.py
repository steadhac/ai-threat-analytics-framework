"""
Test suite for anomaly detection system using Z-score statistical analysis.

This module validates the anomaly detection pipeline's ability to identify
statistical outliers in data streams with various data distributions and
threshold sensitivities.

Test Coverage:
- Normal data produces zero false positives
- Single anomalies are correctly identified
- Multiple anomalies are all detected
- Threshold sensitivity behaves predictably
- Detection works across different data scales

Nondeterminism Handling:
The Z-score algorithm is deterministic: Z = (X - μ) / σ
However, the same outlier can be flagged or ignored depending on threshold.
Tests validate this nondeterminism is controlled and predictable:
- Value 100 in [10, 12, 11, 13, 12, 100, 10, 12]:
  - Flagged at threshold 1.5 (z-score ≈ 2.65)
  - Flagged at threshold 2.0 (z-score ≈ 2.65)
  - NOT flagged at threshold 3.0 (z-score ≈ 2.65)

Usage:
    pytest tests_pipelines/test_anomaly_detection.py -v
    pytest tests_pipelines/test_anomaly_detection.py -k threshold -v
"""

import pytest
import logging
from core.anomaly_utils import detect_anomalies

logger = logging.getLogger(__name__)


def test_normal_data_no_anomalies():
    """
    Test that normal data produces ZERO false positives.
    
    Validates:
        - Clean baseline data triggers no alarms
        - No spurious anomaly detection in healthy data
        - Detection model is stable across normal ranges
    
    Test Data:
        [10, 12, 11, 13, 12, 11, 10, 12]
        All values within 1 standard deviation of mean (≈11.5)
        Z-scores all < 1.0 (well below threshold 2.0)
    
    Expected Result:
        anomalies = []  (empty list)
    
    Assertions:
        1 assertion validates zero anomalies
    
    Risk Mitigated:
        False positives cause alert fatigue and reduce system reliability
    """
    logger.info("=" * 60)
    logger.info("TEST: Normal Data - No False Positives")
    
    logger.debug("Step 1: Create normal baseline data")
    normal_data = [10, 12, 11, 13, 12, 11, 10, 12]
    logger.debug(f"Data: {normal_data}")
    logger.debug(f"Mean: {sum(normal_data)/len(normal_data):.2f}")
    
    logger.debug("Step 2: Run anomaly detection")
    anomalies = detect_anomalies(normal_data, threshold=2.0)
    logger.info(f"Anomalies found: {anomalies}")
    
    logger.debug("Step 3: Validate no anomalies detected")
    assert len(anomalies) == 0, "Normal data should have NO anomalies"
    logger.debug("✓ No false positives")
    
    logger.info("✓ PASSED: Normal data stays clean")
    logger.info("=" * 60)


def test_single_spike_anomaly():
    """
    Test detection of single synthetic anomaly (spike).
    
    Validates:
        - Injected anomaly is correctly identified
        - Anomaly indices point to correct location
        - Anomaly values are correctly extracted
    
    Test Data:
        [10, 12, 11, 13, 12, 100, 10, 12]
        Index 5 contains synthetic outlier: value 100
        Mean ≈ 21.25, StdDev ≈ 29.3
        Z-score for 100 ≈ 2.65 (exceeds threshold 2.0)
    
    Expected Result:
        anomalies = [5]
        anomaly_values = [100]
    
    Assertions:
        2 assertions validate anomaly detection and identification
    
    Test Design:
        Synthetic anomaly injection method
        Tests that system can find intentionally-planted problems
    """
    logger.info("=" * 60)
    logger.info("TEST: Single Spike Anomaly Detection")
    
    logger.debug("Step 1: Create data with synthetic anomaly")
    data_with_anomaly = [10, 12, 11, 13, 12, 100, 10, 12]
    logger.debug(f"Data: {data_with_anomaly}")
    logger.debug(f"Anomaly injected at index 5: value 100")
    
    logger.debug("Step 2: Run anomaly detection with threshold=2.0")
    anomalies = detect_anomalies(data_with_anomaly, threshold=2.0)
    logger.info(f"Anomaly indices found: {anomalies}")
    
    logger.debug("Step 3: Verify anomaly detected")
    assert len(anomalies) > 0, "Should detect the spike"
    logger.debug("✓ Anomaly detected")
    
    logger.debug("Step 4: Extract and validate anomaly values")
    anomaly_values = [data_with_anomaly[i] for i in anomalies]
    logger.debug(f"Anomaly values: {anomaly_values}")
    assert 100 in anomaly_values, "Value 100 should be identified"
    logger.debug("✓ Correct value identified")
    
    logger.info("✓ PASSED: Spike correctly detected and located")
    logger.info("=" * 60)


@pytest.mark.parametrize("threshold,expected_count", [
    (1.5, 1),  # Very sensitive - catches spike
    (2.0, 1),  # Standard sensitivity - catches spike
    (3.0, 0),  # Low sensitivity - misses spike
])
def test_anomaly_detection_threshold_behavior(threshold, expected_count):
    """
    Test threshold sensitivity and nondeterminism.
    
    Validates:
        - Same data produces different results at different thresholds
        - Threshold behavior is predictable and documented
        - System respects sensitivity configuration
    
    Test Data (parameterized):
        [10, 12, 11, 13, 12, 100, 10, 12]
        Same data, three different threshold sensitivity levels
    
    Parametrization:
        - threshold=1.5, expected_count=1: High sensitivity
        - threshold=2.0, expected_count=1: Standard sensitivity
        - threshold=3.0, expected_count=0: Low sensitivity
    
    Expected Results:
        Z-score for 100 ≈ 2.65, so:
        - 1.5 < 2.65: Detected (count=1)
        - 2.0 < 2.65: Detected (count=1)
        - 3.0 > 2.65: NOT Detected (count=0)
    
    Assertions:
        1 assertion per parametrized run validates count matches expectation
    
    Nondeterminism Explanation:
        This demonstrates controlled nondeterminism: the same input (data)
        produces different outputs based on threshold configuration. This is
        expected and validated behavior, not a bug.
    """
    logger.info("=" * 60)
    logger.info(f"TEST: Threshold Behavior (threshold={threshold}, expected={expected_count})")
    
    logger.debug("Step 1: Create test data with anomaly")
    data = [10, 12, 11, 13, 12, 100, 10, 12]
    logger.debug(f"Data: {data}")
    logger.debug(f"Testing with threshold={threshold}")
    
    logger.debug("Step 2: Run anomaly detection")
    anomalies = detect_anomalies(data, threshold=threshold)
    logger.info(f"Anomalies found: {anomalies} (count: {len(anomalies)})")
    
    logger.debug("Step 3: Validate result matches expectation")
    logger.debug(f"Expected: {expected_count}, Got: {len(anomalies)}")
    assert len(anomalies) == expected_count, \
        f"Threshold {threshold}: expected {expected_count}, got {len(anomalies)}"
    logger.debug("✓ Threshold behavior correct")
    
    logger.info(f"✓ PASSED: Threshold {threshold} behaves as expected")
    logger.info("=" * 60)


@pytest.mark.parametrize("baseline_data,anomaly_value", [
    ([50, 52, 51, 53, 52], 200),      # High baseline
    ([1, 2, 1, 2, 1], 10),            # Low baseline
    ([100, 102, 101, 103, 102], 500), # High values
])
def test_anomaly_detection_scale_independence(baseline_data, anomaly_value):
    """
    Test detection across different data scales.
    
    Validates:
        - Z-score analysis works regardless of data magnitude
        - Low-scale anomalies (1→10) detected same as high-scale (100→500)
        - Algorithm is scale-invariant and robust
    
    Test Data (parameterized):
        Three different scales with proportional anomalies:
        1. Small numbers: [1, 2, 1, 2, 1] with anomaly 10 (10x spike)
        2. Medium numbers: [50, 52, 51, 53, 52] with anomaly 200 (4x spike)
        3. Large numbers: [100, 102, 101, 103, 102] with anomaly 500 (5x spike)
    
    Expected Result:
        All three cases should detect the anomaly
        Algorithm normalizes by standard deviation (Z-score advantage)
    
    Assertions:
        1 assertion per parametrized run validates anomaly detected
    
    Test Design:
        Scale independence ensures algorithm works on:
        - Low-traffic data streams (1-10 range)
        - Normal traffic patterns (50-100 range)
        - High-volume systems (100-500+ range)
    """
    logger.info("=" * 60)
    logger.info(f"TEST: Scale Independence")
    logger.info(f"Baseline: {baseline_data}, Anomaly Value: {anomaly_value}")
    
    logger.debug("Step 1: Create data with anomaly")
    data = baseline_data + [anomaly_value] + baseline_data
    logger.debug(f"Combined data: {data}")
    logger.debug(f"Data scale: {min(data)}-{max(data)}")
    
    logger.debug("Step 2: Run anomaly detection")
    anomalies = detect_anomalies(data, threshold=2.0)
    logger.info(f"Anomalies found: {anomalies}")
    
    logger.debug("Step 3: Validate anomaly detected")
    assert len(anomalies) > 0, \
        f"Failed to detect anomaly {anomaly_value} at scale {max(baseline_data)}"
    logger.debug("✓ Anomaly detected")
    
    logger.info("✓ PASSED: Detection works across different scales")
    logger.info("=" * 60)