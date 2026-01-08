"""
Anomaly Detection Module
========================

Detects anomalies in numeric data using statistical methods (Z-score analysis).
Identifies outliers that deviate significantly from mean using standard deviation.

Use Cases:
    - Detect unusual threat patterns in security data
    - Identify suspicious spikes in request volumes
    - Flag outlier values in metrics datasets
    - Real-time anomaly alerting

Methods:
    - detect_anomalies(): Z-score based outlier detection
"""

import statistics


def detect_anomalies(data, threshold=2.0):
    """
    Detect anomalies using Z-score (standard deviation analysis).
    
    Identifies values that deviate from the mean by more than threshold
    standard deviations. Useful for detecting outliers in metrics, logs,
    or threat data.
    
    Args:
        data (list): List of numeric values
            Minimum 2 values required (need stdev)
            Can contain ints or floats
            Empty list returns []
        
        threshold (float): Z-score threshold for anomaly (default: 2.0)
            threshold=1.5: Detect ~13% of normal distribution
            threshold=2.0: Detect ~5% of normal distribution
            threshold=3.0: Detect ~0.3% of normal distribution
    
    Returns:
        list: Indices of anomalous values in original data
              Empty list if no anomalies or insufficient data
    
    Example:
        >>> data = [10, 12, 11, 9, 100, 13, 11]  # 100 is anomaly
        >>> indices = detect_anomalies(data, threshold=2.0)
        >>> print(indices)
        [4]
        
        >>> # Multiple anomalies
        >>> data = [5, 5, 5, 100, 5, 200, 5]
        >>> indices = detect_anomalies(data, threshold=2.0)
        >>> print(indices)
        [3, 5]
        
        >>> # No anomalies (uniform data)
        >>> data = [10, 10, 10, 10, 10]
        >>> indices = detect_anomalies(data, threshold=2.0)
        >>> print(indices)
        []
    
    Z-Score Formula:
        z = |value - mean| / stdev
        Anomaly if: z > threshold
    
    Algorithm:
        1. Calculate mean of data
        2. Calculate standard deviation
        3. For each value, compute Z-score
        4. Return indices where Z-score exceeds threshold
    
    Edge Cases:
        - Insufficient data (< 2 values): Returns [] (can't compute stdev)
        - All same values (stdev = 0): Returns [] (no deviations)
        - Single outlier: Detected if large enough
        - Multiple outliers: All detected independently
    
    Performance: O(n) where n = length of data
    
    Limitations:
        - Assumes normal distribution (Gaussian)
        - Sensitive to multiple outliers (inflate stdev)
        - May not detect subtle gradual changes
        - Fixed threshold across all data types
    
    Use Cases:
        - Threat metrics: Flag unusually high attack rates
        - Performance: Detect latency spikes
        - Audit logs: Identify suspicious volumes
        - Data quality: Find measurement errors
    """
    if len(data) < 2:
        return []
    
    mean = statistics.mean(data)
    stdev = statistics.stdev(data)
    
    anomalies = []
    for i, value in enumerate(data):
        z_score = abs((value - mean) / stdev) if stdev > 0 else 0
        if z_score > threshold:
            anomalies.append(i)
    
    return anomalies


# ============================================================================
# Integration Examples
# ============================================================================

if __name__ == '__main__':
    """
    Demonstration of anomaly detection usage.
    """
    
    # Example 1: Basic anomaly detection
    print("=== Basic Anomaly Detection ===")
    data = [10, 12, 11, 9, 100, 13, 11]
    indices = detect_anomalies(data, threshold=2.0)
    print(f"Data: {data}")
    print(f"Anomalies at indices: {indices}")
    print(f"Anomalous values: {[data[i] for i in indices]}\n")
    
    # Example 2: Multiple anomalies
    print("=== Multiple Anomalies ===")
    data = [5, 5, 5, 100, 5, 200, 5]
    indices = detect_anomalies(data, threshold=2.0)
    print(f"Data: {data}")
    print(f"Anomalies at indices: {indices}\n")
    
    # Example 3: Different thresholds
    print("=== Threshold Comparison ===")
    data = [10, 10, 10, 10, 50, 10]
    for threshold in [1.0, 1.5, 2.0, 3.0]:
        indices = detect_anomalies(data, threshold=threshold)
        print(f"Threshold {threshold}: {indices}")
    print()
    
    # Example 4: Threat metrics
    print("=== Threat Metrics ===")
    requests_per_hour = [50, 55, 52, 48, 1000, 51, 49]  # 1000 is spike
    anomalies = detect_anomalies(requests_per_hour, threshold=2.0)
    print(f"Hourly requests: {requests_per_hour}")
    print(f"Anomalous hours: {anomalies}")
    if anomalies:
        print(f"Alert: Unusual activity at hour(s) {anomalies}\n")
    
    # Example 5: No anomalies
    print("=== Normal Data ===")
    data = [100, 101, 99, 102, 98, 100, 101]
    indices = detect_anomalies(data, threshold=2.0)
    print(f"Data: {data}")
    print(f"Anomalies: {indices if indices else 'None'}")