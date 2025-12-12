import pytest
from core.anomaly_utils import detect_anomalies


def test_anomaly_detection():
    """Test anomaly detection in data streams"""
    # Normal data
    normal_data = [10, 12, 11, 13, 12, 11, 10, 12]
    
    # Data with anomaly (spike)
    data_with_anomaly = [10, 12, 11, 13, 12, 100, 10, 12]
    
    # Lower threshold to 2.0 to catch the spike
    anomalies = detect_anomalies(data_with_anomaly, threshold=2.0)
    
    assert len(anomalies) > 0
    assert 100 in [data_with_anomaly[i] for i in anomalies]