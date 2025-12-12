import statistics


def detect_anomalies(data, threshold=2.0):
    """
    Detect anomalies using standard deviation
    
    Args:
        data: List of numeric values
        threshold: Number of standard deviations for anomaly
        
    Returns:
        List of indices where anomalies are detected
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