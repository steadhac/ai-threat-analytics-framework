# Key Concepts - AI Threat Analytics Framework

This document explains the core concepts and algorithms used in the framework.

---

## Table of Contents

1. [Anomaly Detection & Z-Score](#anomaly-detection--z-score)
2. [Threat Classification](#threat-classification)
3. [LLM Security Guardrails](#llm-security-guardrails)
4. [Text Summarization](#text-summarization)

---

## Anomaly Detection & Z-Score

### What is Anomaly Detection?

Anomaly detection identifies unusual patterns that deviate significantly from normal behavior. In security, this could be:
- Unusual login times
- Suspicious transaction amounts
- Abnormal network traffic
- Unexpected system resource usage

### How Z-Score Works

**Z-Score Formula:**
z = (value - mean) / standard_deviation

**What it tells you:**
- z = 0: Value is exactly at the mean (average)
- z = 1: Value is 1 standard deviation above mean
- z = -1: Value is 1 standard deviation below mean
- z = 2+: Value is unusually high
- z = -2-: Value is unusually low

### Step-by-Step Example

```python
# Login times (in hours): 9am, 9am, 10am, 12pm, 2pm, 3am, 5pm
data = [9, 9, 10, 12, 14, 3, 17]

# Step 1: Calculate mean
mean = (9 + 9 + 10 + 12 + 14 + 3 + 17) / 7 = 10.57

# Step 2: Calculate standard deviation
stdev = 4.35

# Step 3: Calculate z-score for each value
Value 9:  z = (9 - 10.57) / 4.35 = -0.36  ✅ Normal
Value 10: z = (10 - 10.57) / 4.35 = -0.13 ✅ Normal  
Value 3:  z = (3 - 10.57) / 4.35 = -1.74  🚨 Unusual (3am login!)
Value 17: z = (17 - 10.57) / 4.35 = 1.48  ✅ Normal

# Step 4: Apply threshold (2.0)
# If |z| > 2.0 → Flag as anomaly
# In this case: 1.74 < 2.0, so not flagged (borderline!)

### Understanding Threshold
## The Threshold Decision:

Threshold	Percentile	    Meaning	        Use Case
1.0	        68%	    Flags ~32% as outliers	Very sensitive, many alerts
1.5	        87%	    Flags ~13% as outliers	Security-critical systems
2.0 ⭐	    95%	    Flags ~5% as outliers	Most common choice
2.5	        99%	    Flags ~1% as outliers	Reduce alert fatigue
3.0	        99.7%	Flags ~0.3% as outliers	Only extreme cases

# Visual Representation:
Bell Curve (Normal Distribution):

                    68%
            |-----------------|
                    95%
        |------------------------|
                  99.7%
    |------------------------------|
    
    -3σ  -2σ  -1σ   μ   +1σ  +2σ  +3σ
     |    |    |    |    |    |    |
     |    └─ threshold=2.0
     └─────── threshold=3.0

# Tuning Recommendations
#Start Here:

**Default**: threshold = 2.0
Run on historical data
Observe false positive rate

# Adjust Based on Domain:
# Financial transactions (be cautious)
threshold = 1.8  # Catch fraud early

# System monitoring (balanced)  
threshold = 2.0  # Standard approach

# User notifications (reduce noise)
threshold = 2.5  # Only notify on real issues

# Critical alerts only
threshold = 3.0  # Extreme cases only

# Cost of Errors:

Scenario	        False Positive Cost	        False Negative Cost	    Recommended Threshold
Security            breach	Low (investigate)	Very High (breach!)	    1.5 - 2.0
Spam filter	        Medium (miss email)	        Low (see spam)	        2.0 - 2.5
Fraud detection	    Low (verify)	            High (lose money)	    1.5 - 2.0
Performance alerts	High (alert fatigue)	    Medium (slow system)	2.5 - 3.0
