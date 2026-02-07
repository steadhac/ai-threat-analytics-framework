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

# Threat Classification
## What is Threat Classification?
Threat classification is the process of categorizing identified security threats based on their characteristics, severity, and impact. This enables effective prioritization, response planning, and resource allocation.

## Classification Categories

### By Threat Level


Level	Priority	Response Time	Examples
Critical	Immediate	< 1 hour	Active breach, ransomware, data exfiltration
High	Urgent	< 4 hours	Unauthorized access, privilege escalation
Medium	Important	< 24 hours	Suspicious activity, policy violations
Low	Monitor	< 1 week	Anomalous patterns, failed attempts

### By Threat Type
External Threats:

- Malware & ransomware
- Phishing & social engineering
- DDoS attacks
- SQL injection & web exploits
- Credential stuffing

Internal Threats:

- Insider threats
- Misconfigurations
- Unauthorized access
- Data exfiltration
- Privilege abuse

Emerging Threats:

- Zero-day vulnerabilities
- Advanced persistent threats (APT)
- Supply chain attacks
- Cloud-specific attacks
- AI/ML-based attacks

## Classification Framework

Components to Evaluate:

### 1. Impact Assessment

- Confidentiality: Is sensitive data exposed?
- Integrity: Can data/systems be modified?
- Availability: Are services disrupted?

### 2. Attack Vector

- Network (remote)
- Physical (on-premises)
- Social (human-based)
- Supply chain (third-party)

### 3. Likelihood

- Rare: < 1% chance
- Unlikely: 1-10% chance
- Possible: 10-50% chance
- Likely: 50-90% chance
- Almost Certain: > 90% chance

### 4. Scope

- Single user/system
- Department/segment
- Entire organization
- External partners affected

# Classification Algorithm
``` python
def classify_threat(threat_data):
    """
    Classify a threat based on multiple factors.
    
    Returns: threat_level (Critical, High, Medium, Low)
    """
    
    # Step 1: Calculate impact score (0-100)
    impact_score = (
        confidentiality_risk * 0.4 +
        integrity_risk * 0.35 +
        availability_risk * 0.25
    )
    
    # Step 2: Calculate likelihood score (0-100)
    likelihood_score = (
        attack_vector_score * 0.3 +
        attacker_skill_required * 0.2 +
        historical_frequency * 0.5
    )
    
    # Step 3: Calculate scope multiplier
    scope_multiplier = {
        'single_system': 1.0,
        'segment': 2.0,
        'organization': 5.0,
        'external': 8.0
    }
    
    # Step 4: Calculate risk score
    risk_score = impact_score * likelihood_score * scope_multiplier / 100
    
    # Step 5: Map to threat level
    if risk_score >= 75:
        return "Critical"
    elif risk_score >= 50:
        return "High"
    elif risk_score >= 25:
        return "Medium"
    else:
        return "Low"
```
Real-World Example
Threat: Suspicious login from unusual location

Data:
- Impact: Moderate (unauthorized access possible)
  - Confidentiality: 0.7
  - Integrity: 0.5
  - Availability: 0.3
- Likelihood: Moderate (some suspicious accounts do this)
  - Attack vector: Network (0.8)
  - Skill required: Low (0.7)
  - Historical: 15% of such events (0.6)
- Scope: Single user (1.0)

Calculation:
- Impact: (0.7 * 0.4) + (0.5 * 0.35) + (0.3 * 0.25) = 55
- Likelihood: (0.8 * 0.3) + (0.7 * 0.2) + (0.6 * 0.5) = 68
- Risk: 55 * 68 * 1.0 / 100 = 37.4

Classification: MEDIUM ⚠️
Recommended Action: Verify user, enable MFA, monitor account

## LLM Security Guardrails
### What are LLM Security Guardrails?
LLM (Large Language Model) security guardrails are protective mechanisms designed to prevent misuse, data leakage, and harmful outputs from AI language models. They ensure safe and compliant AI system operation.

## Types of Guardrails
1. Input Validation Guardrails
Prevent malicious or unwanted input from reaching the model.

Techniques:

- Prompt injection detection: Identify attempts to override system instructions
- Input length limits: Prevent buffer overflow attacks
- Content filtering: Block offensive/illegal content in prompts
- Language detection: Ensure expected language input
- Format validation: Verify JSON, SQL, or structured inputs

``` python
def validate_input(user_prompt, max_length=2000):
    """
    Validate user input before sending to LLM.
    """
    
    # Check length
    if len(user_prompt) > max_length:
        raise ValueError(f"Input exceeds {max_length} characters")
    
    # Check for prompt injection patterns
    injection_patterns = [
        "ignore previous instructions",
        "system override",
        "bypass this",
        "forget the system prompt"
    ]
    
    prompt_lower = user_prompt.lower()
    for pattern in injection_patterns:
        if pattern in prompt_lower:
            raise SecurityError(f"Potential prompt injection detected")
    
    # Check for malicious content
    if contains_malware_signatures(user_prompt):
        raise SecurityError("Suspicious content detected")
    
    return True
```
2. Output Validation Guardrails
Control and validate LLM responses before sending to users.

Techniques:

- Content filtering: Block harmful outputs (violence, hate speech, etc.)
- PII redaction: Remove personally identifiable information
- Confidentiality checks: Prevent disclosure of secrets/credentials
- Toxicity scoring: Rate response safety
- Fact verification: Cross-check claims against trusted sources
``` python
def validate_output(llm_response, user_context):
    """
    Validate LLM output for safety before returning to user.
    """
    
    # Step 1: Check for harmful content
    if is_harmful_content(llm_response):
        return "I cannot provide that response."
    
    # Step 2: Redact PII
    redacted = redact_pii(llm_response)
    
    # Step 3: Check for credential leakage
    if contains_credentials(redacted):
        return "Response contains sensitive data and cannot be shared."
    
    # Step 4: Score toxicity
    toxicity_score = calculate_toxicity(redacted)
    if toxicity_score > 0.8:
        return "This response is inappropriate. Please try again."
    
    # Step 5: Verify facts if required
    if user_context.requires_fact_check:
        is_factual = verify_facts(redacted)
        if not is_factual:
            return "Some claims in the response could not be verified."
    
    return redacted
```
3. Rate Limiting & Abuse Prevention
Prevent abuse through excessive API usage or exploitation attempts.

Techniques:

- API rate limiting: Limit requests per user/timeframe
- Request throttling: Spread load over time
- Quota management: Set usage limits per user
- Unusual pattern detection: Flag abnormal usage
- Cost controls: Monitor token/resource usage
``` python
def apply_rate_limiting(user_id, request_timestamp):
    """
    Apply rate limiting to prevent abuse.
    """
    
    # Check requests in last hour
    recent_requests = get_user_requests(user_id, hours=1)
    
    if len(recent_requests) > 100:  # 100 requests/hour
        raise RateLimitError("Too many requests. Try again later.")
    
    # Check burst activity (last 5 minutes)
    burst_requests = get_user_requests(user_id, minutes=5)
    if len(burst_requests) > 20:  # 20 requests/5min
        raise RateLimitError("Request spike detected. Please slow down.")
    
    return True
```
4. Data & Privacy Guardrails
Protect sensitive data and ensure compliance.

Techniques:

- Data encryption: Protect data in transit/at rest
- Access controls: Restrict who can use the LLM
- Audit logging: Track all requests and responses
- Anonymization: Remove identifying information
- Compliance checks: Ensure GDPR, HIPAA, etc. compliance
``` python
def apply_privacy_guardrails(request, user_role):
    """
    Apply privacy controls based on user role and data sensitivity.
    """
    
    # Step 1: Classify data sensitivity
    data_classification = classify_data_sensitivity(request)
    
    # Step 2: Verify access rights
    if not user_has_access(user_role, data_classification):
        raise PermissionError("Insufficient permissions for this data")
    
    # Step 3: Encrypt sensitive data
    if data_classification == "Confidential":
        request = encrypt_request(request)
    
    # Step 4: Log for audit trail
    log_request(user_id, request, data_classification)
    
    # Step 5: Apply retention policy
    set_data_retention(request_id, data_classification)
    
    return request
```
Guardrail Configuration
Example Configuration:
``` yaml
guardrails:
  input_validation:
    max_length: 2000
    check_injection: true
    blocked_keywords: ["malware", "virus", "exploit"]
    
  output_validation:
    filter_harmful: true
    redact_pii: true
    check_credentials: true
    toxicity_threshold: 0.8
    
  rate_limiting:
    requests_per_hour: 100
    requests_per_minute: 20
    burst_limit: 5
    
  privacy:
    encrypt_data: true
    require_auth: true
    audit_logging: true
    retention_days: 30
```
## Text Summarization
### What is Text Summarization?
Text summarization is the process of reducing a large body of text into a shorter, coherent summary that captures the key information and main ideas while preserving essential meaning.

## Types of Summarization
1. Extractive Summarization
Selects and combines important sentences directly from the original text.

Characteristics:

- Uses original text fragments
- No new text generation
- Faster and more predictable
- May lack coherence
- Algorithm: TF-IDF (Term Frequency-Inverse Document Frequency)
``` python
def extractive_summarize(text, summary_ratio=0.3):
    """
    Create extractive summary using TF-IDF scoring.
    """
    
    # Step 1: Split into sentences
    sentences = split_into_sentences(text)
    
    # Step 2: Calculate TF-IDF scores
    tfidf_scores = {}
    for i, sentence in enumerate(sentences):
        words = tokenize(sentence)
        score = 0
        for word in words:
            tf = calculate_term_frequency(word, sentence)
            idf = calculate_inverse_document_frequency(word, text)
            score += tf * idf
        tfidf_scores[i] = score / len(words)  # Normalize
    
    # Step 3: Select top sentences
    num_sentences = max(1, int(len(sentences) * summary_ratio))
    top_indices = sorted(tfidf_scores.items(), 
                         key=lambda x: x[1], 
                         reverse=True)[:num_sentences]
    
    # Step 4: Arrange in original order
    top_indices = sorted([idx for idx, _ in top_indices])
    summary = " ".join([sentences[idx] for idx in top_indices])
    
    return summary
```
2. Abstractive Summarization
Generates new text that captures the essence of the original content.

Characteristics:

- Generates new sentences
- More natural and concise
- Requires NLP/deep learning models
- May introduce errors
- Algorithm: Sequence-to-Sequence with Attention
``` python
def abstractive_summarize(text, max_length=150):
    """
    Create abstractive summary using seq2seq model.
    
    This uses transformer-based models (e.g., BART, T5).
    """
    
    # Step 1: Tokenize input
    input_ids = tokenizer.encode(text, return_tensors="pt")
    
    # Step 2: Generate summary
    summary_ids = model.generate(
        input_ids,
        max_length=max_length,
        min_length=50,
        length_penalty=2.0,
        num_beams=4,
        early_stopping=True
    )
    
    # Step 3: Decode output
    summary = tokenizer.decode(summary_ids[0], skip_special_tokens=True)
    
    return summary
```

Summarization Quality Metrics
ROUGE (Recall-Oriented Understudy for Gisting Evaluation)
``` python
def evaluate_summary_quality(generated_summary, reference_summary):
    """
    Evaluate summary using ROUGE metrics.
    """
    
    # ROUGE-1: Unigram overlap
    rouge1 = calculate_rouge(generated_summary, reference_summary, n=1)
    
    # ROUGE-2: Bigram overlap
    rouge2 = calculate_rouge(generated_summary, reference_summary, n=2)
    
    # ROUGE-L: Longest common subsequence
    rougel = calculate_longest_common_subsequence(
        generated_summary, 
        reference_summary
    )
    
    print(f"ROUGE-1: {rouge1:.3f}")
    print(f"ROUGE-2: {rouge2:.3f}")
    print(f"ROUGE-L: {rougel:.3f}")
    
    # Overall quality score
    quality_score = (rouge1 + rouge2 + rougel) / 3
    
    if quality_score > 0.4:
        return "High Quality ✅"
    elif quality_score > 0.25:
        return "Medium Quality ⚠️"
    else:
        return "Low Quality ❌"
```

Real-World Example
Original Article (500 words):
The global renewable energy sector has experienced unprecedented growth over 
the past decade. Solar and wind technologies have become increasingly cost-effective, 
driving massive investments from both public and private sectors. According to recent 
reports, renewable energy now accounts for 27% of global electricity generation, up 
from just 12% in 2010. 

China leads in renewable capacity installations, followed by the United States and 
European nations. Battery storage technology improvements have addressed intermittency 
challenges, making renewables more viable for baseload power. Major corporations are 
committing to 100% renewable energy targets, creating demand for green infrastructure.

[... continues for 450 more words ...]

Extractive Summary (35% compression):

The global renewable energy sector has experienced unprecedented growth. Renewable 
energy now accounts for 27% of global electricity generation, up from just 12% in 2010. 
China leads in renewable capacity installations, followed by the United States and 
European nations. Battery storage technology improvements have addressed intermittency 
challenges.

Abstractive Summary (50% compression):

Renewable energy has grown significantly over the past decade, now representing 27% 
of global electricity. Advancements in solar, wind, and battery technologies have made 
renewables cost-competitive, with China, the US, and Europe leading installations. 
Major corporations are increasingly committing to renewable energy targets.

Summarization Best Practices


Aspect	Recommendation	Details
Length	30-40% of original	Balance brevity with information retention
Key Points	Identify 3-5 main ideas	Focus on what matters most
Coherence	Ensure logical flow	Use transitional phrases
Accuracy	Verify facts	Don't introduce false information
Language	Match source tone	Maintain professional style
Structure	Follow chronological/logical order	Make it easy to follow

When to Use Each Approach

Use Extractive Summarization for:

- Technical documentation
- Legal documents
- Financial reports
- When accuracy is critical

Use Abstractive Summarization for:

- News articles
- Blog posts
- Long-form content
- When conciseness matters
- Social media sharing

Hybrid Approach:

Combine both methods for optimal results:

- Extractive: Select key sentences
- Abstractive: Polish and rephrase
- Output: Natural, concise summary
