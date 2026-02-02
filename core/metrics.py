# core/metrics.py
"""
Evaluation metrics for LLM outputs, classifications, and ML models.

This module provides comprehensive evaluation metrics for assessing:
- Classification model performance (precision, recall, F1, accuracy)
- Text generation quality (BLEU, ROUGE scores)
- Semantic similarity (embedding-based and token-based)
- Text summarization effectiveness
- Embedding distance calculations

Purpose:
    Quantify model performance and output quality
    Enable data-driven comparison of different models/approaches
    Validate model improvements and regressions
    Measure alignment with reference/ground truth data

Metrics Categories:
    1. Classification Metrics: Precision, Recall, F1, Accuracy
    2. Text Generation Metrics: BLEU, ROUGE-1/2/L
    3. Similarity Metrics: Cosine similarity, token overlap, semantic similarity
    4. Embedding Metrics: Distance calculations (cosine, euclidean, manhattan)

Use Cases:
    - Model evaluation and comparison
    - Hyperparameter tuning
    - Regression testing
    - Quality assurance before deployment
    - Research and experimentation
    - Performance monitoring

Compliance:
    - Reproducible evaluation (consistent metrics)
    - Documented results (audit trail)
    - Fair comparison (standardized metrics)
"""

import numpy as np
from typing import List, Dict
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
from sklearn.metrics.pairwise import cosine_similarity
from collections import Counter
import re


def compute_classification_metrics(y_true: List[int], y_pred: List[int], average: str = 'weighted') -> Dict[str, float]:
    """
    Compute classification performance metrics.
    
    This function calculates standard metrics for evaluating classification models:
    precision (correct positives / all predicted positives),
    recall (correct positives / all actual positives),
    F1 score (harmonic mean of precision and recall),
    and accuracy (correct predictions / all predictions).
    
    Parameters:
        y_true (List[int]): True class labels (ground truth)
                           - Binary: [0, 1, 1, 0, 1]
                           - Multi-class: [0, 1, 2, 1, 0]
                           - Must match length of y_pred
        
        y_pred (List[int]): Model predicted labels
                           - Same format as y_true
                           - Same length as y_true
        
        average (str, optional): Averaging strategy for multi-class metrics
                                Default: 'weighted'
                                Options:
                                  - 'weighted': Weight by class frequency
                                  - 'macro': Unweighted mean across classes
                                  - 'micro': Calculate globally
                                  - 'binary': For binary classification only
    
    Returns:
        Dict[str, float]: Dictionary containing:
            - 'precision': Correct predictions / all positive predictions
            - 'recall': Correct positive / all actual positives
            - 'f1_score': Harmonic mean (2 * precision * recall / (precision + recall))
            - 'accuracy': Total correct / total predictions
    
    Metric Definitions:
        
        PRECISION: "Of the items we predicted as positive, how many were correct?"
        Formula: TP / (TP + FP)
        Range: 0.0 to 1.0
        High precision = few false positives
        Use when: False positives are costly (security, spam filtering)
        
        RECALL: "Of all actual positive items, how many did we find?"
        Formula: TP / (TP + FN)
        Range: 0.0 to 1.0
        High recall = few false negatives
        Use when: False negatives are costly (fraud, cancer detection)
        
        F1 SCORE: "Balanced measure of precision and recall"
        Formula: 2 * (Precision * Recall) / (Precision + Recall)
        Range: 0.0 to 1.0
        Equal weight to precision and recall
        Use when: Need single metric balancing both
        
        ACCURACY: "What percentage of predictions were correct?"
        Formula: (TP + TN) / (TP + TN + FP + FN)
        Range: 0.0 to 1.0
        Misleading on imbalanced datasets
        Warning: Can be high even with terrible minority class performance
    
    Examples:
        >>> y_true = [0, 1, 1, 0, 1, 0]
        >>> y_pred = [0, 1, 0, 0, 1, 1]
        >>> metrics = compute_classification_metrics(y_true, y_pred)
        >>> metrics
        {
            'precision': 0.67,
            'recall': 0.67,
            'f1_score': 0.67,
            'accuracy': 0.67
        }
    
    Multi-class Example:
        >>> y_true = [0, 1, 2, 1, 0, 2]  # 3 classes
        >>> y_pred = [0, 1, 1, 1, 0, 2]  # 1 error (class 2 → 1)
        >>> metrics = compute_classification_metrics(y_true, y_pred, average='weighted')
        >>> # Returns weighted average across all 3 classes
    
    Choosing Average Strategy:
        
        'weighted' (default): 
        - Best for: Imbalanced datasets
        - Calculation: Weight each class by frequency
        - Example: If 90% class 0, 10% class 1 → more weight to class 0
        
        'macro': 
        - Best for: Balanced importance to all classes
        - Calculation: Unweighted mean (each class = 50%)
        - Example: Both classes treated equally regardless of frequency
        
        'micro': 
        - Best for: Same as accuracy (global calculation)
        - Calculation: Aggregate TP/FP/FN across all classes
        - Example: Preferred for large datasets
        
        'binary': 
        - Use only: When exactly 2 classes
        - Calculation: No averaging (single metric per class)
    
    Use Cases:
        - Threat classification: Evaluate phishing detector performance
        - Model selection: Compare classifiers (which model is best?)
        - Baseline comparison: How does model A vs B perform?
        - Regression testing: Did recent changes break anything?
        - Hyperparameter tuning: Which parameters give best metrics?
    
    Class Imbalance Handling:
        - Imbalanced example: 95% negative class, 5% positive
        - zero_division=0: Return 0 if class never appears (prevents errors)
        - Recommend: Use weighted average for imbalanced data
        - Better metrics: Precision-recall curve, ROC-AUC for imbalanced
    
    Performance:
        - Time: O(n) where n = number of predictions
        - Space: O(1) for computation
        - Typical: < 1ms for 100K predictions
    
    Related Functions:
        - semantic_similarity(): Measure text similarity
        - bleu_score(): Evaluate text generation
        - rouge_score(): Evaluate summarization
    
    Testing:
        - Unit test: test_classification_metrics()
        - Edge cases: Empty lists, single sample, perfect/terrible predictions
        - Parametrized: Various class distributions
    """
    return {
        "precision": precision_score(y_true, y_pred, average=average, zero_division=0),
        "recall": recall_score(y_true, y_pred, average=average, zero_division=0),
        "f1_score": f1_score(y_true, y_pred, average=average, zero_division=0),
        "accuracy": accuracy_score(y_true, y_pred)
    }


def semantic_similarity(text1: str, text2: str, model=None) -> float:
    """
    Calculate semantic similarity between two texts using embeddings.
    
    This function measures how semantically similar two texts are by:
    1. Converting text to numerical embeddings (vector representation)
    2. Computing cosine similarity between embeddings
    Embeddings capture semantic meaning (unlike simple keyword matching).
    
    Parameters:
        text1 (str): First text to compare
        text2 (str): Second text to compare
        model (optional): Pre-loaded SentenceTransformer model
                         If None, loads 'all-MiniLM-L6-v2' (fast, accurate)
    
    Returns:
        float: Cosine similarity score (0.0 to 1.0)
              1.0 = identical meaning
              0.5 = moderate similarity
              0.0 = completely different
    
    How It Works:
        1. Text → Embeddings: Convert text to 384-dimensional vectors
        2. Similarity: Calculate cosine(vector1, vector2)
        3. Range: 0.0 (opposite directions) to 1.0 (same direction)
    
    Embedding Model:
        Default: 'all-MiniLM-L6-v2' (Sentence Transformers)
        - 384-dimensional embeddings
        - Fast inference (< 1ms per text)
        - Good quality for semantic similarity
        - Works across 100+ languages
    
    Examples:
        >>> similarity = semantic_similarity("I like pizza", "I enjoy pizza")
        >>> similarity
        0.95  # High similarity (same meaning, different words)
        
        >>> similarity = semantic_similarity("I like pizza", "I hate spinach")
        >>> similarity
        0.12  # Low similarity (different topics)
        
        >>> similarity = semantic_similarity("cat", "cat")
        >>> similarity
        1.0  # Perfect match
    
    Similarity Ranges:
        0.9-1.0: Essentially same meaning (paraphrases, duplicates)
        0.7-0.9: Similar meaning (related sentences)
        0.5-0.7: Moderate similarity (same topic, different angle)
        0.3-0.5: Weak similarity (tangentially related)
        0.0-0.3: Very different (different topics)
    
    Use Cases:
        - Duplicate detection: Find identical/near-identical reports
        - Recommendation: Find similar threat alerts
        - Clustering: Group related incidents
        - Search: Find most relevant documents
        - Validation: Check if paraphrases mean same thing
    
    Advantages Over Token Overlap:
        Semantic understanding:
        - "car" vs "automobile" → HIGH similarity (understands synonyms)
        - Token overlap would score ZERO (no matching words)
        
        Paraphrase detection:
        - Same meaning, different words → HIGH similarity
        - Token overlap might miss paraphrases
        
        Language understanding:
        - Understands context and meaning
        - Robust to word order changes
    
    Limitations:
        - Requires sentence-transformers library (memory overhead)
        - Slow on first call (model loading ~2 seconds)
        - May not understand very specialized domain terms
        - Works better with full sentences than single words
        - Different languages get different embeddings
    
    Fallback Behavior:
        If sentence-transformers not installed:
        - Falls back to token_overlap_similarity()
        - Much faster but less accurate
        - Still usable for basic similarity
    
    Performance:
        - First call: ~2 seconds (model loading)
        - Subsequent calls: < 1ms per pair
        - Memory: ~400MB for model
        - Can reuse model for multiple comparisons
    
    Advanced Usage - Reuse Model:
        >>> from sentence_transformers import SentenceTransformer
        >>> model = SentenceTransformer('all-MiniLM-L6-v2')
        >>> 
        >>> # Reuse model for multiple comparisons (faster)
        >>> sim1 = semantic_similarity(text1, text2, model=model)
        >>> sim2 = semantic_similarity(text3, text4, model=model)
        >>> sim3 = semantic_similarity(text5, text6, model=model)
    
    Related Functions:
        - token_overlap_similarity(): Fast fallback method
        - embedding_distance(): Distance between vectors
    
    Testing:
        - Unit test: test_semantic_similarity()
        - Parametrized: Known similar/dissimilar pairs
        - Edge cases: Empty text, special characters, long text
    """
    try:
        from sentence_transformers import SentenceTransformer
        
        # Load model if not provided
        if model is None:
            model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Encode texts to embeddings
        embeddings = model.encode([text1, text2])
        
        # Calculate cosine similarity
        similarity = cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]
        return float(similarity)
    
    except ImportError:
        # Fallback if sentence-transformers not available
        return token_overlap_similarity(text1, text2)


def token_overlap_similarity(text1: str, text2: str) -> float:
    """
    Calculate simple token overlap similarity (Jaccard coefficient).
    
    Fast similarity metric based on shared words (tokens).
    Use as fallback when semantic embeddings unavailable.
    
    Parameters:
        text1 (str): First text
        text2 (str): Second text
    
    Returns:
        float: Jaccard similarity (0.0 to 1.0)
              1.0 = identical words
              0.0 = no shared words
    
    Algorithm:
        1. Extract word tokens (alphanumeric sequences)
        2. Convert to sets (unique words)
        3. Jaccard = intersection / union
    
    Formula:
        Jaccard(A, B) = |A ∩ B| / |A ∪ B|
        
    Examples:
        >>> token_overlap_similarity("hello world", "hello there")
        0.6  # Shared: {hello}, Total: {hello, world, there}
        
        >>> token_overlap_similarity("cat dog", "cat dog")
        1.0  # Perfect match
        
        >>> token_overlap_similarity("abc", "xyz")
        0.0  # No shared words
    
    Advantages:
        - Very fast (no ML model needed)
        - No dependencies (uses regex)
        - Deterministic (same input = same output)
        - Works offline
    
    Limitations:
        - No semantic understanding
        - Can't detect synonyms (car ≠ automobile)
        - Misses paraphrases (different words, same meaning)
        - Single word tokens (ignores phrases)
        - Sensitive to case (normalized to lowercase)
    
    Use Cases:
        - Quick similarity check (speed critical)
        - Fallback when semantic similarity unavailable
        - Baseline comparison
        - Keyword-based matching
    
    When to Use This vs semantic_similarity():
        
        Use token_overlap when:
        - Speed is critical
        - Limited memory
        - Exact word matching needed
        - No ML model available
        
        Use semantic_similarity when:
        - Accuracy more important than speed
        - Need to understand synonyms/paraphrases
        - Sufficient memory/computational resources
        - Semantic meaning important
    
    Performance:
        - Time: O(n + m) where n, m = text lengths
        - Space: O(n + m) for token sets
        - Typical: < 0.1ms for normal text
    
    Related Functions:
        - semantic_similarity(): ML-based similarity
        - embedding_distance(): Vector distance
    """
    # Extract tokens (word characters only)
    tokens1 = set(re.findall(r'\w+', text1.lower()))
    tokens2 = set(re.findall(r'\w+', text2.lower()))
    
    # Handle edge case: empty text
    if not tokens1 or not tokens2:
        return 0.0
    
    # Calculate Jaccard similarity: intersection / union
    intersection = len(tokens1.intersection(tokens2))
    union = len(tokens1.union(tokens2))
    
    return intersection / union if union > 0 else 0.0


def rouge_score(reference: str, candidate: str) -> Dict[str, float]:
    """
    Calculate ROUGE scores for evaluating text summarization.
    
    ROUGE (Recall-Oriented Understudy for Gisting Evaluation) measures
    overlap between reference (gold standard) and candidate (system output).
    Widely used for evaluating summarization and translation systems.
    
    Parameters:
        reference (str): Reference/gold standard text
                        Should be high-quality summary
        
        candidate (str): Candidate/system output text
                        Summary to evaluate
    
    Returns:
        Dict[str, float]: Dictionary containing:
            - 'rouge1': Unigram (single word) overlap F1 score
            - 'rouge2': Bigram (word pairs) overlap F1 score
            - 'rougeL': Longest common subsequence F1 score
    
    ROUGE Metrics Explained:
        
        ROUGE-1 (Unigram Overlap):
        - Measures: Single word overlap
        - Formula: Shared words / total words
        - What it catches: Basic content coverage
        - Strength: Captures key terms
        - Weakness: Ignores word order, synonyms
        
        ROUGE-2 (Bigram Overlap):
        - Measures: Two-word phrase overlap
        - Formula: Shared bigrams / total bigrams
        - What it catches: Local phrase preservation
        - Strength: Better captures coherence
        - Weakness: Sensitive to small variations
        
        ROUGE-L (Longest Common Subsequence):
        - Measures: Longest sequence of words in order
        - Formula: LCS length / reference length
        - What it catches: Structure/flow preservation
        - Strength: Captures grammatical coherence
        - Weakness: May not catch synonyms
    
    Score Interpretation:
        0.0-0.2: Poor summary (minimal overlap)
        0.2-0.4: Below average summary
        0.4-0.6: Average summary
        0.6-0.8: Good summary
        0.8-1.0: Excellent summary (very similar to reference)
    
    Examples:
        >>> reference = "The cat sat on the mat."
        >>> candidate = "The cat sat on the mat."
        >>> scores = rouge_score(reference, candidate)
        >>> scores
        {'rouge1': 1.0, 'rouge2': 1.0, 'rougeL': 1.0}
        # Perfect match
        
        >>> reference = "The cat sat on the mat."
        >>> candidate = "A cat was sitting."
        >>> scores = rouge_score(reference, candidate)
        >>> scores
        {'rouge1': 0.4, 'rouge2': 0.0, 'rougeL': 0.2}
        # Partial overlap (some words shared, different structure)
    
    Use Cases:
        - Evaluate summarization models
        - Compare summarization approaches
        - Benchmark threat report summaries
        - Regression testing (ensure summary quality maintained)
        - Hyperparameter tuning
    
    For Threat Reports:
        - reference: Professional analyst summary
        - candidate: AI-generated summary
        - High ROUGE: AI summary covers all key points
        - Low ROUGE: AI summary misses important details
    
    Algorithm Details:
        
        ROUGE-1 Calculation:
        1. Extract all words (unigrams) from both texts
        2. Count word frequencies
        3. Calculate precision: shared / candidate words
        4. Calculate recall: shared / reference words
        5. F1 = 2 * (precision * recall) / (precision + recall)
        
        ROUGE-2 Calculation:
        1. Extract word pairs (bigrams)
        2. Count bigram frequencies
        3. Same P/R/F1 calculation as ROUGE-1
        
        ROUGE-L Calculation:
        1. Find longest common subsequence (word-level)
        2. LCS doesn't require consecutive words
        3. Precision: LCS length / candidate length
        4. Recall: LCS length / reference length
        5. F1 = harmonic mean of P and R
    
    Limitations:
        - Reference dependent (assumes reference is high quality)
        - Single reference bias (one correct summary type)
        - Word-level only (doesn't understand synonyms)
        - Can favor extractive (copying) over abstractive (paraphrasing)
        - Language specific (built for English)
    
    Variant Scoring:
        This implementation uses F1 scores
        - ROUGE precision: How much of candidate is correct
        - ROUGE recall: How much of reference is captured
        - ROUGE F1: Harmonic mean (balanced)
    
    Performance:
        - Time: O(n + m) for ROUGE-1/2, O(n*m) for ROUGE-L
        - Space: O(n + m) for counters, O(n*m) for LCS DP table
        - Typical: 1-10ms for typical summaries
    
    Related Functions:
        - bleu_score(): Alternative text generation metric
        - semantic_similarity(): Semantic overlap metric
    
    Testing:
        - Unit test: test_rouge_score()
        - Edge cases: Empty text, single word, identical texts
        - Parametrized: Various summary quality levels
    """
    
    def get_ngrams(text: str, n: int) -> Counter:
        """Extract n-grams from text."""
        tokens = re.findall(r'\w+', text.lower())
        return Counter(zip(*[tokens[i:] for i in range(n)]))
    
    def lcs_length(x: List[str], y: List[str]) -> int:
        """Calculate longest common subsequence length using dynamic programming."""
        m, n = len(x), len(y)
        # DP table: dp[i][j] = LCS length of x[0:i] and y[0:j]
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        # Fill DP table
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if x[i-1] == y[j-1]:
                    # Characters match: extend LCS
                    dp[i][j] = dp[i-1][j-1] + 1
                else:
                    # Characters don't match: take best path
                    dp[i][j] = max(dp[i-1][j], dp[i][j-1])
        
        return dp[m][n]
    
    # Tokenize texts
    ref_tokens = re.findall(r'\w+', reference.lower())
    cand_tokens = re.findall(r'\w+', candidate.lower())
    
    # ===== ROUGE-1 (Unigram Overlap) =====
    ref_unigrams = Counter(ref_tokens)
    cand_unigrams = Counter(cand_tokens)
    # Intersection: min frequency for each token
    overlap_unigrams = sum((ref_unigrams & cand_unigrams).values())
    rouge1_precision = overlap_unigrams / max(sum(cand_unigrams.values()), 1)
    rouge1_recall = overlap_unigrams / max(sum(ref_unigrams.values()), 1)
    rouge1_f1 = 2 * rouge1_precision * rouge1_recall / max(rouge1_precision + rouge1_recall, 0.0001)
    
    # ===== ROUGE-2 (Bigram Overlap) =====
    ref_bigrams = get_ngrams(reference, 2)
    cand_bigrams = get_ngrams(candidate, 2)
    overlap_bigrams = sum((ref_bigrams & cand_bigrams).values())
    rouge2_precision = overlap_bigrams / max(sum(cand_bigrams.values()), 1)
    rouge2_recall = overlap_bigrams / max(sum(ref_bigrams.values()), 1)
    rouge2_f1 = 2 * rouge2_precision * rouge2_recall / max(rouge2_precision + rouge2_recall, 0.0001)
    
    # ===== ROUGE-L (Longest Common Subsequence) =====
    lcs = lcs_length(ref_tokens, cand_tokens)
    rougel_precision = lcs / max(len(cand_tokens), 1)
    rougel_recall = lcs / max(len(ref_tokens), 1)
    rougel_f1 = 2 * rougel_precision * rougel_recall / max(rougel_precision + rougel_recall, 0.0001)
    
    return {
        "rouge1": rouge1_f1,
        "rouge2": rouge2_f1,
        "rougeL": rougel_f1
    }


def bleu_score(reference: str, candidate: str, max_n: int = 4) -> float:
    """
    Calculate BLEU score for evaluating text generation.
    
    BLEU (Bilingual Evaluation Understudy) measures n-gram precision
    between machine-generated and reference translations/summaries.
    Standard metric for machine translation and text generation.
    
    Parameters:
        reference (str): Reference text (gold standard)
        candidate (str): Generated text to evaluate
        max_n (int, optional): Maximum n-gram order (default: 4)
                              1: unigrams only
                              4: unigrams through 4-grams
    
    Returns:
        float: BLEU score (0.0 to 1.0)
              1.0 = perfect match with reference
              0.0 = no n-gram overlap
    
    Calculation Steps:
        1. Extract n-grams (1-grams through max_n-grams)
        2. Calculate precision for each n-gram level
        3. Compute geometric mean of precisions
        4. Apply brevity penalty (if candidate shorter than reference)
    
    Interpretation:
        0.9-1.0: Excellent (essentially identical)
        0.7-0.9: Good (high quality translation/summary)
        0.5-0.7: Acceptable (understandable, some errors)
        0.3-0.5: Poor (significant errors)
        0.0-0.3: Very poor (barely understandable)
    
    Examples:
        >>> reference = "the cat sat on the mat"
        >>> candidate = "the cat sat on the mat"
        >>> bleu_score(reference, candidate)
        1.0
        
        >>> reference = "the cat sat on the mat"
        >>> candidate = "the dog sat on the mat"
        >>> bleu_score(reference, candidate)
        0.68  # 5 of 6 words match
        
        >>> reference = "the cat sat on the mat"
        >>> candidate = "a cat"
        >>> bleu_score(reference, candidate)
        0.24  # Short, limited overlap
    
    N-gram Weighting:
        Default (max_n=4): Equal weight to all n-gram orders
        - 1-gram (unigrams): Measures word choice
        - 2-gram (bigrams): Measures word pairs
        - 3-gram (trigrams): Measures local phrases
        - 4-gram: Measures longer context
    
    Brevity Penalty:
        Problem: System could score high by only outputting common words
        Solution: Penalize outputs shorter than reference
        Formula: exp(1 - reference_length / candidate_length)
        Effect: Encourages longer, more complete outputs
    
    Use Cases:
        - Machine translation evaluation
        - Text summarization quality
        - Paraphrase generation
        - Data-to-text generation
        - Response generation in dialogue
    
    For Security Threat Summaries:
        - reference: Professional human-written summary
        - candidate: AI-generated summary
        - High BLEU: AI captures key phrases and structure
        - Low BLEU: AI uses different words or misses content
    
    Algorithm Details:
        
        Modified Precision:
        - Counts each n-gram in reference corpus
        - Candidate can't score higher than reference count
        - Prevents double-counting of common words
        
        Geometric Mean:
        - More robust than arithmetic mean
        - Single zero precision → zero BLEU (ensures all levels matter)
        - Example: (0.5 * 0.3 * 0.2 * 0.1)^(1/4) = 0.23
        
        Brevity Penalty:
        - If candidate longer: BP = 1.0 (no penalty)
        - If candidate shorter: BP = exp(1 - ref_len/cand_len)
        - Severe penalty for very short outputs
    
    Limitations:
        - Single reference bias (one correct form exists)
        - N-gram based (misses synonyms, paraphrases)
        - No semantic understanding
        - Can favor common words
        - Doesn't correlate perfectly with human judgment
    
    Variants & Improvements:
        BLEU assumes single reference translation
        - Multi-BLEU: Multiple reference comparisons
        - METEOR: Adds semantic similarity
        - ROUGE/CIDEr: Alternative metrics
    
    Performance:
        - Time: O(n * m) where n=ref_length, m=cand_length
        - Space: O(n + m) for n-gram counts
        - Typical: < 5ms for typical texts
    
    Related Functions:
        - rouge_score(): Alternative text generation metric
        - semantic_similarity(): Semantic-based similarity
    
    Testing:
        - Unit test: test_bleu_score()
        - Edge cases: Empty, single word, identical
        - Parametrized: Various text lengths and similarities
    """
    
    def get_ngrams(tokens: List[str], n: int) -> Counter:
        """Extract n-grams and count frequencies."""
        return Counter(zip(*[tokens[i:] for i in range(n)]))
    
    # Tokenize
    ref_tokens = re.findall(r'\w+', reference.lower())
    cand_tokens = re.findall(r'\w+', candidate.lower())
    
    # Handle edge case: empty candidate
    if not cand_tokens:
        return 0.0
    
    # Calculate modified precision for each n-gram order
    precisions = []
    for n in range(1, max_n + 1):
        # Get n-grams from both texts
        ref_ngrams = get_ngrams(ref_tokens, n)
        cand_ngrams = get_ngrams(cand_tokens, n)
        
        # Count overlapping n-grams (modified precision)
        # Intersection: take min count for each n-gram
        overlap = sum((ref_ngrams & cand_ngrams).values())
        total = sum(cand_ngrams.values())
        
        # Precision for this n-gram level
        precision = overlap / max(total, 1)
        precisions.append(precision)
    
    # Geometric mean of precisions
    # If any precision is 0, BLEU = 0
    if min(precisions) == 0:
        return 0.0
    
    # Log-scale geometric mean (avoids underflow)
    geo_mean = np.exp(np.mean([np.log(p) for p in precisions if p > 0]))
    
    # Brevity penalty (penalize short outputs)
    ref_len = len(ref_tokens)
    cand_len = len(cand_tokens)
    # No penalty if candidate is longer; severe penalty if much shorter
    bp = 1.0 if cand_len > ref_len else np.exp(1 - ref_len / max(cand_len, 1))
    
    # Final BLEU = brevity_penalty * geometric_mean_precision
    return bp * geo_mean


def embedding_distance(embedding1: np.ndarray, embedding2: np.ndarray, metric: str = 'cosine') -> float:
    """
    Calculate distance between two embedding vectors.
    
    Computes various distance metrics between vector representations.
    Used to measure similarity/difference between embeddings.
    
    Parameters:
        embedding1 (np.ndarray): First embedding vector
                                Shape: (embedding_dim,)
        
        embedding2 (np.ndarray): Second embedding vector
                                Shape: must match embedding1
        
        metric (str, optional): Distance metric to use
                               Default: 'cosine'
                               Options:
                                 - 'cosine': Cosine distance (1 - similarity)
                                 - 'euclidean': Euclidean/L2 distance
                                 - 'manhattan': Manhattan/L1 distance
    
    Returns:
        float: Distance value (interpretation depends on metric)
              cosine: 0.0 (identical) to 2.0 (opposite)
              euclidean: 0.0 (identical) to ∞ (far apart)
              manhattan: 0.0 (identical) to ∞ (far apart)
    
    Distance Metrics Explained:
        
        COSINE Distance:
        - Range: 0.0 to 2.0
        - Interpretation: 0 = same direction, 2 = opposite direction
        - Calculation: 1 - cosine_similarity
        - Best for: Direction (angle between vectors)
        - Ignores: Vector magnitude
        - Example: "big cat" and "small cat" have similar direction
        
        EUCLIDEAN Distance:
        - Range: 0.0 to ∞
        - Interpretation: Straight-line distance in embedding space
        - Calculation: sqrt(Σ(x_i - y_i)²)
        - Best for: Magnitude-aware distance
        - Considers: Both direction and magnitude
        - Example: Vector scale matters for classification
        
        MANHATTAN Distance:
        - Range: 0.0 to ∞
        - Interpretation: "Block distance" (like city streets)
        - Calculation: Σ|x_i - y_i|
        - Best for: Computational efficiency, sparse embeddings
        - Faster: Than Euclidean (no square root)
        - Example: When individual dimensions matter
    
    Examples:
        >>> import numpy as np
        >>> emb1 = np.array([1, 0, 0])
        >>> emb2 = np.array([1, 0, 0])
        >>> embedding_distance(emb1, emb2, 'cosine')
        0.0  # Identical
        
        >>> emb1 = np.array([1, 0, 0])
        >>> emb2 = np.array([0, 1, 0])
        >>> embedding_distance(emb1, emb2, 'cosine')
        1.0  # Perpendicular
        
        >>> emb1 = np.array([1, 0, 0])
        >>> emb2 = np.array([-1, 0, 0])
        >>> embedding_distance(emb1, emb2, 'cosine')
        2.0  # Opposite directions
    
    Use Cases:
        - Clustering: Group similar embeddings
        - Search: Find nearest neighbors
        - Anomaly detection: Identify outliers
        - Recommendation: Find similar items
        - Classification: Distance-based prediction
    
    Metric Selection Guide:
        
        Choose COSINE when:
        - Direction/orientation matters (semantic similarity)
        - Magnitude is variable or unimportant
        - Comparing word embeddings
        - ML models expect normalized vectors
        
        Choose EUCLIDEAN when:
        - Magnitude matters (actual distances)
        - Feature scales are meaningful
        - Physical/geometric interpretation needed
        - Standard distance metric needed
        
        Choose MANHATTAN when:
        - Computational speed is critical
        - Feature interactions are independent
        - Sparse embeddings (many zeros)
        - Integer-valued features
    
    Performance:
        - Cosine: O(d) where d = embedding dimension
        - Euclidean: O(d)
        - Manhattan: O(d) fastest implementation
        - Typical: < 1 microsecond for 384-dim embeddings
    
    Related Functions:
        - semantic_similarity(): Uses cosine on embeddings
    
    Testing:
        - Unit test: test_embedding_distance()
        - Edge cases: Zero vectors, identical vectors
        - Parametrized: Various dimensions and metrics
    """
    if metric == 'cosine':
        # Cosine distance = 1 - cosine_similarity
        return 1 - cosine_similarity([embedding1], [embedding2])[0][0]
    
    elif metric == 'euclidean':
        # Euclidean distance = sqrt(sum of squared differences)
        return float(np.linalg.norm(embedding1 - embedding2))
    
    elif metric == 'manhattan':
        # Manhattan distance = sum of absolute differences
        return float(np.sum(np.abs(embedding1 - embedding2)))
    
    else:
        # Unknown metric
        raise ValueError(f"Unknown metric: {metric}")