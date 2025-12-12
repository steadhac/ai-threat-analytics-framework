# core/metrics.py
"""
Evaluation metrics for LLM outputs, classifications, and ML models.
Includes precision, recall, BLEU, ROUGE, and embedding similarity.
"""
import numpy as np
from typing import List, Dict, Any, Tuple
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
from sklearn.metrics.pairwise import cosine_similarity
from collections import Counter
import re


def compute_classification_metrics(y_true: List[int], y_pred: List[int], average: str = 'weighted') -> Dict[str, float]:
    """
    Compute classification metrics.
    
    Args:
        y_true: True labels
        y_pred: Predicted labels
        average: Averaging strategy for multi-class
        
    Returns:
        Dictionary of metrics
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
    
    Args:
        text1: First text
        text2: Second text
        model: Optional pre-loaded sentence transformer model
        
    Returns:
        Cosine similarity score (0-1)
    """
    try:
        from sentence_transformers import SentenceTransformer
        
        if model is None:
            model = SentenceTransformer('all-MiniLM-L6-v2')
        
        embeddings = model.encode([text1, text2])
        similarity = cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]
        return float(similarity)
    
    except ImportError:
        # Fallback to simple token overlap if sentence-transformers not available
        return token_overlap_similarity(text1, text2)


def token_overlap_similarity(text1: str, text2: str) -> float:
    """
    Calculate simple token overlap similarity.
    
    Args:
        text1: First text
        text2: Second text
        
    Returns:
        Jaccard similarity coefficient
    """
    tokens1 = set(re.findall(r'\w+', text1.lower()))
    tokens2 = set(re.findall(r'\w+', text2.lower()))
    
    if not tokens1 or not tokens2:
        return 0.0
    
    intersection = len(tokens1.intersection(tokens2))
    union = len(tokens1.union(tokens2))
    
    return intersection / union if union > 0 else 0.0


def rouge_score(reference: str, candidate: str) -> Dict[str, float]:
    """
    Calculate ROUGE scores for summarization evaluation.
    
    Args:
        reference: Reference text
        candidate: Candidate text to evaluate
        
    Returns:
        Dictionary with ROUGE-1, ROUGE-2, ROUGE-L scores
    """
    def get_ngrams(text: str, n: int) -> Counter:
        """Extract n-grams from text."""
        tokens = re.findall(r'\w+', text.lower())
        return Counter(zip(*[tokens[i:] for i in range(n)]))
    
    def lcs_length(x: List[str], y: List[str]) -> int:
        """Calculate longest common subsequence length."""
        m, n = len(x), len(y)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if x[i-1] == y[j-1]:
                    dp[i][j] = dp[i-1][j-1] + 1
                else:
                    dp[i][j] = max(dp[i-1][j], dp[i][j-1])
        
        return dp[m][n]
    
    # Tokenize
    ref_tokens = re.findall(r'\w+', reference.lower())
    cand_tokens = re.findall(r'\w+', candidate.lower())
    
    # ROUGE-1 (unigram overlap)
    ref_unigrams = Counter(ref_tokens)
    cand_unigrams = Counter(cand_tokens)
    overlap_unigrams = sum((ref_unigrams & cand_unigrams).values())
    rouge1_precision = overlap_unigrams / max(sum(cand_unigrams.values()), 1)
    rouge1_recall = overlap_unigrams / max(sum(ref_unigrams.values()), 1)
    rouge1_f1 = 2 * rouge1_precision * rouge1_recall / max(rouge1_precision + rouge1_recall, 0.0001)
    
    # ROUGE-2 (bigram overlap)
    ref_bigrams = get_ngrams(reference, 2)
    cand_bigrams = get_ngrams(candidate, 2)
    overlap_bigrams = sum((ref_bigrams & cand_bigrams).values())
    rouge2_precision = overlap_bigrams / max(sum(cand_bigrams.values()), 1)
    rouge2_recall = overlap_bigrams / max(sum(ref_bigrams.values()), 1)
    rouge2_f1 = 2 * rouge2_precision * rouge2_recall / max(rouge2_precision + rouge2_recall, 0.0001)
    
    # ROUGE-L (longest common subsequence)
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
    Calculate BLEU score for text generation evaluation.
    
    Args:
        reference: Reference text
        candidate: Candidate text to evaluate
        max_n: Maximum n-gram order (default: 4)
        
    Returns:
        BLEU score
    """
    def get_ngrams(tokens: List[str], n: int) -> Counter:
        return Counter(zip(*[tokens[i:] for i in range(n)]))
    
    ref_tokens = re.findall(r'\w+', reference.lower())
    cand_tokens = re.findall(r'\w+', candidate.lower())
    
    if not cand_tokens:
        return 0.0
    
    # Calculate modified precision for each n-gram order
    precisions = []
    for n in range(1, max_n + 1):
        ref_ngrams = get_ngrams(ref_tokens, n)
        cand_ngrams = get_ngrams(cand_tokens, n)
        
        overlap = sum((ref_ngrams & cand_ngrams).values())
        total = sum(cand_ngrams.values())
        
        precision = overlap / max(total, 1)
        precisions.append(precision)
    
    # Geometric mean of precisions
    if min(precisions) == 0:
        return 0.0
    
    geo_mean = np.exp(np.mean([np.log(p) for p in precisions if p > 0]))
    
    # Brevity penalty
    ref_len = len(ref_tokens)
    cand_len = len(cand_tokens)
    bp = 1.0 if cand_len > ref_len else np.exp(1 - ref_len / max(cand_len, 1))
    
    return bp * geo_mean


def embedding_distance(embedding1: np.ndarray, embedding2: np.ndarray, metric: str = 'cosine') -> float:
    """
    Calculate distance between two embeddings.
    
    Args:
        embedding1: First embedding vector
        embedding2: Second embedding vector
        metric: Distance metric ('cosine', 'euclidean', 'manhattan')
        
    Returns:
        Distance value
    """
    if metric == 'cosine':
        return 1 - cosine_similarity([embedding1], [embedding2])[0][0]
    elif metric == 'euclidean':
        return float(np.linalg.norm(embedding1 - embedding2))
    elif metric == 'manhattan':
        return float(np.sum(np.abs(embedding1 - embedding2)))
    else:
        raise ValueError(f"Unknown metric: {metric}")
