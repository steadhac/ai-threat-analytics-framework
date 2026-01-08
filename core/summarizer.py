"""
Threat Summarizer Module


Provides extractive text summarization for threat reports and security alerts.
Reduces verbose reports to essential information by selecting complete sentences
until reaching a specified length limit.

Algorithm:
    Greedy extractive summarization - selects sentences in order until limit
    
Performance:
    - O(n) time complexity where n = text length
    - O(n) space for output buffer
    - < 10ms typical latency
    
Use Cases:
    - Summarize lengthy threat reports
    - Extract key points from security alerts
    - Reduce incident documentation size
    - Compress verbose security logs
"""


class ThreatSummarizer:
    """
    Extractive summarizer for threat reports and security content.
    
    Reduces verbose text by selecting complete sentences greedily until
    reaching a specified length limit. Preserves original sentence text
    (no paraphrasing or abstraction).
    
    Example:
        >>> summarizer = ThreatSummarizer()
        >>> report = "Phishing detected. Users affected. Team responding."
        >>> result = summarizer.summarize(report, max_length=50)
        >>> print(result['summary'])
        'Phishing detected. Users affected.'
        >>> print(result['compression_ratio'])
        0.67
    """
    
    def summarize(self, text: str, max_length: int = 100) -> dict:
        """
        Summarize text using greedy sentence selection.
        
        Extracts complete sentences in order until reaching max_length.
        Returns summary with metadata about compression.
        
        Args:
            text (str): Text to summarize (threat report, alert, etc.)
            max_length (int): Maximum length of summary in characters (default: 100)
        
        Returns:
            dict: Summarization result
                - summary: Compressed text (selected sentences)
                - summary_length: Character count of summary
                - original_length: Character count of original text
                - compression_ratio: summary_length / original_length
        
        Example:
            >>> text = "Malware detected. Multiple systems affected. Team responding."
            >>> result = summarizer.summarize(text, max_length=40)
            >>> print(result)
            {
                'summary': 'Malware detected.',
                'summary_length': 18,
                'original_length': 59,
                'compression_ratio': 0.31
            }
        
        Algorithm:
            1. Split text by '. ' to extract sentences
            2. Initialize empty summary
            3. For each sentence:
               - If adding sentence doesn't exceed max_length:
                 - Add sentence to summary
               - Else:
                 - Stop and return
            4. Return summary with metrics
        
        Edge Cases:
            - Empty text: Returns empty summary
            - Single sentence: Returns that sentence (if fits)
            - No periods: Treats entire text as one sentence
            - Very short max_length: May return partial content
        
        Performance: O(n) where n = text length
        """
        if not text or not text.strip():
            return {
                'summary': '',
                'summary_length': 0,
                'original_length': len(text),
                'compression_ratio': 0.0
            }
        
        # Normalize whitespace
        text = ' '.join(text.split())
        original_length = len(text)
        
        # Split into sentences (delimited by '. ')
        sentences = text.split('. ')
        
        # Greedily add sentences until reaching max_length
        summary = ''
        for i, sentence in enumerate(sentences):
            # Add period back to sentence (except last if no period originally)
            sentence_with_period = sentence if i == len(sentences) - 1 else sentence + '.'
            
            # Check if adding this sentence exceeds limit
            if len(summary) + len(sentence_with_period) + (1 if summary else 0) <= max_length:
                if summary:
                    summary += ' '
                summary += sentence_with_period
            else:
                break
        
        summary_length = len(summary)
        compression_ratio = summary_length / original_length if original_length > 0 else 0.0
        
        return {
            'summary': summary,
            'summary_length': summary_length,
            'original_length': original_length,
            'compression_ratio': round(compression_ratio, 2)
        }


# ============================================================================
# Integration Examples
# ============================================================================

if __name__ == '__main__':
    """
    Demonstration of threat summarization usage.
    """
    
    summarizer = ThreatSummarizer()
    
    # Example 1: Basic threat report
    print("=== Threat Report Summarization ===")
    report = "A critical phishing attack was detected. Multiple users affected. Team responded quickly. Patches deployed."
    result = summarizer.summarize(report, max_length=80)
    print(f"Original: {report}")
    print(f"Summary: {result['summary']}")
    print(f"Compression: {result['compression_ratio']}\n")
    
    # Example 2: Incident report
    print("=== Incident Report ===")
    incident = "Malware detected on server. Database accessed. Data encrypted. Legal team notified. Investigation ongoing."
    result = summarizer.summarize(incident, max_length=60)
    print(f"Original: {incident}")
    print(f"Summary: {result['summary']}")
    print(f"Length: {result['summary_length']} chars\n")
    
    # Example 3: Security alert
    print("=== Security Alert ===")
    alert = "Suspicious activity detected. Rate limit exceeded. IP blocked. Monitoring increased."
    result = summarizer.summarize(alert, max_length=50)
    print(f"Original: {alert}")
    print(f"Summary: {result['summary']}")
    print(f"Compression: {result['compression_ratio']}\n")