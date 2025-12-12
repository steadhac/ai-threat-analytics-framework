class ThreatSummarizer:
    """AI-powered threat report summarization"""
    
    def summarize(self, text, max_length=100):
        """Summarize threat report"""
        # Simple extractive summarization (first sentences)
        sentences = text.split('. ')
        
        summary = ''
        for sentence in sentences:
            if len(summary) + len(sentence) <= max_length:
                summary += sentence + '. '
            else:
                break
        
        return {
            'original_length': len(text),
            'summary': summary.strip(),
            'summary_length': len(summary),
            'compression_ratio': round(len(summary) / len(text), 2)
        }