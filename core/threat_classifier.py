class ThreatClassifier:
    """AI threat classification"""
    
    def classify(self, text):
        """Classify threat type from text"""
        text_lower = text.lower()
        labels = []
        confidence = []
        
        # Check for phishing
        if any(word in text_lower for word in ['click here', 'claim prize', 'urgent', 'verify account']):
            labels.append('phishing')
            confidence.append(0.92)
        
        # Check for malware
        if any(word in text_lower for word in ['download', 'attachment', 'install', 'exe']):
            labels.append('malware')
            confidence.append(0.88)
        
        # Check for spam
        if any(word in text_lower for word in ['buy now', 'limited offer', 'act fast']):
            labels.append('spam')
            confidence.append(0.75)
        
        return {
            'text': text,
            'labels': labels if labels else ['unknown'],
            'confidence': confidence if confidence else [0.3],
            'is_threat': len(labels) > 0
        }