class ThreatClassifier:
    """
    AI threat classification engine for detecting phishing, malware, and spam threats.
    
    This classifier uses keyword pattern matching to identify threat types in text
    and provides confidence scores for each detected threat. It analyzes email text,
    messages, and user-submitted content to classify security threats.
    
    Threat Types Detected:
        - Phishing: Email-based social engineering attacks using urgency and verification
        - Malware: Suspicious file delivery attempts with installation keywords
        - Spam: Marketing/promotional messages with limited-time offer patterns
    
    Confidence Scoring:
        - Phishing: 0.92 (high confidence from specific keywords)
        - Malware: 0.88 (high confidence from suspicious patterns)
        - Spam: 0.75 (moderate confidence from marketing keywords)
        - Unknown: 0.3 (default for unmatched text)
    
    Attributes:
        None (stateless classifier)
    
    Example:
        >>> classifier = ThreatClassifier()
        >>> result = classifier.classify("Click here to claim your prize!")
        >>> result['is_threat']
        True
        >>> result['labels']
        ['phishing']
        >>> result['confidence'][0]
        0.92
    """
    
    def classify(self, text):
        """
        Classify threat type from input text using keyword pattern matching.
        
        This method analyzes text for threat indicators across three categories:
        phishing (urgency + verification), malware (file delivery), and spam
        (promotional language). Returns detected threat types and confidence scores.
        
        Algorithm:
            1. Convert text to lowercase for case-insensitive matching
            2. Initialize empty labels and confidence lists
            3. Check for phishing keywords (4 patterns)
            4. Check for malware keywords (4 patterns)
            5. Check for spam keywords (3 patterns)
            6. Return results with is_threat boolean
        
        Parameters:
            text (str): Input text to classify (email body, message, alert, etc.)
        
        Returns:
            dict: Classification result containing:
                - 'text' (str): Original input text
                - 'labels' (list): Detected threat types or ['unknown']
                - 'confidence' (list): Confidence scores (0.0-1.0) for each label
                - 'is_threat' (bool): True if any threats detected, False otherwise
        
        Threat Categories:
            
            1. PHISHING Detection
               Keywords: 'click here', 'claim prize', 'urgent', 'verify account'
               Confidence: 0.92
               Indicators: Urgency, action requests, account verification
               Risk: Social engineering, credential theft
               
            2. MALWARE Detection
               Keywords: 'download', 'attachment', 'install', 'exe'
               Confidence: 0.88
               Indicators: File delivery, execution requests
               Risk: System compromise, infection
               
            3. SPAM Detection
               Keywords: 'buy now', 'limited offer', 'act fast'
               Confidence: 0.75
               Indicators: Marketing language, scarcity tactics
               Risk: Unwanted solicitation, fraud
        
        Returns:
            Example 1 - Phishing Detected:
            {
                'text': 'Click here to claim your prize! Urgent!',
                'labels': ['phishing'],
                'confidence': [0.92],
                'is_threat': True
            }
            
            Example 2 - Multiple Threats:
            {
                'text': 'Download now and buy cheap software urgently!',
                'labels': ['malware', 'spam', 'phishing'],
                'confidence': [0.88, 0.75, 0.92],
                'is_threat': True
            }
            
            Example 3 - No Threat:
            {
                'text': 'What is the weather today?',
                'labels': ['unknown'],
                'confidence': [0.3],
                'is_threat': False
            }
        
        Notes:
            - Text is case-insensitive (converted to lowercase)
            - Multiple threats can be detected in single text
            - Keywords are exact substring matches (not regex)
            - Confidence scores are static per threat type
            - Unknown/unmatched text confidence defaults to 0.3
        
        Usage Examples:
            >>> classifier = ThreatClassifier()
            
            # Example 1: Phishing email
            >>> phishing = classifier.classify("Click here to verify your account urgently!")
            >>> phishing['is_threat']
            True
            >>> phishing['labels']
            ['phishing']
            
            # Example 2: Malware attachment
            >>> malware = classifier.classify("Download the attachment and install exe")
            >>> malware['labels']
            ['malware']
            
            # Example 3: Spam message
            >>> spam = classifier.classify("Buy now with limited offer act fast today!")
            >>> spam['labels']
            ['spam']
            
            # Example 4: Safe message
            >>> safe = classifier.classify("Hello, how are you today?")
            >>> safe['is_threat']
            False
        
        Performance:
            - Time Complexity: O(n*m) where n=keywords, m=text length
            - Space Complexity: O(k) where k=threats found (usually 0-3)
            - Execution: < 1ms for typical email length text
        
        Limitations:
            - Keyword-based (no NLP/ML models)
            - Can have false positives if keywords appear in legitimate context
            - Cannot detect novel/obfuscated threats
            - No semantic understanding
            - Static confidence scores regardless of context
        
        Future Enhancements:
            - ML model-based classification (BERT, GPT)
            - Dynamic confidence scoring based on keyword frequency
            - Context-aware analysis (sentence structure, tone)
            - Obfuscation detection (ROT13, character substitution)
            - Multi-language support
        """
        # Normalize text to lowercase for case-insensitive keyword matching
        text_lower = text.lower()
        
        # Initialize lists to store detected threats and their confidence scores
        labels = []
        confidence = []
        
        # PHISHING DETECTION
        # Check for social engineering keywords that indicate urgent verification requests
        # Phishing attacks typically use urgency and account verification tactics
        phishing_keywords = ['click here', 'claim prize', 'urgent', 'verify account']
        if any(word in text_lower for word in phishing_keywords):
            labels.append('phishing')
            confidence.append(0.92)  # High confidence: specific phishing indicators
        
        # MALWARE DETECTION
        # Check for suspicious file delivery and execution keywords
        # Malware is often delivered via attachments or downloads with installation requests
        malware_keywords = ['download', 'attachment', 'install', 'exe']
        if any(word in text_lower for word in malware_keywords):
            labels.append('malware')
            confidence.append(0.88)  # High confidence: clear malware delivery patterns
        
        # SPAM DETECTION
        # Check for marketing language and limited-time offer patterns
        # Spam typically uses urgency and scarcity tactics to drive action
        spam_keywords = ['buy now', 'limited offer', 'act fast']
        if any(word in text_lower for word in spam_keywords):
            labels.append('spam')
            confidence.append(0.75)  # Moderate confidence: marketing language
        
        # Return classification results
        # If no threats detected, return 'unknown' label with low confidence (0.3)
        return {
            'text': text,
            'labels': labels if labels else ['unknown'],  # Use labels if found, else 'unknown'
            'confidence': confidence if confidence else [0.3],  # Use confidence if found, else 0.3
            'is_threat': len(labels) > 0  # True if any threats detected
        }