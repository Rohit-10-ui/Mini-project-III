"""
Feature extraction for Email/SMS phishing detection
Extracts 15 features from text messages to detect phishing attempts
"""

import re
from urllib.parse import urlparse

def extract_text_features(text, sender=None):
    """
    Extract features from email/SMS text for phishing detection
    
    Args:
        text: The message content (email body or SMS text)
        sender: Optional sender email/phone (for domain validation)
    
    Returns:
        List of 15 feature values (all normalized to -1, 0, or 1)
    """
    
    # 1. num_urls: Number of URLs in the text
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    num_urls = len(urls)
    num_urls_score = 1 if num_urls > 2 else (0 if num_urls > 0 else -1)
    
    # 2. url_with_ip: Check if any URL contains IP address
    url_with_ip = -1
    for url in urls:
        # Check for IP pattern in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            url_with_ip = 1
            break
    
    # 3. has_shortened_url: Check for URL shorteners
    shortened_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
    has_shortened_url = -1
    for url in urls:
        if any(domain in url.lower() for domain in shortened_domains):
            has_shortened_url = 1
            break
    
    # 4. urgency_score: Urgent/pressure language
    urgency_keywords = [
        'urgent', 'immediately', 'act now', 'limited time', 'expires', 'hurry',
        'only', 'today only', 'don\'t miss', 'last chance', 'act fast', 'quick',
        'asap', 'right now', 'within 24 hours', 'expire', 'deadline'
    ]
    urgency_score = 1 if any(keyword in text.lower() for keyword in urgency_keywords) else -1
    
    # 5. financial_score: Financial/money keywords
    financial_keywords = [
        'bank', 'account', 'credit card', 'payment', 'paypal', 'venmo', 'cash',
        'money', 'refund', 'tax', 'irs', 'verify account', 'suspend', 'confirm',
        'billing', 'invoice', 'transaction', 'wire transfer', 'bitcoin', 'crypto'
    ]
    financial_score = 1 if any(keyword in text.lower() for keyword in financial_keywords) else -1
    
    # 6. suspicious_score: Suspicious words (prizes, lottery, etc.)
    suspicious_keywords = [
        'winner', 'prize', 'lottery', 'congratulations', 'claim', 'reward',
        'free', 'bonus', 'gift', 'won', 'selected', 'lucky', 'exclusive offer',
        'special promotion', 'discount', 'deal', 'guaranteed'
    ]
    suspicious_score = 1 if any(keyword in text.lower() for keyword in suspicious_keywords) else -1
    
    # 7. threat_score: Threatening language
    threat_keywords = [
        'suspend', 'locked', 'blocked', 'unauthorized', 'security alert',
        'unusual activity', 'compromised', 'fraud', 'verify', 'confirm identity',
        'account will be closed', 'legal action', 'arrest', 'warrant', 'police'
    ]
    threat_score = 1 if any(keyword in text.lower() for keyword in threat_keywords) else -1
    
    # 8. excessive_punctuation: Too many !, ?, etc.
    punctuation_count = len(re.findall(r'[!?]{2,}', text))
    excessive_punctuation = 1 if punctuation_count > 2 else -1
    
    # 9. all_caps_ratio: Percentage of uppercase words
    words = text.split()
    if len(words) > 0:
        caps_words = sum(1 for word in words if word.isupper() and len(word) > 1)
        caps_ratio = caps_words / len(words)
        all_caps_ratio = 1 if caps_ratio > 0.3 else -1
    else:
        all_caps_ratio = -1
    
    # 10. spelling_quality: Common misspellings in phishing
    # Simplified: check for repeated letters or common typos
    misspelling_patterns = [
        r'(.)\1{2,}',  # Repeated letters (e.g., 'hellooo')
        r'\b\w*[0-9]+\w*\b'  # Words with numbers mixed in
    ]
    has_misspellings = any(re.search(pattern, text) for pattern in misspelling_patterns)
    spelling_quality = 0 if has_misspellings else 0  # Neutral feature for now
    
    # 11. sender_mismatch: Check if sender domain matches URL domains
    sender_mismatch = 0  # Default neutral
    if sender and urls:
        try:
            # Extract sender domain
            if '@' in sender:
                sender_domain = sender.split('@')[1].lower()
                
                # Check if any URL domain differs from sender
                for url in urls:
                    parsed = urlparse(url)
                    url_domain = parsed.netloc.lower()
                    
                    # If URL domain doesn't match sender domain
                    if url_domain and sender_domain not in url_domain and url_domain not in sender_domain:
                        sender_mismatch = 1
                        break
        except:
            sender_mismatch = 0
    
    # 12. has_phone_number: Contains phone number
    phone_pattern = r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
    has_phone_number = 1 if re.search(phone_pattern, text) else -1
    
    # 13. requests_personal_info: Asks for sensitive information
    personal_info_keywords = [
        'social security', 'ssn', 'password', 'pin', 'credit card number',
        'cvv', 'date of birth', 'mother\'s maiden name', 'full name',
        'address', 'driver\'s license', 'passport', 'account number'
    ]
    requests_personal_info = 1 if any(keyword in text.lower() for keyword in personal_info_keywords) else -1
    
    # 14. message_length: Unusual length (too short or too long)
    msg_len = len(text)
    if msg_len < 20 or msg_len > 1000:
        message_length = 0  # Suspicious
    else:
        message_length = -1  # Normal
    
    # 15. suspicious_domain: Check for suspicious domain patterns in URLs
    suspicious_domain = -1
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check for suspicious patterns
        if any([
            '-' in domain and len(domain.split('-')) > 3,  # Too many hyphens
            domain.count('.') > 3,  # Too many subdomains
            re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain),  # IP address
            any(susp in domain for susp in ['verify', 'secure', 'account', 'update', 'confirm'])
        ]):
            suspicious_domain = 1
            break
    
    return [
        num_urls_score,
        url_with_ip,
        has_shortened_url,
        urgency_score,
        financial_score,
        suspicious_score,
        threat_score,
        excessive_punctuation,
        all_caps_ratio,
        spelling_quality,
        sender_mismatch,
        has_phone_number,
        requests_personal_info,
        message_length,
        suspicious_domain
    ]


def get_feature_names():
    """Return the list of feature names in order"""
    return [
        "num_urls",
        "url_with_ip",
        "has_shortened_url",
        "urgency_score",
        "financial_score",
        "suspicious_score",
        "threat_score",
        "excessive_punctuation",
        "all_caps_ratio",
        "spelling_quality",
        "sender_mismatch",
        "has_phone_number",
        "requests_personal_info",
        "message_length",
        "suspicious_domain",
    ]


# Test function
if __name__ == "__main__":
    # Test with a phishing example
    phishing_text = """
    URGENT! Your bank account has been compromised! 
    Click here to verify immediately: http://192.168.1.1/secure-banking
    Act now or your account will be SUSPENDED within 24 hours!
    Call 1-800-555-0123 to confirm your identity.
    """
    
    legitimate_text = """
    Hi, this is a reminder that your package will arrive tomorrow.
    You can track it here: https://amazon.com/track/12345
    Thanks for your order!
    """
    
    print("Testing Feature Extraction")
    print("="*60)
    
    print("\nPhishing Example:")
    phishing_features = extract_text_features(phishing_text, "scammer@fake-bank.com")
    for name, value in zip(get_feature_names(), phishing_features):
        print(f"  {name}: {value}")
    
    print("\nLegitimate Example:")
    legit_features = extract_text_features(legitimate_text, "noreply@amazon.com")
    for name, value in zip(get_feature_names(), legit_features):
        print(f"  {name}: {value}")
