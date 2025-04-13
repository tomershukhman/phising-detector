import re
from urllib.parse import urlparse
import tldextract
import pandas as pd
import numpy as np
import joblib

def extract_url_features(url):
    """Extract features from a URL without making HTTP requests"""
    features = {}
    url = str(url).lower()

    # --- Basic Length Features ---
    features['URLLength'] = len(url)

    # --- Parsing Components ---
    try:
        parsed_url = urlparse(url)
        extracted_domain = tldextract.extract(url)
        domain_name = extracted_domain.domain
        subdomain = extracted_domain.subdomain
        tld = extracted_domain.suffix
        full_domain = extracted_domain.registered_domain

        features['DomainLength'] = len(full_domain) if full_domain else 0
        features['PathLength'] = len(parsed_url.path)
        features['QueryLength'] = len(parsed_url.query)
        features['NumSubdomains'] = len(subdomain.split('.')) if subdomain else 0
        features['TLDLength'] = len(tld) if tld else 0
        
        # Domain structure features
        features['HasSubdomain'] = 1 if subdomain else 0
        features['SubdomainLength'] = len(subdomain) if subdomain else 0
        features['DomainNameLength'] = len(domain_name)
        features['NumDots'] = url.count('.')
        features['NumDashes'] = url.count('-')
        
        # URL component entropy (measure of randomness/complexity)
        features['DomainEntropy'] = calculate_entropy(domain_name)
        features['SubdomainEntropy'] = calculate_entropy(subdomain) if subdomain else 0
        features['PathEntropy'] = calculate_entropy(parsed_url.path)
        
        # Path analysis
        path_parts = parsed_url.path.split('/')
        features['PathDepth'] = len([p for p in path_parts if p])
        features['MaxPathPartLength'] = max([len(p) for p in path_parts if p], default=0)
        
        # Query analysis
        query_params = parsed_url.query.split('&')
        features['NumQueryParams'] = len([q for q in query_params if q])
        features['MaxQueryParamLength'] = max([len(q) for q in query_params if q], default=0)

    except Exception:
        features.update({
            'DomainLength': 0, 'PathLength': 0, 'QueryLength': 0,
            'NumSubdomains': 0, 'TLDLength': 0, 'HasSubdomain': 0,
            'SubdomainLength': 0, 'DomainNameLength': 0, 'NumDots': 0,
            'NumDashes': 0, 'DomainEntropy': 0, 'SubdomainEntropy': 0,
            'PathEntropy': 0, 'PathDepth': 0, 'MaxPathPartLength': 0,
            'NumQueryParams': 0, 'MaxQueryParamLength': 0
        })

    # --- Character Distribution Features ---
    features['NumDigits'] = sum(c.isdigit() for c in url)
    features['NumLetters'] = sum(c.isalpha() for c in url)
    features['NumSpecialChars'] = len(re.findall(r'[^a-z0-9\.]', url))
    
    # Character type ratios
    total_len = len(url) if len(url) > 0 else 1
    features['DigitRatio'] = features['NumDigits'] / total_len
    features['LetterRatio'] = features['NumLetters'] / total_len
    features['SpecialCharRatio'] = features['NumSpecialChars'] / total_len
    
    # Sequential character patterns
    features['ConsecutiveDigits'] = len(re.findall(r'\d{2,}', url))
    features['ConsecutiveSpecialChars'] = len(re.findall(r'[^a-z0-9\.]{2,}', url))
    
    # URL structure indicators
    features['IsHTTPS'] = 1 if parsed_url and parsed_url.scheme == 'https' else 0
    features['HasIPAddress'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    features['HasAtSymbol'] = 1 if '@' in url else 0
    features['HasDoubleSlash'] = 1 if parsed_url and '//' in parsed_url.path else 0
    features['HasHexChars'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
    
    # Calculate frequency distribution of characters
    char_freq = {}
    for char in url:
        char_freq[char] = char_freq.get(char, 0) + 1
    features['UniqueCharsRatio'] = len(char_freq) / total_len
    features['MaxCharFrequency'] = max(char_freq.values()) / total_len if char_freq else 0

    return pd.Series(features)

def calculate_entropy(text):
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0
    text = str(text)
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * pd.np.log2(p) for p in prob)


def predict_phishing(url):
    """
    Predict if a URL is phishing (0) or legitimate (1) using a hybrid approach
    that combines ML predictions with rule-based analysis
    """
    try:
        # Extract features and get ML model prediction
        ml_prediction = get_ml_prediction(url)
        
        # Perform rule-based analysis on the URL
        rule_based_analysis = analyze_url_security(url)
        
        # Combine the ML prediction with rule-based analysis for final decision
        final_prediction = make_final_decision(url, ml_prediction, rule_based_analysis)
        
        return final_prediction
        
    except Exception as e:
        print(f"Error in prediction: {str(e)}")
        return {
            'prediction': 0,  # Mark as phishing
            'confidence': 0.51,
            'is_phishing': True,
            'errors': str(e)
        }

def get_ml_prediction(url):
    """Get prediction from the ML model"""
    try:
        # Load the model and preprocessing objects
        model = joblib.load('phishing_xgb_model.joblib')
        scaler = joblib.load('phishing_scaler.joblib')
        imputer = joblib.load('phishing_imputer.joblib')
        feature_names = joblib.load('phishing_features.joblib')
        
        # Extract features
        url_features = extract_url_features(url)
        
        # Create DataFrame with proper feature names
        features_df = pd.DataFrame([url_features])
        
        # Ensure all required features are present and in correct order
        missing_features = set(feature_names) - set(features_df.columns)
        for feature in missing_features:
            features_df[feature] = 0
        
        # Reorder columns to match training data
        features_df = features_df[feature_names]
        
        # Apply preprocessing while maintaining feature names
        features_imputed = pd.DataFrame(
            imputer.transform(features_df),
            columns=feature_names
        )
        
        features_scaled = pd.DataFrame(
            scaler.transform(features_imputed),
            columns=feature_names
        )
        
        # Get prediction probabilities
        probs = model.predict_proba(features_scaled)[0]
        phishing_prob = probs[0]  # Class 0: phishing
        legitimate_prob = probs[1]  # Class 1: legitimate
        
        return {
            'phishing_prob': phishing_prob,
            'legitimate_prob': legitimate_prob,
            'features': url_features
        }
        
    except Exception as e:
        print(f"ML prediction error: {str(e)}")
        return {
            'phishing_prob': 0.75,
            'legitimate_prob': 0.25,
            'error': str(e)
        }

def analyze_url_security(url):
    """
    Analyze URL for phishing indicators using rule-based methods
    Returns dictionary of security indicators and an overall assessment
    """
    url_lower = url.lower()
    parsed = urlparse(url_lower)
    extracted = tldextract.extract(url_lower)
    
    domain = extracted.domain
    subdomain = extracted.subdomain
    suffix = extracted.suffix
    registered_domain = extracted.registered_domain
    
    security_indicators = {}
    phishing_score = 0
    legitimate_score = 0
    security_flags = []
    
    # --- STRUCTURAL ANALYSIS ---
    
    # Check use of HTTPS (legitimate indicator)
    security_indicators['uses_https'] = parsed.scheme == 'https'
    if security_indicators['uses_https']:
        legitimate_score += 1
    
    # Check for IP address instead of domain (phishing indicator)
    security_indicators['is_ip_address'] = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
    if security_indicators['is_ip_address']:
        phishing_score += 3
        security_flags.append('IP address used as domain')
    
    # Check for URL shorteners (suspicious indicator)
    shortener_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'buff.ly', 'j.mp', 'ow.ly']
    security_indicators['is_shortener'] = any(sd in url_lower for sd in shortener_domains)
    if security_indicators['is_shortener']:
        phishing_score += 1
        security_flags.append('URL shortener detected')
    
    # Check for suspicious TLDs often used in phishing
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'info', 'top', 'pw']
    security_indicators['has_suspicious_tld'] = suffix in suspicious_tlds
    if security_indicators['has_suspicious_tld']:
        phishing_score += 2
        security_flags.append(f'Suspicious TLD: .{suffix}')
    
    # Check common legitimate TLDs
    common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp']
    security_indicators['has_common_tld'] = suffix in common_tlds
    if security_indicators['has_common_tld']:
        legitimate_score += 1
    
    # --- DOMAIN ANALYSIS ---
    
    # Check domain length (excessively long domains are suspicious)
    security_indicators['domain_length'] = len(domain)
    if security_indicators['domain_length'] > 30:
        phishing_score += 1
        security_flags.append('Excessively long domain name')
    
    # Check for excessive subdomain levels
    if subdomain:
        subdomain_parts = subdomain.split('.')
        security_indicators['subdomain_count'] = len(subdomain_parts)
        if security_indicators['subdomain_count'] > 3:
            phishing_score += 1
            security_flags.append('Excessive subdomains')
    
    # Check for hyphens (more than 2 is suspicious)
    security_indicators['hyphen_count'] = domain.count('-')
    if security_indicators['hyphen_count'] > 2:
        phishing_score += 1
        security_flags.append('Multiple hyphens in domain')
    
    # Check for digits in domain (high ratio is suspicious)
    digit_count = sum(c.isdigit() for c in domain)
    digit_ratio = digit_count / len(domain) if len(domain) > 0 else 0
    security_indicators['digit_ratio'] = digit_ratio
    if digit_ratio > 0.5:
        phishing_score += 1
        security_flags.append('High ratio of digits in domain')
    
    # --- CONTENT ANALYSIS ---
    
    # Check for @symbol in URL (often used in phishing)
    security_indicators['has_at_symbol'] = '@' in url_lower
    if security_indicators['has_at_symbol']:
        phishing_score += 3
        security_flags.append('@ symbol in URL')
    
    # Check for double slash after protocol (redirect indication)
    security_indicators['path_has_double_slash'] = '//' in parsed.path
    if security_indicators['path_has_double_slash']:
        phishing_score += 2
        security_flags.append('Double slash in URL path')
    
    # Check for hexadecimal or encoded characters
    security_indicators['has_hex_chars'] = bool(re.search(r'%[0-9a-f]{2}', url_lower))
    if security_indicators['has_hex_chars']:
        phishing_score += 1
        security_flags.append('Hex-encoded characters')
    
    # --- BRAND ANALYSIS ---
    
    # Check for legitimate brand names as the registered domain
    top_domains = [
        'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'amazon.com', 
        'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com', 
        'github.com', 'stackoverflow.com', 'paypal.com', 'bankofamerica.com',
        'chase.com', 'microsoftonline.com', 'wikipedia.org', 'yahoo.com'
    ]
    
    # Check if domain is an exact match to known legitimate domain
    security_indicators['is_known_domain'] = registered_domain in top_domains
    if security_indicators['is_known_domain']:
        legitimate_score += 3
    
    # Check for brand names in URL but not as the main domain (phishing sign)
    brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'twitter', 'instagram', 
              'linkedin', 'netflix', 'github', 'bankofamerica', 'chase', 'wellsfargo', 'amex']
    
    for brand in brands:
        if brand in url_lower and brand not in registered_domain:
            phishing_score += 2
            security_flags.append(f'Brand name ({brand}) in URL but not main domain')
            break
    
    # Check for typosquatted domain (common phishing tactic)
    for legitimate_domain in top_domains:
        legitimate_domain_parts = tldextract.extract(legitimate_domain)
        legitimate_name = legitimate_domain_parts.domain
        
        # Simple edit distance check for typosquatting
        if legitimate_name != domain and len(legitimate_name) > 4 and domain != '':
            similarity_threshold = 0.8
            similarity = string_similarity(legitimate_name, domain)
            
            if similarity > similarity_threshold and similarity < 1.0:
                phishing_score += 3
                security_flags.append(f'Possible typosquatting of {legitimate_domain}')
                break

    # --- SECURITY KEYWORDS ANALYSIS ---
    
    # Check for security-related words in domain (often in phishing)
    security_terms = ['secure', 'login', 'account', 'verify', 'signin', 'security', 
                    'update', 'confirm', 'password', 'authenticate', 'wallet']
    
    security_term_count = sum(1 for term in security_terms if term in domain)
    security_indicators['security_term_count'] = security_term_count
    
    if security_term_count >= 2:
        phishing_score += 2
        security_flags.append('Multiple security terms in domain')
    elif security_term_count == 1:
        phishing_score += 1

    # --- OVERALL ASSESSMENT ---
    
    # Calculate raw phishing and legitimate scores
    raw_phishing_likelihood = phishing_score / 10 if phishing_score <= 10 else 1.0
    raw_legitimate_likelihood = legitimate_score / 5 if legitimate_score <= 5 else 1.0
    
    # Normalize and balance the scores
    total_score = raw_phishing_likelihood + raw_legitimate_likelihood
    if total_score > 0:
        normalized_phishing_score = raw_phishing_likelihood / total_score
        normalized_legitimate_score = raw_legitimate_likelihood / total_score
    else:
        normalized_phishing_score = 0.5
        normalized_legitimate_score = 0.5
    
    return {
        'indicators': security_indicators,
        'phishing_score': normalized_phishing_score,
        'legitimate_score': normalized_legitimate_score,
        'security_flags': security_flags
    }

def make_final_decision(url, ml_prediction, rule_analysis):
    """
    Make the final phishing/legitimate decision by combining ML and rule-based analysis
    """
    # Extract the probabilities from ML model
    ml_phishing_prob = ml_prediction.get('phishing_prob', 0.5)
    ml_legitimate_prob = ml_prediction.get('legitimate_prob', 0.5)
    
    # Extract rule-based analysis
    rule_phishing_score = rule_analysis.get('phishing_score', 0.5)
    rule_legitimate_score = rule_analysis.get('legitimate_score', 0.5)
    security_flags = rule_analysis.get('security_flags', [])
    
    # Combine ML and rule-based probabilities with appropriate weights
    # ML model is clearly biased, so we use a lower weight for it
    ml_weight = 0.4
    rule_weight = 0.6
    
    combined_phishing_prob = (ml_phishing_prob * ml_weight) + (rule_phishing_score * rule_weight)
    combined_legitimate_prob = (ml_legitimate_prob * ml_weight) + (rule_legitimate_score * rule_weight)
    
    # Normalize combined probabilities
    total_prob = combined_phishing_prob + combined_legitimate_prob
    if total_prob > 0:
        final_phishing_prob = combined_phishing_prob / total_prob
        final_legitimate_prob = combined_legitimate_prob / total_prob
    else:
        final_phishing_prob = 0.5
        final_legitimate_prob = 0.5
    
    # Make the final classification decision
    if final_legitimate_prob >= final_phishing_prob:
        prediction = 1  # legitimate
        confidence = final_legitimate_prob
        is_phishing = False
    else:
        prediction = 0  # phishing
        confidence = final_phishing_prob
        is_phishing = True
    
    # Debug info
    print(f"URL: {url}")
    print(f"ML: Phishing={ml_phishing_prob:.4f}, Legitimate={ml_legitimate_prob:.4f}")
    print(f"Rule: Phishing={rule_phishing_score:.4f}, Legitimate={rule_legitimate_score:.4f}")
    if security_flags:
        print(f"Security flags: {', '.join(security_flags)}")
    print(f"Final: Phishing={final_phishing_prob:.4f}, Legitimate={final_legitimate_prob:.4f}")
    print(f"Prediction: {prediction} (1=legitimate, 0=phishing)")
    
    return {
        'prediction': int(prediction),
        'confidence': float(confidence),
        'is_phishing': bool(is_phishing),
        'probabilities': {
            'phishing': float(final_phishing_prob),
            'legitimate': float(final_legitimate_prob)
        },
        'ml_probabilities': {
            'phishing': float(ml_phishing_prob),
            'legitimate': float(ml_legitimate_prob)
        },
        'rule_scores': {
            'phishing': float(rule_phishing_score),
            'legitimate': float(rule_legitimate_score)
        },
        'security_flags': security_flags
    }

def string_similarity(s1, s2):
    """Calculate similarity between two strings (0 to 1)"""
    if not s1 or not s2:
        return 0.0
        
    # Convert to lowercase for case-insensitive comparison
    s1, s2 = s1.lower(), s2.lower()
    
    # Check for exact match
    if s1 == s2:
        return 1.0
        
    # Calculate Jaro-Winkler similarity
    # This is a simplified version that gives higher scores to strings with matching prefixes
    len_s1 = len(s1)
    len_s2 = len(s2)
    
    # Calculate common prefix length
    prefix_len = 0
    for i in range(min(len_s1, len_s2, 4)):  # Max 4 chars for prefix
        if s1[i] == s2[i]:
            prefix_len += 1
        else:
            break
    
    # Simple edit distance calculation
    max_len = max(len_s1, len_s2)
    if max_len == 0:
        return 0.0
    
    # Simple character matching
    matches = 0
    for c in s1:
        if c in s2:
            matches += 1
    
    # Calculate basic similarity
    base_sim = matches / max_len
    
    # Add prefix bonus
    prefix_bonus = prefix_len * 0.1  # Each matching prefix char adds 0.1
    
    return min(base_sim + prefix_bonus, 1.0)