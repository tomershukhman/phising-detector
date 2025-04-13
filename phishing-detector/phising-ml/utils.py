import re
from urllib.parse import urlparse
import tldextract
import pandas as pd
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
    """Predict if a URL is phishing (0) or legitimate (1) using the trained model"""
    try:
        # Load the model and preprocessing objects
        model = joblib.load('phishing_rf_model_engineered.joblib')
        scaler = joblib.load('phishing_scaler_engineered.joblib')
        imputer = joblib.load('phishing_imputer_engineered.joblib')
        feature_names = joblib.load('phishing_features_engineered.joblib')
        
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
        phishing_prob = probs[0]  # Probability of being phishing (class 0)
        
        # Use a threshold of 0.7 for higher precision on phishing detection
        prediction = 0 if phishing_prob > 0.7 else 1
        confidence = max(phishing_prob, 1 - phishing_prob)
        
        return {
            'prediction': int(prediction),
            'confidence': float(confidence),
            'is_phishing': bool(prediction == 0)  # 0 is phishing in our dataset
        }
        
    except Exception as e:
        print(f"Error in prediction: {str(e)}")
        # For edge cases that cause errors, return as suspicious with low confidence
        return {
            'prediction': 0,
            'confidence': 0.51,
            'is_phishing': True
        }