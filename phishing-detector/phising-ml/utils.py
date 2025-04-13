import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import tldextract
import pandas as pd
import joblib

def extract_url_features(url):
    """Extract features from a URL without making HTTP requests"""
    features = {}
    url = str(url).lower() # Ensure string and lowercase

    # --- Basic Length Features ---
    features['URLLength'] = len(url)

    # --- Parsing Components ---
    try:
        parsed_url = urlparse(url)
        # Use tldextract for robust domain/subdomain/suffix separation
        extracted_domain = tldextract.extract(url)
        domain_name = extracted_domain.domain # e.g., 'google' in 'www.google.com'
        subdomain = extracted_domain.subdomain # e.g., 'www'
        tld = extracted_domain.suffix # e.g., 'co.uk' or 'com'

        full_domain = extracted_domain.registered_domain # e.g., 'google.com'

        features['DomainLength'] = len(full_domain) if full_domain else 0
        features['PathLength'] = len(parsed_url.path)
        features['QueryLength'] = len(parsed_url.query)
        features['NumSubdomains'] = len(subdomain.split('.')) if subdomain else 0
        features['TLDLength'] = len(tld) if tld else 0

    except Exception:
        # Handle potential parsing errors by setting defaults
        features['DomainLength'] = 0
        features['PathLength'] = 0
        features['QueryLength'] = 0
        features['NumSubdomains'] = 0
        features['TLDLength'] = 0
        domain_name = ''
        full_domain = ''
        parsed_url = None # Mark as failed

    # --- Character Count Features ---
    features['NumDigitsInURL'] = sum(c.isdigit() for c in url)
    features['NumLettersInURL'] = sum(c.isalpha() for c in url)
    features['NumOtherSpecialChars'] = len(re.findall(r'[^a-z0-9\.\/\?=\-&%]', url))
    features['NumHyphensInDomain'] = full_domain.count('-')
    features['NumUnderscoreInURL'] = url.count('_')
    features['NumAmpersandInURL'] = url.count('&')
    features['NumPercentInURL'] = url.count('%')
    features['NumAtSymbolInURL'] = url.count('@')

    # --- Binary/Heuristic Features ---
    features['IsHTTPS'] = 1 if parsed_url and parsed_url.scheme == 'https' else 0
    features['HasIPAddressDomain'] = 1 if parsed_url and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.netloc) else 0

    # Keyword checks (in domain or path)
    sensitive_keywords = ['login', 'secure', 'account', 'update', 'bank', 'admin', 'password', 'verify', 'signin', 'confirm', 'credential']
    features['HasSensitiveKeyword'] = 1 if any(keyword in url for keyword in sensitive_keywords) else 0
    
    # Check for common shortening service domains
    shortening_domains = ['bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'is.gd', 'ow.ly']
    features['IsShortenedURL'] = 1 if any(short_domain == full_domain for short_domain in shortening_domains) else 0

    # Check if domain name itself is purely numeric
    features['IsDomainNumeric'] = 1 if domain_name.isdigit() else 0

    # --- Ratio Features ---
    features['DigitRatio'] = features['NumDigitsInURL'] / features['URLLength'] if features['URLLength'] > 0 else 0
    features['LetterRatio'] = features['NumLettersInURL'] / features['URLLength'] if features['URLLength'] > 0 else 0
    features['SpecialCharRatio'] = features['NumOtherSpecialChars'] / features['URLLength'] if features['URLLength'] > 0 else 0

    return pd.Series(features)

def extract_html_features(url, timeout=10):
    """Extract features from webpage HTML content"""
    features = {}
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=timeout)
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Basic HTML features
        features['LineOfCode'] = len(html_content.splitlines())
        features['LargestLineLength'] = max(len(line) for line in html_content.splitlines())
        
        # Title features
        title = soup.title.string if soup.title else ''
        features['HasTitle'] = 1 if title else 0
        
        # Links and references
        features['NoOfSelfRef'] = len([a for a in soup.find_all('a') if a.get('href') and (a['href'].startswith('/') or url in a['href'])])
        features['NoOfExternalRef'] = len([a for a in soup.find_all('a') if a.get('href') and not (a['href'].startswith('/') or url in a['href'])])
        features['NoOfEmptyRef'] = len([a for a in soup.find_all('a') if not a.get('href')])
        
        # Resource features
        features['NoOfImage'] = len(soup.find_all('img'))
        features['NoOfCSS'] = len(soup.find_all('link', rel='stylesheet'))
        features['NoOfJS'] = len(soup.find_all('script'))
        
        # Form features
        forms = soup.find_all('form')
        features['HasSubmitButton'] = 1 if any(form.find('input', type='submit') for form in forms) else 0
        features['HasPasswordField'] = 1 if soup.find('input', type='password') else 0
        
        # Meta features
        features['HasDescription'] = 1 if soup.find('meta', attrs={'name': 'description'}) else 0
        features['HasFavicon'] = 1 if soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon') else 0
        features['HasCopyrightInfo'] = 1 if re.search(r'copyright|©', html_content.lower()) else 0
        
        # Social network presence
        social_patterns = r'facebook\.com|twitter\.com|instagram\.com|linkedin\.com'
        features['HasSocialNet'] = 1 if re.search(social_patterns, html_content.lower()) else 0
        
    except Exception:
        # Set default values for all HTML features if extraction fails
        features = {
            'LineOfCode': 0,
            'LargestLineLength': 0,
            'HasTitle': 0,
            'NoOfSelfRef': 0,
            'NoOfExternalRef': 0,
            'NoOfEmptyRef': 0,
            'NoOfImage': 0,
            'NoOfCSS': 0,
            'NoOfJS': 0,
            'HasSubmitButton': 0,
            'HasPasswordField': 0,
            'HasDescription': 0,
            'HasFavicon': 0,
            'HasCopyrightInfo': 0,
            'HasSocialNet': 0
        }
        
    return pd.Series(features)

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
        
        # Ensure features match the training data
        features_df = pd.DataFrame([url_features])
        features_df = features_df[feature_names]  # Reorder columns to match training data
        
        # Apply preprocessing
        features_imputed = imputer.transform(features_df)
        features_scaled = scaler.transform(features_imputed)
        
        # Make prediction
        prediction = model.predict(features_scaled)[0]
        confidence = model.predict_proba(features_scaled)[0].max()
        
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