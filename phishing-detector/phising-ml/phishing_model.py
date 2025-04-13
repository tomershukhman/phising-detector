#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Instead of using the dataset which seems to have issues, let's build our own
def create_synthetic_dataset(num_samples=1000):
    """Create a synthetic dataset of phishing and legitimate URLs"""
    print("Creating synthetic dataset instead of using the problematic Kaggle dataset")
    
    # List of legitimate domains and TLDs
    legitimate_domains = [
        "google.com", "facebook.com", "amazon.com", "youtube.com", "twitter.com",
        "instagram.com", "linkedin.com", "microsoft.com", "apple.com", "reddit.com",
        "netflix.com", "wikipedia.org", "yahoo.com", "ebay.com", "twitch.tv",
        "github.com", "stackoverflow.com", "spotify.com", "cnn.com", "nytimes.com"
    ]
    
    tlds = [".com", ".org", ".net", ".edu", ".gov", ".io", ".co", ".uk", ".ca", ".de", ".jp"]
    
    # Suspicious patterns for creating phishing URLs
    phishing_patterns = [
        # Brand + suspicious words
        "{brand}-login.{fake_domain}",
        "{brand}.secure-{random}.{tld}",
        "{brand}-account-verify.{tld}",
        "login-{brand}.{fake_domain}",
        "secure-{brand}.{tld}",
        "{brand}-{random}-signin.{tld}",
        # Look-alike domains with character substitution
        "{modified_brand}.{tld}",
        # Long subdomains
        "{brand}.{random}.{random}.{tld}",
        # Multiple dashes
        "{brand}-secure-login-account.{tld}",
        # Domain with suspicious TLD
        "{brand}.{suspicious_tld}",
        # IP-looking domain
        "192.168.{random}.{random}/{brand}"
    ]
    
    def random_string(length=5):
        """Generate a random alphanumeric string"""
        import random
        import string
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def modify_brand(brand):
        """Create a typosquatted version of a brand name"""
        import random
        chars = list(brand)
        # Randomly choose a modification
        mod_type = random.randint(0, 3)
        if mod_type == 0 and len(brand) > 3:  # Character swap
            i = random.randint(0, len(chars) - 2)
            chars[i], chars[i+1] = chars[i+1], chars[i]
        elif mod_type == 1:  # Replace 'o' with '0', 'l' with '1', etc.
            replacements = {'o': '0', 'l': '1', 'e': '3', 'a': '4', 's': '5', 'i': '1'}
            for char, replacement in replacements.items():
                if char in brand:
                    chars[brand.index(char)] = replacement
                    break
        elif mod_type == 2:  # Character duplication
            i = random.randint(0, len(chars) - 1)
            chars.insert(i, chars[i])
        elif mod_type == 3:  # Character omission
            if len(brand) > 3:
                i = random.randint(0, len(chars) - 1)
                chars.pop(i)
        return ''.join(chars)
    
    # Generate synthetic data
    urls = []
    labels = []
    
    # Generate legitimate URLs
    for _ in range(num_samples // 2):
        domain = np.random.choice(legitimate_domains)
        brand = domain.split('.')[0]
        
        # Various legitimate URL patterns
        url_type = np.random.randint(0, 5)
        if url_type == 0:  # Simple domain
            url = f"https://www.{domain}"
        elif url_type == 1:  # With path
            path = np.random.choice(["index.html", "home", "products", "about", "contact", "login", "help"])
            url = f"https://www.{domain}/{path}"
        elif url_type == 2:  # With subdomain
            subdomain = np.random.choice(["mail", "drive", "docs", "cloud", "support", "help", "shop", "store"])
            url = f"https://{subdomain}.{domain}"
        elif url_type == 3:  # With query parameters
            param = np.random.choice(["id", "q", "page", "search", "ref"])
            value = random_string()
            url = f"https://www.{domain}?{param}={value}"
        else:  # Complex URL
            path = np.random.choice(["index.html", "home", "products", "about", "contact", "login", "help"])
            param = np.random.choice(["id", "q", "page", "search", "ref"])
            value = random_string()
            url = f"https://www.{domain}/{path}?{param}={value}"
        
        urls.append(url)
        labels.append(0)  # 0 for legitimate
    
    # Generate phishing URLs
    for _ in range(num_samples // 2):
        target_brand = np.random.choice(legitimate_domains).split('.')[0]
        pattern = np.random.choice(phishing_patterns)
        
        # Apply the pattern
        fake_domain = np.random.choice(legitimate_domains)
        tld = np.random.choice(tlds)
        suspicious_tld = np.random.choice([".xyz", ".info", ".tk", ".pw", ".cc", ".gq", ".ml", ".ga", ".cf"])
        random1 = random_string()
        random2 = random_string()
        modified = modify_brand(target_brand)
        
        url = pattern.format(
            brand=target_brand,
            fake_domain=fake_domain,
            tld=tld,
            suspicious_tld=suspicious_tld,
            random=random1,
            modified_brand=modified,
            random2=random2
        )
        
        # Add http/https
        if not url.startswith(('http://', 'https://')):
            prefix = np.random.choice(["http://", "https://"])
            url = prefix + url
        
        urls.append(url)
        labels.append(1)  # 1 for phishing
    
    # Create DataFrame
    df = pd.DataFrame({
        'url': urls,
        'label': labels
    })
    
    # Shuffle the data
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return df

def extract_features(urls):
    """Extract features from URLs that are effective for phishing detection"""
    features = pd.DataFrame()
    
    # URL length
    features['url_length'] = urls.apply(len)
    
    # Count special characters
    features['num_dots'] = urls.apply(lambda x: x.count('.'))
    features['num_dashes'] = urls.apply(lambda x: x.count('-'))
    features['num_underscores'] = urls.apply(lambda x: x.count('_'))
    features['num_slashes'] = urls.apply(lambda x: x.count('/'))
    features['num_digits'] = urls.apply(lambda x: sum(c.isdigit() for c in x))
    features['num_at_signs'] = urls.apply(lambda x: x.count('@'))
    features['num_equals'] = urls.apply(lambda x: x.count('='))
    features['num_qs'] = urls.apply(lambda x: x.count('?'))
    
    # Ratios
    features['digit_ratio'] = features['num_digits'] / features['url_length']
    features['special_char_ratio'] = (features['num_dots'] + features['num_dashes'] + 
                                      features['num_underscores'] + features['num_slashes'] + 
                                      features['num_at_signs'] + features['num_equals'] + 
                                      features['num_qs']) / features['url_length']
    
    # Domain and path features
    def parse_domain_features(url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            # Handle URLs without scheme
            if not domain and path:
                parts = url.split('/', 1)
                if parts[0] and '.' in parts[0]:
                    domain = parts[0]
                    path = '/' + parts[1] if len(parts) > 1 else ''
            
            # Domain features
            domain_length = len(domain)
            num_subdomains = domain.count('.') + (1 if domain.startswith('www.') else 0)
            
            # Path features
            path_length = len(path)
            num_path_segments = path.count('/')
            
            # TLD
            tld = domain.split('.')[-1] if '.' in domain else ''
            tld_length = len(tld)
            
            # Check for suspicious TLDs
            suspicious_tlds = ['xyz', 'info', 'tk', 'pw', 'cc', 'gq', 'ml', 'ga', 'cf']
            has_suspicious_tld = 1 if tld in suspicious_tlds else 0
            
            return {
                'domain_length': domain_length,
                'num_subdomains': num_subdomains,
                'path_length': path_length,
                'num_path_segments': num_path_segments,
                'tld_length': tld_length,
                'has_suspicious_tld': has_suspicious_tld
            }
        except:
            return {
                'domain_length': 0,
                'num_subdomains': 0,
                'path_length': 0,
                'num_path_segments': 0,
                'tld_length': 0,
                'has_suspicious_tld': 0
            }
    
    domain_features = urls.apply(parse_domain_features).apply(pd.Series)
    features = pd.concat([features, domain_features], axis=1)
    
    # Check for brand names and suspicious words
    def check_brand_and_suspicious(url):
        url_lower = url.lower()
        
        # Check for common brand names
        brand_names = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 
                       'netflix', 'linkedin', 'twitter', 'instagram', 'youtube']
        
        # Check for suspicious words
        suspicious_words = ['login', 'signin', 'secure', 'account', 'verify', 'update', 'confirm',
                            'password', 'banking', 'wallet', 'payment', 'security', 'auth']
        
        # Check for common digit substitutions
        digit_substitutions = ['g00gle', 'faceb00k', 'amaz0n', 'appl3', 'micr0s0ft', 'paypa1',
                              'netfl1x', 'l1nked1n', 'tw1tter', '1nstagram', 'y0utube']
        
        has_brand = 0
        has_suspicious = 0
        has_digit_subst = 0
        
        for brand in brand_names:
            if brand in url_lower:
                has_brand = 1
                break
                
        for word in suspicious_words:
            if word in url_lower:
                has_suspicious = 1
                break
                
        for subst in digit_substitutions:
            if subst in url_lower:
                has_digit_subst = 1
                break
                
        # Check for brand + suspicious combination
        has_brand_suspicious = 1 if has_brand and has_suspicious else 0
        
        # Check for IP-like pattern
        has_ip_pattern = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
        
        return {
            'has_brand': has_brand,
            'has_suspicious_word': has_suspicious,
            'has_digit_substitution': has_digit_subst,
            'has_brand_suspicious': has_brand_suspicious,
            'has_ip_pattern': has_ip_pattern
        }
    
    word_features = urls.apply(check_brand_and_suspicious).apply(pd.Series)
    features = pd.concat([features, word_features], axis=1)
    
    # Character sequence features
    def character_sequence_features(url):
        # Check for consecutive dots, dashes, etc.
        consecutive_dots = max([len(match) for match in re.findall(r'\.+', url)] + [0])
        consecutive_dashes = max([len(match) for match in re.findall(r'\-+', url)] + [0])
        consecutive_digits = max([len(match) for match in re.findall(r'\d+', url)] + [0])
        
        return {
            'max_consecutive_dots': consecutive_dots,
            'max_consecutive_dashes': consecutive_dashes,
            'max_consecutive_digits': consecutive_digits
        }
    
    sequence_features = urls.apply(character_sequence_features).apply(pd.Series)
    features = pd.concat([features, sequence_features], axis=1)
    
    return features

def train_phishing_model():
    """Train a new phishing detection model from synthetic data"""
    # Create dataset
    df = create_synthetic_dataset(num_samples=5000)
    
    print(f"Created dataset with {len(df)} URLs ({df['label'].sum()} phishing, {len(df) - df['label'].sum()} legitimate)")
    print("\nSample legitimate URLs:")
    print(df[df['label'] == 0]['url'].head(3).tolist())
    print("\nSample phishing URLs:")
    print(df[df['label'] == 1]['url'].head(3).tolist())
    
    # Extract features
    print("\nExtracting features...")
    X = extract_features(df['url'])
    y = df['label']
    
    print(f"Extracted {X.shape[1]} features")
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Train the model
    print("\nTraining model...")
    model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\nEvaluating model...")
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    
    print(f"Train accuracy: {train_score:.4f}")
    print(f"Test accuracy: {test_score:.4f}")
    
    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Feature importance
    importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nTop 10 important features:")
    print(importance.head(10))
    
    # Test with examples
    print("\nTesting with example phishing URLs:")
    test_urls = [
        "https://g00gle-acc0unt-verify.netlify.app",
        "https://appleid.apple.com.signin-verify.info",
        "https://www.paypa1-secure.com/account/login",
        "https://www.facebook-security-login.com"
    ]
    
    test_features = extract_features(pd.Series(test_urls))
    test_predictions = model.predict(test_features)
    test_proba = model.predict_proba(test_features)
    
    for i, url in enumerate(test_urls):
        pred = "PHISHING" if test_predictions[i] == 1 else "LEGITIMATE"
        conf = test_proba[i][1] if test_predictions[i] == 1 else test_proba[i][0]
        print(f"URL: {url}")
        print(f"Prediction: {pred} (confidence: {conf:.2%})")
    
    # Save the model and feature list
    feature_list = list(X.columns)
    
    return model, feature_list

def main():
    """Main function to train and save the phishing model"""
    print("Training new phishing detection model using synthetic data...")
    model, feature_list = train_phishing_model()
    
    # Save the model and feature list
    print("\nSaving model...")
    joblib.dump(model, "phishing_model.pkl")
    joblib.dump(feature_list, "selected_features.pkl")
    # No need for scaler since we're not scaling features
    
    print("Model saved to phishing_model.pkl")
    print("Feature list saved to selected_features.pkl")
    
    return model, feature_list

if __name__ == "__main__":
    main()
