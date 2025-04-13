#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script for the phishing detection model.
This script loads the trained model and tests it with real-world phishing and legitimate URLs.
"""

import os
import sys
import joblib
import pandas as pd
from urllib.parse import urlparse
import re
import requests
import urllib3
from bs4 import BeautifulSoup

# Disable SSL warnings
urllib3.disable_warnings()

def load_model():
    """Load the saved phishing detection model"""
    model_path = "phishing_model.pkl"
    features_path = "selected_features.pkl"
    
    if os.path.exists(model_path) and os.path.exists(features_path):
        print("Loading model...")
        model = joblib.load(model_path)
        feature_list = joblib.load(features_path)
        return model, feature_list
    else:
        print("ERROR: Model files not found!")
        sys.exit(1)

def extract_features_for_url(url, feature_list):
    """Extract features from a single URL based on the feature list"""
    # First create a Series for consistent processing
    url_series = pd.Series([url])
    
    # Use the same feature extraction as in the training
    from phishing_model import extract_features
    features_df = extract_features(url_series)
    
    # Make sure we have all the required features in the right order
    result = pd.DataFrame(columns=feature_list)
    for feature in feature_list:
        if feature in features_df.columns:
            result[feature] = features_df[feature]
        else:
            result[feature] = 0  # Default value
    
    return result

def predict_url(url, model, feature_list, output_file=None):
    """Predict if a URL is phishing or legitimate"""
    print(f"\nAnalyzing URL: {url}")
    
    # Extract features
    features = extract_features_for_url(url, feature_list)
    
    # Make prediction
    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]
    
    # Determine confidence
    confidence = probabilities[1] if prediction == 1 else probabilities[0]
    
    # Format result
    result = "PHISHING" if prediction == 1 else "LEGITIMATE"
    
    # Print to console
    print(f"Prediction: {result} with {confidence:.2%} confidence")
    
    # Feature summary (most important ones)
    important_features = {
        'url_length': features['url_length'].values[0],
        'has_suspicious_word': features['has_suspicious_word'].values[0] if 'has_suspicious_word' in features else 'N/A',
        'has_brand': features['has_brand'].values[0] if 'has_brand' in features else 'N/A',
        'has_digit_substitution': features['has_digit_substitution'].values[0] if 'has_digit_substitution' in features else 'N/A',
        'num_dots': features['num_dots'].values[0],
        'num_dashes': features['num_dashes'].values[0],
        'domain_length': features['domain_length'].values[0] if 'domain_length' in features else 'N/A'
    }
    print(f"Key features: {important_features}")
    
    # Write to output file
    if output_file:
        output_file.write(f"URL: {url}\n")
        output_file.write(f"Prediction: {result} with {confidence:.2%} confidence\n")
        output_file.write("Key features:\n")
        for feature, value in important_features.items():
            output_file.write(f"  {feature}: {value}\n")
        output_file.write("\n")
    
    return result, confidence

def main():
    """Main function to test URLs with the trained model"""
    print("Loading phishing detection model...")
    model, feature_list = load_model()
    
    # Expanded list of legitimate URLs with more variety
    legitimate_urls = [
        # Major websites
        "https://www.google.com",
        "https://www.amazon.com",
        "https://www.microsoft.com",
        
        # News sites
        "https://www.nytimes.com/section/politics",
        "https://www.bbc.co.uk/news/world",
        "https://edition.cnn.com/travel",
        
        # Tech/developer sites
        "https://www.github.com/features",
        "https://stackoverflow.com/questions/tagged/python",
        "https://developer.mozilla.org/en-US/docs/Web",
        
        # Educational sites
        "https://www.wikipedia.org/wiki/Machine_learning",
        "https://www.khanacademy.org/math",
        "https://www.coursera.org/courses?query=data%20science",
        
        # Entertainment
        "https://www.netflix.com/browse/genre/83",
        "https://www.youtube.com/feed/trending",
        "https://open.spotify.com/genre/podcasts-web",
        
        # Shopping
        "https://www.ebay.com/b/Electronics/bn_7000259124",
        "https://www.etsy.com/c/jewelry-and-accessories?ref=catnav-10855",
        
        # Social media
        "https://www.facebook.com/groups/",
        "https://twitter.com/explore",
        "https://www.linkedin.com/jobs/"
    ]
    
    # Expanded list of phishing URLs with more sophisticated patterns
    phishing_urls = [
        # Basic phishing with suspicious words
        "https://g00gle-acc0unt-verify.netlify.app",
        "https://appleid.apple.com.signin-verify.info",
        "https://amazon-verification.com/signin",
        
        # Domain spoofing with subdomains
        "https://login.microsoft.com.security-check.malicious-site.com/",
        "https://secure-paypal.com.restoreaccount.info/login.php",
        "https://accounts.google.com.password-reset.suspiciousdomain.co/verify",
        
        # Typosquatting (character substitution)
        "https://www.arnazon.com/order/confirmation", # 'rn' instead of 'm'
        "https://www.paypa1.com/account/security",   # '1' instead of 'l'
        "https://www.g00gle.com/mail/secure",        # '0' instead of 'o'
        
        # URL shorteners (often used in phishing)
        "https://bit.ly/3xR5tY7",  # Simulating shortened malicious URL
        "https://tinyurl.com/nhf5d2zx",  # Another shortened URL example
        
        # Complex paths and parameters to look legitimate
        "https://secure.bankofamerica.com.logon.sicherheit-update.com/login?session=expired&redirect=true",
        "https://www.dropbox.com.file.share.stsystems.ca/document/invoice?id=12345&auth=true",
        
        # Brand impersonation with suspicious domains
        "https://www.facebook-security-login.com/checkpoint/",
        "https://netflix-updatepayment.com/billing/update?region=us",
        
        # Excessive subdomains
        "https://accounts.google.com.security.login.auth.serv07.cf/",
        "https://auth.login.secure.myaccount.apple.com.id-apple.net/verify",
        
        # Uncommon TLDs
        "https://amazon-orders.xyz/track-package",
        "https://microsoft-365-update.tk/admin",
        
        # IP addresses instead of domains
        "http://192.168.12.34/paypal/login",
        "https://137.44.12.89/banking/auth"
    ]
    
    # Open output file
    output_path = "out.txt"
    print(f"Saving results to {output_path}")
    output_file = open(output_path, 'w')
    output_file.write("=== PHISHING DETECTION RESULTS ===\n\n")
    
    # Test legitimate URLs
    print("\n=== Testing Legitimate URLs ===")
    output_file.write("=== LEGITIMATE URLS ===\n\n")
    legitimate_results = []
    for url in legitimate_urls:
        try:
            result, confidence = predict_url(url, model, feature_list, output_file)
            legitimate_results.append((url, result, confidence))
        except Exception as e:
            print(f"Error processing {url}: {str(e)}")
            output_file.write(f"Error processing {url}: {str(e)}\n\n")
    
    # Test phishing URLs
    print("\n=== Testing Phishing URLs ===")
    output_file.write("\n=== PHISHING URLS ===\n\n")
    phishing_results = []
    for url in phishing_urls:
        try:
            result, confidence = predict_url(url, model, feature_list, output_file)
            phishing_results.append((url, result, confidence))
        except Exception as e:
            print(f"Error processing {url}: {str(e)}")
            output_file.write(f"Error processing {url}: {str(e)}\n\n")
    
    # Summarize results
    correct_legitimate = sum(1 for _, result, _ in legitimate_results if result == "LEGITIMATE")
    correct_phishing = sum(1 for _, result, _ in phishing_results if result == "PHISHING")
    
    print("\n=== Results Summary ===")
    print(f"Legitimate URLs: {correct_legitimate}/{len(legitimate_results)} correct ({correct_legitimate/len(legitimate_results):.2%})")
    print(f"Phishing URLs: {correct_phishing}/{len(phishing_results)} correct ({correct_phishing/len(phishing_results):.2%})")
    total_correct = correct_legitimate + correct_phishing
    total = len(legitimate_results) + len(phishing_results)
    print(f"Overall accuracy: {total_correct}/{total} ({total_correct/total:.2%})")
    
    # Write summary to file
    output_file.write("\n=== RESULTS SUMMARY ===\n")
    output_file.write(f"Legitimate URLs: {correct_legitimate}/{len(legitimate_results)} correct ({correct_legitimate/len(legitimate_results):.2%})\n")
    output_file.write(f"Phishing URLs: {correct_phishing}/{len(phishing_results)} correct ({correct_phishing/len(phishing_results):.2%})\n")
    output_file.write(f"Overall accuracy: {total_correct}/{total} ({total_correct/total:.2%})\n")
    
    output_file.close()
    print(f"Results saved to {output_path}")

if __name__ == "__main__":
    main()
