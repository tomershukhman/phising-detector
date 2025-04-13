#!/usr/bin/env python3
"""
Phishing Detector Inference Script
This script runs the trained phishing detector model on a set of example URLs
to demonstrate its effectiveness in identifying phishing and legitimate websites.
"""

import joblib
import time
from tabulate import tabulate
from utils import predict_url

def load_model(model_path='phishing_detector_model.pkl'):
    """Load the trained phishing detector model"""
    print(f"Loading model from {model_path}...")
    return joblib.load(model_path)

def get_feature_columns(model):
    """Get the feature columns used by the model"""
    # This function assumes the model has feature_names_ attribute
    # If not, we'll return None and handle it in the predict function
    try:
        return model.feature_names_in_
    except:
        return None

def main():
    """Main function to run inference on a set of URLs"""
    print("Phishing Detector - Inference Test")
    print("==================================")
    
    # Load the model
    model = load_model()
    feature_columns = get_feature_columns(model)
    
    # Define test URLs - a mix of legitimate and potentially phishing sites
    # Note: All URLs should be valid at the time of script execution
    legitimate_urls = [
        "https://www.google.com",
        "https://www.apple.com",
        "https://www.microsoft.com",
        "https://www.amazon.com",
        "https://github.com",
        "https://www.nytimes.com",
        "https://www.cnn.com",
        "https://stackoverflow.com",
        "https://www.wikipedia.org",
        "https://www.reddit.com"
    ]
    
    # These are example URLs that have characteristics common in phishing sites
    # Note: Some of these are constructed examples and may not be actual phishing sites
    suspicious_urls = [
        "http://192.168.1.1/login.php",  # IP instead of domain
        "http://bit.ly/3xR5tY",  # URL shortener
        "https://secure-banking.com-user-session.info",  # Domain spoofing
        "http://paypal.com@secure-account-login.com",  # @ symbol in URL
        "https://banking.secure.com//redirect",  # Double slash redirect
        "https://secure-bank-verification-center.com",  # Long URL with dashes
        "https://login.secure.banking.com.verify.net",  # Multiple subdomains
        "https://banking-secure-https.com",  # HTTPS in domain name
        "http://0x58.0xCC.0xCA.0x62/secure",  # Hexadecimal IP
        "http://secure.bank.com.phishing.xyz/login"  # Multi-level domain
    ]
    
    results = []
    
    # Test legitimate URLs
    print("\nTesting legitimate URLs...")
    for url in legitimate_urls:
        try:
            start_time = time.time()
            result = predict_url(url, model, feature_columns)
            processing_time = time.time() - start_time
            
            results.append({
                "url": url,
                "prediction": result["prediction"],
                "processing_time": processing_time
            })
            
            print(f"✓ Processed: {url}")
        except Exception as e:
            print(f"✗ Error with {url}: {e}")
    
    # Test suspicious URLs
    print("\nTesting suspicious URLs...")
    for url in suspicious_urls:
        try:
            start_time = time.time()
            result = predict_url(url, model, feature_columns)
            processing_time = time.time() - start_time
            
            results.append({
                "url": url,
                "prediction": result["prediction"],
                "processing_time": processing_time
            })
            
            print(f"✓ Processed: {url}")
        except Exception as e:
            print(f"✗ Error with {url}: {e}")
    
    # Display results in a table
    print("\nResults:")
    table_data = []
    
    for result in results:
        table_data.append([
            result["url"][:60] + "..." if len(result["url"]) > 60 else result["url"],
            result["prediction"],
            f"{result['processing_time']:.2f}s"
        ])
    
    headers = ["URL", "Prediction", "Processing Time"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # Calculate statistics
    legitimate_count = sum(1 for r in results if r["prediction"] == "Legitimate")
    phishing_count = sum(1 for r in results if r["prediction"] == "Phishing")
    total_count = len(results)
    
    print("\nSummary:")
    print(f"Total URLs tested: {total_count}")
    print(f"Predicted legitimate: {legitimate_count} ({legitimate_count/total_count*100:.1f}%)")
    print(f"Predicted phishing: {phishing_count} ({phishing_count/total_count*100:.1f}%)")
    print(f"Average processing time: {sum(r['processing_time'] for r in results)/total_count:.2f}s")

if __name__ == "__main__":
    main()