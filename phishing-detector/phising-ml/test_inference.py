#!/usr/bin/env python3
"""
Phishing Detector Inference Script
This script runs the trained phishing detector model on a set of example URLs
to demonstrate its effectiveness in identifying phishing and legitimate websites.
"""

import joblib
import time
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from tabulate import tabulate
from features_extraction import extract_features

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
    except AttributeError:
        return None

def predict_url(url, model, feature_columns=None):
    """
    Predict if a URL is phishing or legitimate
    
    Args:
        url: The URL to analyze
        model: The trained machine learning model
        feature_columns: Optional list of feature column names expected by the model
                         If None, will use the features as extracted
        
    Returns:
        Dictionary with prediction result and URL
    """
    # Extract features from URL using the local extract_features function
    features = extract_features(url)
    
    # Convert extracted features to DataFrame
    import pandas as pd
    features_df = pd.DataFrame([features])
    
    if feature_columns is not None:
        # Make sure all expected columns exist (fill missing with 0)
        for col in feature_columns:
            if col not in features_df.columns:
                features_df[col] = 0
                
        # Use only the columns expected by the model
        features_df = features_df[feature_columns]
    
    # Make prediction
    prediction = model.predict(features_df)[0]
    result = "Phishing" if prediction == 1 else "Legitimate"
    
    return {
        "url": url,
        "prediction": result,
        "raw_prediction": prediction
    }

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
    true_labels = []
    predicted_labels = []
    
    # Test legitimate URLs
    print("\nTesting legitimate URLs...")
    for url in legitimate_urls:
        try:
            start_time = time.time()
            result = predict_url(url, model, feature_columns)
            processing_time = time.time() - start_time
            
            # Store the true label (legitimate = 0)
            true_labels.append(0)
            # Store the predicted label (Legitimate = 0, Phishing = 1)
            predicted_labels.append(1 if result["prediction"] == "Phishing" else 0)
            
            results.append({
                "url": url,
                "true_label": "Legitimate",
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
            
            # Store the true label (phishing = 1)
            true_labels.append(1)
            # Store the predicted label (Legitimate = 0, Phishing = 1)
            predicted_labels.append(1 if result["prediction"] == "Phishing" else 0)
            
            results.append({
                "url": url,
                "true_label": "Phishing",
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
            result["true_label"],
            result["prediction"],
            f"{result['processing_time']:.2f}s"
        ])
    
    headers = ["URL", "True Label", "Prediction", "Processing Time"]
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
    
    # Create and display confusion matrix
    labels = ["Legitimate", "Phishing"]
    cm = confusion_matrix(true_labels, predicted_labels)
    
    print("\nConfusion Matrix:")
    print("True \\ Predicted |  Legitimate  |  Phishing  ")
    print("-"*45)
    print(f"Legitimate      |      {cm[0][0]}        |     {cm[0][1]}     ")
    print(f"Phishing        |      {cm[1][0]}        |     {cm[1][1]}     ")
    
    # Visualize the confusion matrix
    fig, ax = plt.subplots(figsize=(8, 6))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
    disp.plot(cmap=plt.cm.Blues, ax=ax)
    plt.title("Phishing Detection Confusion Matrix")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png")
    print("\nConfusion matrix visualization saved as 'confusion_matrix.png'")
    
    # Calculate additional metrics
    true_positives = cm[1][1]   # Correctly identified phishing
    true_negatives = cm[0][0]   # Correctly identified legitimate
    false_positives = cm[0][1]  # Legitimate incorrectly classified as phishing
    false_negatives = cm[1][0]  # Phishing incorrectly classified as legitimate
    
    accuracy = (true_positives + true_negatives) / total_count
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print("\nPerformance Metrics:")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1_score:.4f}")

if __name__ == "__main__":
    main()