#!/usr/bin/env python3
"""
Phishing Detector Inference Script
This script runs the trained phishing detector model on URLs from a CSV file
to demonstrate its effectiveness in identifying phishing and legitimate websites.
"""

import joblib
import pandas as pd
import numpy as np
import time
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, classification_report
from tabulate import tabulate
import csv
import random
from collections import Counter
from urllib.parse import urlparse
from features_extraction import extract_features
import seaborn as sns  # Add this import
from class_labels_mapping import PHISING_LABEL, LEGITIMATE_LABEL, AMBIGUOUS_LABEL

DEBUG_SAMPLES = 5  # Number of samples per class to use in debug mode

def load_model(model_path='phishing_detector_model.pkl'):
    """Load the trained phishing detector model"""
    print(f"Loading model from {model_path}...")
    return joblib.load(model_path)

def get_feature_columns(model):
    """Get the feature columns used by the model"""
    # This function assumes the model has feature_names_in_ attribute
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
    # Extract features from URL
    features = extract_features(url)
    
    # Convert extracted features to DataFrame
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
    result = "Phishing" if prediction == -1 else "Legitimate"
    
    return {
        "url": url,
        "prediction": result,
        "raw_prediction": prediction
    }

def load_test_urls(csv_path='test_urls.csv', max_samples=None):
    """
    Load test URLs from a CSV file
    
    Args:
        csv_path: Path to CSV file containing URLs and their actual labels
        max_samples: Maximum number of samples to load (if None, load all)
        
    Returns:
        List of dictionaries with URLs and actual labels
    """
    urls = []
    
    try:
        with open(csv_path, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                urls.append({
                    "url": row["url"],
                    "actual": 1 if int(row["result"]) == 1 else -1
                })
                
                if max_samples and len(urls) >= max_samples:
                    break
    except Exception as e:
        print(f"Error loading URLs from {csv_path}: {e}")
        return []
    
    print(f"Loaded {len(urls)} URLs from {csv_path}")
    return urls

def main(debug=False):
    """Main function to run inference on a set of URLs from CSV file"""
    
    # Load the model
    model = load_model()
    feature_columns = get_feature_columns(model)
    
    # Load URLs from CSV file
    csv_path = 'test_urls.csv'
    print(f"Reading URLs from {csv_path}")
    test_urls = load_test_urls(csv_path)

    # Debug mode: pick DEBUG_SAMPLES with result=1 and DEBUG_SAMPLES with result=-1
    if debug:
        pos_samples = [u for u in test_urls if u["actual"] == LEGITIMATE_LABEL][:DEBUG_SAMPLES]
        neg_samples = [u for u in test_urls if u["actual"] == PHISING_LABEL][:DEBUG_SAMPLES]
        test_urls = pos_samples + neg_samples
        print(f"[DEBUG MODE] Using {len(test_urls)} URLs: {len(pos_samples)} Legitimate, {len(neg_samples)} Phishing")
    
    # Perform inference
    print("\nRunning inference on test URLs...")
    results = []
    start_time = time.time()
    
    for i, url_info in enumerate(test_urls):
        url = url_info["url"]
        actual = url_info["actual"]
        
        try:
            print(f"\n[{i+1}/{len(test_urls)}] Testing: {url}")
            result = predict_url(url, model, feature_columns)
            result["actual"] = "Phishing" if actual == PHISING_LABEL else "Legitimate"
            result["actual_raw"] = actual
            results.append(result)
            print(f"Prediction: {result['prediction']}, Actual: {result['actual']}")
        except Exception as e:
            print(f"Error predicting URL {url}: {e}")
    
    end_time = time.time()
    
    # Calculate statistics
    print(f"\nProcessed {len(results)} URLs in {end_time - start_time:.2f} seconds")
    
    # Show results in a table
    table_data = []
    y_true = []
    y_pred = []
    
    for result in results:
        table_data.append([
            result["url"][:50] + "..." if len(result["url"]) > 50 else result["url"],
            result["prediction"],
            result["actual"],
            "✓" if result["prediction"] == result["actual"] else "✗"
        ])
        y_true.append(result["actual_raw"])
        y_pred.append(result["raw_prediction"])
    
    print("\nSample Results:")
    print(tabulate(table_data[:10], headers=["URL", "Prediction", "Actual", "Correct"]))
    
    # Calculate and display accuracy
    correct = sum(1 for r in results if r["prediction"] == r["actual"])
    accuracy = correct / len(results) if results else 0
    print(f"\nOverall Accuracy: {accuracy:.2f} ({correct}/{len(results)})")
    
    # Display classification report
    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, labels=[PHISING_LABEL, LEGITIMATE_LABEL], target_names=["Phishing", "Legitimate"], zero_division=0))
    
    # Display confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=[PHISING_LABEL, LEGITIMATE_LABEL])
    print("\nConfusion Matrix:")
    print(cm)
    
    # Plot confusion matrix
    fig, ax = plt.subplots(figsize=(8, 6))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Phishing", "Legitimate"])
    disp.plot(ax=ax)
    plt.title("Phishing Detection Confusion Matrix")
    plt.savefig("confusion_matrix.png")
    print("\nConfusion matrix saved as 'confusion_matrix.png'")
    
    # Plot confusion matrix (seaborn heatmap for readability)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=True,
                xticklabels=["Phishing", "Legitimate"],
                yticklabels=["Phishing", "Legitimate"], ax=ax)
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.title('Phishing Detection Confusion Matrix (Readable)')
    plt.tight_layout()
    plt.savefig('confusion_matrix_readable.png')
    print("\nReadable confusion matrix saved as 'confusion_matrix_readable.png'")
    
    # Additional statistics
    prediction_counts = Counter(r["prediction"] for r in results)
    actual_counts = Counter(r["actual"] for r in results)
    
    print("\nPrediction Distribution:")
    for category, count in prediction_counts.items():
        print(f"{category}: {count} ({count/len(results):.1%})")
    
    print("\nActual Distribution:")
    for category, count in actual_counts.items():
        print(f"{category}: {count} ({count/len(results):.1%})")

if __name__ == "__main__":
    import sys
    debug = "--debug" in sys.argv
    main(debug=debug)