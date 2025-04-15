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
    # Updated to use our consistent mapping: -1 for phishing, 1 for legitimate
    result = "Phishing" if prediction == -1 else "Legitimate"
    
    return {
        "url": url,
        "prediction": result,
        "raw_prediction": prediction
    }

def main():
    """Main function to run inference on a set of URLs"""
    print("Phishing Detector - Advanced Challenge Test")
    print("===========================================")
    
    # Load the model
    model = load_model()
    feature_columns = get_feature_columns(model)
    
    # URLs for testing
    legit_urls = [
        "https://www.aiismath.com/",
        "https://www.youtube.com/playlist?list=PLmWq-5VQxdn533RW5XgpCvLadG-qzMMvI",
        "https://www.visidata.org/credits/",
        "https://phishtank.org/",
        # Additional legitimate URLs
        "https://docs.voxel51.com/dataset_zoo/index.html",
        "https://lightning.ai/tomershukhman-3ftjt/home",
        "https://resources.arc.net/hc/en-us",
        "https://www.leumi.co.il/he",
        "https://www.amazon.com/s?k=gaming+headsets"
    ]

    phishing_urls = [
        "https://sudden-hazel-alligator.glitch.me/",
        "https://quirky-nebula-almandine.glitch.me/",
        "https://www.filmreviewers.com/",
        "https://youremotejobs.com/",
        "http://amazon-first-project.vercel.app/",
        # Additional phishing URLs
        "http://support-docs--ledgre.webflow.io/",
        "https://fedex.com-pf.sbs/us/payment.html",
        "https://www.appshop-allegro.com/",
        "http://applynflix.com/",
        "https://www.whatsapp-direct.ru/",
        "https://airbnb-v2-navy.vercel.app/"
    ]
    
    # Combine into test sets
    legitimate_urls = legit_urls
    
    results = []
    true_labels = []
    predicted_labels = []
    
    # Test legitimate URLs
    print("\nTesting challenging legitimate URLs...")
    for url in legitimate_urls:
        try:
            start_time = time.time()
            result = predict_url(url, model, feature_columns)
            processing_time = time.time() - start_time
            
            # Store the true label (legitimate = 1)
            true_labels.append(1)
            # Store the predicted label (Legitimate = 1, Phishing = -1)
            predicted_labels.append(1 if result["prediction"] == "Legitimate" else -1)
            
            results.append({
                "url": url,
                "true_label": "Legitimate",
                "prediction": result["prediction"],
                "processing_time": processing_time
            })
            
            print(f"✓ Processed: {url}")
        except Exception as e:
            print(f"✗ Error with {url}: {e}")
    
    # Test phishing URLs
    print("\nTesting sophisticated phishing URLs...")
    for url in phishing_urls:
        try:
            start_time = time.time()
            result = predict_url(url, model, feature_columns)
            processing_time = time.time() - start_time
            
            # Store the true label (phishing = -1)
            true_labels.append(-1)
            # Store the predicted label (Legitimate = 1, Phishing = -1)
            predicted_labels.append(1 if result["prediction"] == "Legitimate" else -1)
            
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
        # Determine if the prediction was correct
        is_correct = result["true_label"] == result["prediction"]
        correctness = "✓ Correct" if is_correct else "✗ Wrong"
        
        table_data.append([
            result["url"][:60] + "..." if len(result["url"]) > 60 else result["url"],
            result["true_label"],
            result["prediction"],
            correctness,
            f"{result['processing_time']:.2f}s"
        ])
    
    headers = ["URL", "True Label", "Prediction", "Correctness", "Processing Time"]
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
    labels = ["Phishing", "Legitimate"]
    # Convert prediction values to indices for confusion matrix
    # Map -1 to 0 index, and 1 to 1 index
    true_indices = [(val + 1) // 2 for val in true_labels]
    pred_indices = [(val + 1) // 2 for val in predicted_labels]
    cm = confusion_matrix(true_indices, pred_indices)
    
    print("\nConfusion Matrix:")
    print("True \\ Predicted |  Phishing  |  Legitimate  ")
    print("-"*45)
    print(f"Phishing        |     {cm[0][0]}      |     {cm[0][1]}     ")
    print(f"Legitimate      |     {cm[1][0]}      |     {cm[1][1]}     ")
    
    # Visualize the confusion matrix
    fig, ax = plt.subplots(figsize=(8, 6))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
    disp.plot(cmap=plt.cm.Blues, ax=ax)
    plt.title("Phishing Detection Confusion Matrix")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png")
    print("\nConfusion matrix visualization saved as 'confusion_matrix.png'")
    
    # Calculate additional metrics - adjusting indices for our mapping
    true_positives = cm[0][0]   # Correctly identified phishing
    true_negatives = cm[1][1]   # Correctly identified legitimate
    false_positives = cm[1][0]  # Legitimate incorrectly classified as phishing
    false_negatives = cm[0][1]  # Phishing incorrectly classified as legitimate
    
    accuracy = (true_positives + true_negatives) / total_count
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print("\nPerformance Metrics:")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1_score:.4f}")
    
    # Additional analysis - categorize errors (adjust for our new mapping)
    false_positive_examples = [r for r in results if r["true_label"] == "Legitimate" and r["prediction"] == "Phishing"]
    false_negative_examples = [r for r in results if r["true_label"] == "Phishing" and r["prediction"] == "Legitimate"]
    
    if false_positive_examples:
        print("\nFalse Positive Examples (Legitimate URLs classified as Phishing):")
        for i, example in enumerate(false_positive_examples[:5], 1):  # Show up to 5 examples
            print(f"{i}. {example['url']}")
        if len(false_positive_examples) > 5:
            print(f"...and {len(false_positive_examples) - 5} more")
    
    if false_negative_examples:
        print("\nFalse Negative Examples (Phishing URLs classified as Legitimate):")
        for i, example in enumerate(false_negative_examples[:5], 1):  # Show up to 5 examples
            print(f"{i}. {example['url']}")
        if len(false_negative_examples) > 5:
            print(f"...and {len(false_negative_examples) - 5} more")
    
if __name__ == "__main__":
    main()