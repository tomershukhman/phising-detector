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
    
    # Define challenging legitimate URLs
    # These URLs have characteristics that might trigger false positives
    legitimate_urls = [
        "https://login.microsoftonline.com/common/oauth2/authorize?client_id=29d9ed98-a469-4536-ade2-f981bc1d605e",  # Long URL with parameters
        "https://accounts.google.com/o/oauth2/auth/identifier?client_id=717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com",  # Long auth URL
        "https://secure2.store.apple.com/shop/signIn/orders?r=SCDHYHP7CY4H9KXEX",  # Secure subdomain with number
        "https://github.com/login?return_to=%2Fjoin%3Fsource%3Dheader-home",  # URL with encoded parameters
        "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com",  # Complex auth URL
        "https://www.paypal.com/signin?returnUri=https%3A%2F%2Fwww.paypal.com%2Fmyaccount%2Ftransfer",  # Auth URL with returnUri
        "https://www.bankofamerica.com/online-banking/sign-in/",  # Banking URL with dashes
        "https://account.t-mobile.com/oauth2/v1/auth/login-password",  # Mobile provider with version in URL
        "https://appleid.apple.com/auth/oauth2/authorize?client_id=com.apple.gs.xcode.auth",  # Apple ID auth URL
        "https://login.yahoo.com/?.src=ym&.intl=us&.lang=en-US&.done=https%3A%2F%2Fmail.yahoo.com"  # Yahoo login with multiple parameters
    ]
    
    # Challenging phishing URLs - these are more sophisticated examples
    # These are constructed examples and should not be real phishing sites
    suspicious_urls = [
        "https://login-microsoft365.com/signin",  # Convincing domain with dash
        "https://accounts-google.com/signin/v2/challenge/pwd",  # Convincing domain with legitimate-looking path
        "https://appleid-verify.com/manage/overview",  # Brand + action word domain
        "https://www.paypaI.com/us/signin",  # Homograph attack (capital I instead of l)
        "https://amazonprime.delivery/tracking/order",  # Brand + related word domain
        "https://secure-bankofamerica.com/login.php",  # Secure prefix with brand
        "https://www.dropbox.security-check.com/verify",  # Subdomain using brand name
        "https://netflix-account-services.com/renew-membership",  # Service-related domain
        "https://online.banking-wells-fargo.com/auth",  # Legitimate-looking banking URL
        "https://www.linkedin.com.profile-view.xyz/",  # Path after TLD
        "https://facebook-login-secure.herokuapp.com/",  # Popular hosting service
        "https://instagram-verify.onrender.com/confirm-identity",  # Cloud platform with brand
        "https://confirm-chase-account.vercel.app/",  # Modern hosting platform
        "https://www.docusign.com.document-verify.site/signing"  # Brand with action words
    ]
    
    # For advanced testing - URLs with mixed signals
    edge_case_urls = [
        # Legitimate but suspicious-looking URLs
        "https://sandbox.paypal.com/webapps/auth/login",  # Testing subdomain of legitimate site
        "https://test-payment.adyen.com/hpp/pay.shtml",  # Payment processor test environment
        "https://demo.stripe.com/v3/elements?login=true",  # Payment demo site
        "https://developer-account.intel.com/dashboard/2FA",  # Developer portal with number
        "https://login.salesforce.com/secur/forgotpassword.jsp",  # Enterprise login with JSP
        
        # Phishing but with sophisticated techniques
        "https://review-account-security.com/microsoft/sso",  # Generic domain with brand in path
        "https://credential-verification.com/google/signin",  # Generic domain with recognizable path
        "https://drive-google.share-document.com/view",  # Convincing domain combination
        "https://secure.banking-updates.com/chase/login",  # Security words with brand in path
        "https://mail.google.com.mailbox-verify.site/signin"  # Full domain prefix of legitimate site
    ]
    
    # Combine edge cases with main test sets for comprehensive testing
    legitimate_urls.extend([url for url in edge_case_urls[:5]])  # First 5 are legitimate
    suspicious_urls.extend([url for url in edge_case_urls[5:]])  # Rest are phishing
    
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
    print("\nTesting sophisticated phishing URLs...")
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