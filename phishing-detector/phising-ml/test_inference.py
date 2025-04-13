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
    print("Phishing Detector - Advanced Challenge Test")
    print("===========================================")
    
    # Load the model
    model = load_model()
    feature_columns = get_feature_columns(model)
    
    # CATEGORY 1: EXTREMELY DECEPTIVE PHISHING URLS
    # These are sophisticated phishing attempts using various advanced techniques
    sophisticated_phishing_urls = [
        # Typosquatting (character replacement/homograph)
        "https://www.аррӏе.com/icloud/login",  # Cyrillic 'а' and 'р' characters look like Latin 'a' and 'p'
        "https://www.faceboоk.com/login.php",  # Latin 'о' vs Cyrillic 'о'
        "https://www.microsоft.com/en-us/security",  # Another homograph attack with Cyrillic 'о'
        "https://www.amаzon.com/verify/account",  # Cyrillic 'а' instead of Latin 'a'
        
        # Subdomain manipulation
        "https://login.microsoft.com.security-check-required.com/auth",  # Full domain as subdomain
        "https://accounts-google.com.verification.biz/signin",  # Domain + subdomain tricks
        "https://bankofamerica.com.secure-banking.us/login",  # Using target domain as subdomain
        "https://www.paypal.com.account-security.app/",  # Modern TLD (.app) with legit domain as subdomain
        
        # Domain variations with security terms
        "https://secure-wells-fargo-bank.com/auth",  # Security words + brand
        "https://login-chase-secure-bank.com/verify",  # Multiple security terms
        "https://verified-appleid.cloud/manage",  # Security word with cloud TLD
        "https://authverify-amazon.co/review",  # Action verbs combined
        
        # Path manipulation (legitimate domain in path)
        "https://security-alert.com/microsoft.com/account/verify",  # Legitimate domain in path
        "https://verification-center.net/chase.com/statement",  # Banking domain in path
        "https://account-update.org/paypal.com/login",  # Payment provider in path
        "https://confirm-activity.site/instagram/unusual-login",  # Social media + action
        
        # Modern hosting platforms (harder to detect)
        "https://netflix-account-update.netlify.app/",  # Netlify (static hosting)
        "https://amazon-delivery-tracking.vercel.app/",  # Vercel (modern hosting)
        "https://apple-id-validate.web.app/",  # Firebase hosting
        "https://docusign-document-p346.onrender.com/",  # Render (cloud platform)
    ]
    
    # CATEGORY 2: LEGITIMATE URLS WITH SUSPICIOUS CHARACTERISTICS
    # These are real legitimate URLs that might trigger false positives
    deceptive_legitimate_urls = [
        # Legitimate sites with complex/suspicious looking URLs
        "https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=13&ct=1618675326",  # Microsoft complex login URL
        "https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmail.google.com",  # Google complex login
        "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.identity=http%3A%2F%2Fspecs.openid.net",  # Amazon OAuth
        "https://auth0.openai.com/u/login/identifier?state=hKFo2SBMVkR5b19yREIweHB",  # Auth0 login URL
        
        # Legitimate but with security/verification terms
        "https://secure.checkout.visa.com/checkout-widget/assets/img/src",  # 'secure' in legitimate domain
        "https://verify.twilio.com/v2/phone-numbers/verification/start",  # 'verify' in legitimate domain
        "https://id-verification.amazonaws.com/session",  # 'verification' in AWS subdomain
        "https://authentication.td.com/uap-ui/?consumer=easyweb",  # 'authentication' in bank domain
        
        # Legitimate but with uncommon TLDs or structures
        "https://auth.tesla.cn/oauth2/v3/authorize",  # Less common TLD (.cn)
        "https://signin.aws.amazon.com/oauth",  # Multiple subdomains for service
        "https://security-center.nasdaq.com/account/login",  # 'security' term in legitimate subdomain
        "https://www.instagram-engineering.com/blog",  # Legitimate brand + hyphen (official engineering blog)
        
        # Legitimate sandbox/development environments
        "https://test-sandbox.adyen.com/ca/ca.shtml",  # Payment processor test environment
        "https://developer-admin.sandbox.checkout.com/login",  # Dev sandbox with 'admin'
        "https://test.authorize.net/sandbox/account",  # Testing environment
        "https://sandbox.payfast.dev/engine/process",  # Payment sandbox environment
        
        # Legitimate but with URL structure similar to phishing
        "https://demo.stripe.com/account/login?redirect=%2Fdashboard",  # Demo site with redirect parameter
        "https://classroom.github.com/auth/github?auth_type=student",  # GitHub classroom auth
        "https://www.office.com/login?es=Click&ru=%2Fsetup",  # Microsoft Office login with parameters
        "https://login.mailchimp.com/oauth2/v1/authorize?response_type=code"  # OAuth flow
    ]
    
    # CATEGORY 3: EXTREMELY CHALLENGING EDGE CASES
    # These URLs are specifically designed to be very hard to classify correctly
    edge_case_urls = [
        # Legitimate but suspicious subdirectories using security terms
        "https://github.com/security/advisories/report",  # 'security' in path but legitimate
        "https://twitter.com/account/verify_credentials",  # 'verify' in path of legitimate site
        "https://developer.paypal.com/api/auth-credentials/",  # Auth in legitimate developer portal
        "https://help.netflix.com/legal/security-verification",  # Security term in help page
        
        # Phishing - domains that look very close to legitimate
        "https://www.cloudflare-cdn.com/signin",  # Not the real Cloudflare domain
        "https://checkout-paypal-secure.com/review",  # Multiple legitimate terms combined
        "https://my-appleid.cloud.com/manage",  # Combining brand with legitimate term
        "https://onedrive-sharepoint.com/files/document",  # Two Microsoft products combined
        
        # Legitimate with oauth tokens and many parameters (very complex)
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All",  # Microsoft OAuth
        "https://accounts.google.com/o/oauth2/v2/auth/identifier?client_id=717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com&scope=profile%20email&redirect_uri=https%3A%2F%2Fstackauth.com%2Fauth%2Foauth2%2Fgoogle&state=%7B%22sid%22%3A1%2C%22st%22%3A%2259%3A3%3Abbc%2C16%3A9fbf5998a53a6de2%2C10%3A1647695052%2C16%3A66ba0b7fb39c10da%2C106e44857549041e621c02f3436a836b46e65219da2d0b76e36d7423025f9fbd%22%2C%22cid%22%3A%22717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com%22%2C%22k%22%3A%22Google%22%2C%22ses%22%3A%22c6c564513fa648049c388a518e6cf938%22%7D&response_type=code&service=lso&o2v=2&flowName=GeneralOAuthFlow",  # Google OAuth with many parameters
        
        # Phishing - multi-method attack (combining multiple techniques)
        "https://signin.ebay-verify.secure-id.payment.update.com-tx.xyz/",  # Multiple subdomains with brands
        "https://security.google.auth.com.verification-support.online/account",  # Many security terms + brand
        
        # Legitimate but very unusual URL structures
        "https://for-the-badge.blink1073.repl.co/badges/releases/Netflix?repository=renovate",  # Custom service on replit
        "https://us-central1-visualism-dev.cloudfunctions.net/api/auth/callback/github",  # Google Cloud Function URL
        
        # Phishing that mimics URL shorteners or redirects
        "https://bit.ly.url-shortener-redirect.com/g00gl3",  # Fake URL shortener
        "https://rb.gy.click-confirmation.online/amzn-delivery",  # Fake shortened URL
        
        # Extremely deceptive phishing using Unicode character tricks
        "https://www.xn--pple-43d.com/signin",  # Punycode for apple with dots under 'a'
        "https://xn--gogle-0nf.com/mail",  # Punycode for google with accent 
    ]
    
    # Combine into test sets
    phishing_urls = sophisticated_phishing_urls + edge_case_urls[4:8] + edge_case_urls[12:14] + edge_case_urls[-2:]
    legitimate_urls = deceptive_legitimate_urls + edge_case_urls[0:4] + edge_case_urls[8:12] + edge_case_urls[14:16]
    
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
    
    # Test phishing URLs
    print("\nTesting sophisticated phishing URLs...")
    for url in phishing_urls:
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
    
    # Additional analysis - categorize errors
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