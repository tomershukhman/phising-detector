import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, classification_report
from utils import predict_phishing

# Define test URLs with their true labels
urls_data = [
    # Legitimate URLs
    ('https://www.google.com', 0),
    ('https://github.com', 0),
    ('https://www.microsoft.com/en-us', 0),
    ('https://stackoverflow.com/questions', 0),
    ('https://www.amazon.com/dp/B08F7N9ZF4', 0),
    
    # Phishing URLs
    ('http://googgle-secure-signin.com', 1),  # Typosquatting
    ('https://paypal-account-secure-login.com', 1),  # Brand + security words
    ('http://login-secure-bankofamerica.tk', 1),  # Suspicious TLD
    ('https://facebook.login-verify-account.net', 1),  # Brand in subdomain
    ('http://192.168.1.1/login.php', 1),  # IP address URL
    ('http://bit.ly/3xF9ke', 1),  # URL shortener
    ('https://secure-login123.com', 1),  # Numeric domain
    ('https://account-verify-signin.com/login', 1),  # Multiple security keywords
    ('http://bankofarnerica.com', 1),  # Character replacement
    ('https://www.paypal.com.secure-login.net', 1),  # Domain spoofing
    
    # Ambiguous URLs (actually legitimate)
    ('https://login.microsoftonline.com', 0),
    ('https://accounts.google.com', 0),
    ('https://www.bankofamerica.com/login', 0),
    ('https://github.com/login', 0),
    ('https://bit.ly/github', 0)
]

def evaluate_urls():
    # Create lists to store results
    results = []
    true_labels = []
    predicted_labels = []
    
    # Evaluate each URL
    for url, true_label in urls_data:
        prediction = predict_phishing(url)
        if prediction:
            predicted_label = 1 if prediction['is_phishing'] else 0
            confidence = prediction['confidence']
        else:
            predicted_label = 1  # Assume suspicious if prediction fails
            confidence = 1.0
            
        results.append({
            'URL': url,
            'True Label': 'Phishing' if true_label == 1 else 'Legitimate',
            'Predicted Label': 'Phishing' if predicted_label == 1 else 'Legitimate',
            'Confidence': confidence
        })
        true_labels.append(true_label)
        predicted_labels.append(predicted_label)
    
    # Create DataFrame
    df = pd.DataFrame(results)
    print("\nURL Evaluation Results:")
    print("=" * 100)
    print(df.to_string(index=False))
    
    # Calculate and display confusion matrix
    cm = confusion_matrix(true_labels, predicted_labels)
    print("\nConfusion Matrix:")
    print("=" * 50)
    print("              Predicted")
    print("              Legitimate  Phishing")
    print(f"Actual  Legitimate  {cm[0][0]:<10d} {cm[0][1]:<10d}")
    print(f"        Phishing    {cm[1][0]:<10d} {cm[1][1]:<10d}")
    
    # Display classification report
    print("\nClassification Report:")
    print("=" * 50)
    print(classification_report(true_labels, predicted_labels, 
                              target_names=['Legitimate', 'Phishing']))

if __name__ == '__main__':
    evaluate_urls()