import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, classification_report
from utils import predict_phishing

# Define test URLs with their true labels
urls_data = [
    # Legitimate URLs (label=1)
    ('https://www.google.com', 1),
    ('https://github.com', 1),
    ('https://www.microsoft.com/en-us', 1),
    ('https://stackoverflow.com/questions', 1),
    ('https://www.amazon.com/dp/B08F7N9ZF4', 1),
    
    # Phishing URLs (label=0)
    ('http://googgle-secure-signin.com', 0),  # Typosquatting
    ('https://paypal-account-secure-login.com', 0),  # Brand + security words
    ('http://login-secure-bankofamerica.tk', 0),  # Suspicious TLD
    ('https://facebook.login-verify-account.net', 0),  # Brand in subdomain
    ('http://192.168.1.1/login.php', 0),  # IP address URL
    ('http://bit.ly/3xF9ke', 0),  # URL shortener
    ('https://secure-login123.com', 0),  # Numeric domain
    ('https://account-verify-signin.com/login', 0),  # Multiple security keywords
    ('http://bankofarnerica.com', 0),  # Character replacement
    ('https://www.paypal.com.secure-login.net', 0),  # Domain spoofing
    
    # Ambiguous URLs (actually legitimate, label=1)
    ('https://login.microsoftonline.com', 1),
    ('https://accounts.google.com', 1),
    ('https://www.bankofamerica.com/login', 1),
    ('https://github.com/login', 1),
    ('https://bit.ly/github', 1)
]

def evaluate_urls():
    # Create lists to store results
    results = []
    true_labels = []
    predicted_labels = []
    
    # Evaluate each URL
    for url, true_label in urls_data:
        prediction = predict_phishing(url)
        predicted_label = 0 if prediction['is_phishing'] else 1
        confidence = prediction['confidence']
            
        results.append({
            'URL': url,
            'True Label': 'Legitimate' if true_label == 1 else 'Phishing',
            'Predicted Label': 'Legitimate' if predicted_label == 1 else 'Phishing',
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
    print(f"Actual  Legitimate  {cm[1][1]:<10d} {cm[1][0]:<10d}")
    print(f"        Phishing    {cm[0][1]:<10d} {cm[0][0]:<10d}")
    
    # Display classification report
    print("\nClassification Report:")
    print("=" * 50)
    print(classification_report(true_labels, predicted_labels, 
                              target_names=['Phishing', 'Legitimate']))

if __name__ == '__main__':
    evaluate_urls()