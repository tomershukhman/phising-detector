import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc
import matplotlib.pyplot as plt
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
    legitimate_probs = []
    
    # Evaluate each URL
    for url, true_label in urls_data:
        prediction = predict_phishing(url)
        predicted_label = prediction['prediction']
        confidence = prediction['confidence']
        probs = prediction.get('probabilities', {})
        phishing_prob = probs.get('phishing', 0)
        legitimate_prob = probs.get('legitimate', 0)
            
        results.append({
            'URL': url,
            'True Label': 'Legitimate' if true_label == 1 else 'Phishing',
            'Predicted Label': 'Legitimate' if predicted_label == 1 else 'Phishing',
            'Confidence': confidence,
            'Phishing Prob': phishing_prob,
            'Legitimate Prob': legitimate_prob
        })
        true_labels.append(true_label)
        predicted_labels.append(predicted_label)
        legitimate_probs.append(legitimate_prob)
    
    # Create DataFrame
    df = pd.DataFrame(results)
    
    # Print URL evaluation results
    pd.set_option('display.max_colwidth', 100)
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
                              target_names=['Phishing', 'Legitimate'],
                              zero_division=0))
    
    # Calculate accuracy
    accuracy = (cm[0][0] + cm[1][1]) / (cm[0][0] + cm[1][1] + cm[0][1] + cm[1][0])
    print(f"Overall Accuracy: {accuracy:.4f}")
    
    # Calculate accuracy for each class
    legitimate_acc = cm[1][1] / (cm[1][0] + cm[1][1]) if (cm[1][0] + cm[1][1]) > 0 else 0
    phishing_acc = cm[0][0] / (cm[0][0] + cm[0][1]) if (cm[0][0] + cm[0][1]) > 0 else 0
    
    print(f"Legitimate URL Detection Accuracy: {legitimate_acc:.4f}")
    print(f"Phishing URL Detection Accuracy: {phishing_acc:.4f}")
    
    # Calculate ROC curve if possible
    try:
        fpr, tpr, _ = roc_curve(true_labels, legitimate_probs)
        roc_auc = auc(fpr, tpr)
        print(f"ROC AUC: {roc_auc:.4f}")
        
        # Try to plot ROC curve
        plt.figure()
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic')
        plt.legend(loc="lower right")
        try:
            plt.savefig('roc_curve.png')
            print("ROC curve saved as 'roc_curve.png'")
        except Exception as e:
            print(f"Could not save ROC curve: {e}")
    except Exception as e:
        print(f"Could not calculate ROC curve: {e}")
    
    # Try different thresholds for prediction
    print("\nThreshold Analysis:")
    print("Threshold | Accuracy | Precision | Recall")
    print("-" * 50)
    for threshold in np.arange(0.1, 1.0, 0.1):
        y_pred_threshold = [1 if p >= threshold else 0 for p in legitimate_probs]
        cm_t = confusion_matrix(true_labels, y_pred_threshold)
        acc_t = (cm_t[0][0] + cm_t[1][1]) / (cm_t[0][0] + cm_t[1][1] + cm_t[0][1] + cm_t[1][0])
        
        # Calculate precision and recall for legitimate class
        if cm_t[1][1] + cm_t[0][1] > 0:
            precision = cm_t[1][1] / (cm_t[1][1] + cm_t[0][1])
        else:
            precision = 0
            
        if cm_t[1][1] + cm_t[1][0] > 0:
            recall = cm_t[1][1] / (cm_t[1][1] + cm_t[1][0])
        else:
            recall = 0
            
        print(f"{threshold:.1f}      | {acc_t:.4f}   | {precision:.4f}    | {recall:.4f}")

if __name__ == '__main__':
    evaluate_urls()