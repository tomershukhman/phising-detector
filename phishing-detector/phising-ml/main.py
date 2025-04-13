import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import joblib
from ucimlrepo import fetch_ucirepo

# Import our feature extraction utilities
from features_extraction import predict_url, extract_features

print("Phishing Detection using Random Forest Classifier")
print("------------------------------------------------")

# Fetch dataset from UCI repository
print("Fetching UCI Phishing Websites dataset...")
phishing_websites = fetch_ucirepo(id=327) 
  
# Data (as pandas dataframes) 
X = phishing_websites.data.features 
y = phishing_websites.data.targets 

# Print basic dataset information
print("\nPhishing Website Dataset Information:")
print(f"Total instances: {len(X)}")
print(f"Features: {len(X.columns)}")
print(f"Feature names: {list(X.columns)}")
print("\nTarget distribution:")
print(y.value_counts())

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

print(f"\nTraining set shape: {X_train.shape}")
print(f"Testing set shape: {X_test.shape}")

# Create and train Random Forest model
print("\nTraining Random Forest classifier...")
rf_model = RandomForestClassifier(
    n_estimators=100, 
    max_depth=None,
    min_samples_split=2,
    random_state=42,
    n_jobs=-1
)

rf_model.fit(X_train, y_train.values.ravel())

# Evaluate model
y_pred = rf_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\nModel accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
conf_matrix = confusion_matrix(y_test, y_pred)
print(conf_matrix)

# Feature importances
feature_importances = rf_model.feature_importances_
sorted_idx = np.argsort(feature_importances)
feature_names = X.columns

# Plot top 15 feature importances (to make it more readable)
plt.figure(figsize=(12, 10))
plt.barh(range(15), feature_importances[sorted_idx[-15:]], align='center')
plt.yticks(range(15), [feature_names[i] for i in sorted_idx[-15:]])
plt.xlabel('Feature Importance')
plt.ylabel('Feature')
plt.title('Top 15 Features for Phishing Detection')
plt.tight_layout()
plt.savefig('feature_importances.png')
print("\nFeature importance plot saved as 'feature_importances.png'")

# Save the model
joblib.dump(rf_model, 'phishing_detector_model.pkl')
print("\nModel saved as 'phishing_detector_model.pkl'")

# Test the prediction function on example URLs
print("\nTesting prediction function on example URLs:")
test_urls = [
    'https://www.google.com',  # should be legitimate
    'http://142.93.107.132/login.php'  # should be phishing (IP address)
]

for url in test_urls:
    try:
        # Let's first print the extracted features to debug
        features = extract_features(url)
        print(f"\nFeatures extracted from {url}:")
        for feature_name, feature_value in features.items():
            print(f"  {feature_name}: {feature_value}")
        
        # Use the centralized prediction function with feature column names
        result = predict_url(url, rf_model, feature_columns=X.columns)
        print(f"Model prediction: {result['prediction']}")
        
        # Confirm the dataset's feature names match our extraction
        print("\nFeature names in dataset vs. our extraction:")
        for col in X.columns:
            if col in features:
                print(f"  ✓ {col}")
            else:
                print(f"  ✗ {col} - MISSING!")
                
    except Exception as e:
        print(f"Error analyzing {url}: {e}")

# Provide a CLI interface for user testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # If URL provided as command line argument
        url_to_check = sys.argv[1]
        result = predict_url(url_to_check, rf_model, feature_columns=X.columns)
        print(f"\nURL: {url_to_check}")
        print(f"Prediction: {result['prediction']}")
