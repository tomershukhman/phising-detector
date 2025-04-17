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

# Save the first 5 lines of the dataset to a CSV file
print("\nSaving first 5 lines of the dataset to CSV file...")
# Combine features and target for a complete dataset view
full_dataset = X.copy()
full_dataset['target'] = y
full_dataset.head(5).to_csv('dataset_sample.csv', index=False)
print("Sample dataset saved to 'dataset_sample.csv'")

# Select only specific features as requested
selected_feature_indices = [0, 1, 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 14, 15, 16, 17, 22, 23, 24, 25, 27, 29]
feature_names = X.columns
selected_feature_names = [feature_names[i] for i in selected_feature_indices]
X_selected = X.iloc[:, selected_feature_indices]

print(f"\nTraining on {len(selected_feature_indices)} selected features:")
print(f"Selected features: {selected_feature_names}")

# Split the data into training and testing sets using selected features
X_train, X_test, y_train, y_test = train_test_split(X_selected, y, test_size=0.3, random_state=42)

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
print(classification_report(y_test, y_pred, zero_division=0))

print("\nConfusion Matrix:")
conf_matrix = confusion_matrix(y_test, y_pred)
print(conf_matrix)

# Feature importances
feature_importances = rf_model.feature_importances_
sorted_idx = np.argsort(feature_importances)
feature_names = X_selected.columns

# Plot feature importances (all of them since we only use selected ones)
plt.figure(figsize=(12, 10))
plt.barh(range(len(feature_importances)), feature_importances[sorted_idx], align='center')
plt.yticks(range(len(feature_importances)), [feature_names[i] for i in sorted_idx])
plt.xlabel('Feature Importance')
plt.ylabel('Feature')
plt.title('Feature Importances for Phishing Detection (Selected Features)')
plt.tight_layout()
plt.savefig('feature_importances.png')
print("\nFeature importance plot saved as 'feature_importances.png'")

# Save the model
joblib.dump(rf_model, 'phishing_detector_model.pkl')
# Save the selected feature names along with the model
joblib.dump(selected_feature_names, 'selected_features.pkl')
print("\nModel saved as 'phishing_detector_model.pkl'")
print("Selected features saved as 'selected_features.pkl'")

# Test the prediction function on example URLs
print("\nTesting prediction function on example URLs:")
test_urls = [
    'https://www.google.com',  # should be legitimate
    'http://142.93.107.132/login.php'  # should be phishing (IP address)
]

for url in test_urls:
    try:
        # Extract only the features we need for our model - this is more efficient
        features = extract_features(url, features_to_extract=selected_feature_names)
        print(f"\nFeatures extracted from {url}:")
        for feature_name, feature_value in features.items():
            print(f"  {feature_name}: {feature_value}")
        
        # Use the centralized prediction function with the selected feature column names
        result = predict_url(url, rf_model, feature_columns=selected_feature_names)
        print(f"Model prediction: {result['prediction']}")
        
        # Confirm all required features were extracted
        missing_features = [col for col in selected_feature_names if col not in features]
        if missing_features:
            print("\nWarning: Some selected features were not extracted:")
            for col in missing_features:
                print(f"  ✗ {col} - MISSING!")
        else:
            print("\nAll required features were successfully extracted.")
                
    except Exception as e:
        print(f"Error analyzing {url}: {e}")

# Provide a CLI interface for user testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # If URL provided as command line argument
        url_to_check = sys.argv[1]
        result = predict_url(url_to_check, rf_model, feature_columns=selected_feature_names)
        print(f"\nURL: {url_to_check}")
        print(f"Prediction: {result['prediction']}")
