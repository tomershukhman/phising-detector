# Import necessary libraries
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
import time
import warnings
warnings.filterwarnings('ignore')

# Download the dataset
import kagglehub
from kagglehub import KaggleDatasetAdapter

# Start timer to measure execution time
start_time = time.time()

print("Loading dataset...")
# Set the path to the file you'd like to load
file_path = "PhiUSIIL_Phishing_URL_Dataset.csv"

# Load the latest version
try:
    df = kagglehub.load_dataset(
      KaggleDatasetAdapter.PANDAS,
      "ndarvind/phiusiil-phishing-url-dataset",
      file_path
    )
    print("Dataset loaded successfully.")
    print(f"Shape of the dataset: {df.shape}")
    print("First 5 records:")
    print(df.head())
except Exception as e:
    print(f"Error loading dataset: {e}")
    exit(1)

# Data preprocessing
# Check for missing values
print("\nMissing values count:")
print(df.isnull().sum().sum())

# Check class distribution
print("\nClass distribution:")
print(df['label'].value_counts())
print(f"Percentage of phishing sites: {df['label'].mean()*100:.2f}%")

# Check for duplicate rows
duplicate_count = df.duplicated().sum()
print(f"\nNumber of duplicate rows: {duplicate_count}")
if duplicate_count > 0:
    print("Removing duplicates...")
    df = df.drop_duplicates()
    print(f"Dataset shape after removing duplicates: {df.shape}")

# Investigate potential data leakage
print("\nInvestigating suspicious features...")
print("\nChecking URLSimilarityIndex distribution:")
print(df.groupby('label')['URLSimilarityIndex'].describe())

# Let's check correlation between URLSimilarityIndex and the label
correlation = df['URLSimilarityIndex'].corr(df['label'])
print(f"\nCorrelation between URLSimilarityIndex and label: {correlation:.4f}")

# Check other high-correlation features
corrs = df.corr()['label'].abs().sort_values(ascending=False)
print("\nTop 10 features correlated with the label:")
print(corrs.head(10))

# Remove potentially problematic features
print("\nRemoving potentially problematic features...")
suspicious_features = ['URLSimilarityIndex', 'CharContinuationRate', 'URLTitleMatchScore', 'DomainTitleMatchScore']
safe_features = [col for col in df.columns if col not in suspicious_features + ['URL', 'Domain', 'TLD', 'Title', 'label']]
print(f"Removed features: {suspicious_features}")
print(f"Remaining features: {len(safe_features)}")

# Separate features and target variable
X = df[safe_features]
y = df['label']

# Check the number of features
print(f"\nNumber of features after removal: {X.shape[1]}")

# Split the data, ensuring no duplicates between train and test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
print(f"\nTraining set size: {X_train.shape}")
print(f"Testing set size: {X_test.shape}")

# Feature scaling
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Verify no data leakage by checking model performance with cross-validation
print("\nVerifying model robustness with cross-validation...")
cv_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
cv_scores = cross_val_score(cv_model, X_train_scaled, y_train, cv=StratifiedKFold(5), scoring='accuracy')
print(f"Cross-validation accuracy scores: {cv_scores}")
print(f"Mean CV accuracy: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")

# If CV scores are too high, we might still have data leakage
if cv_scores.mean() > 0.99:
    print("\nWARNING: Cross-validation accuracy is suspiciously high. There might still be data leakage.")
    print("Consider collecting a completely new test set for final evaluation.")

# Train the model on the full training set
print("\nTraining the final model...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf_model.fit(X_train_scaled, y_train)

# Find important features for the robust model
feature_importance = pd.DataFrame({
    'Feature': X.columns,
    'Importance': rf_model.feature_importances_
}).sort_values('Importance', ascending=False)

print("\nTop 15 important features from robust model:")
print(feature_importance.head(15))

# Select top N features for the lightweight model
top_n = 15
top_features = feature_importance.head(top_n)['Feature'].tolist()

print(f"\nSelected top {top_n} features for the lightweight model:")
for i, feature in enumerate(top_features, 1):
    print(f"{i}. {feature}")

# Create datasets with only the selected features
X_train_selected = X_train[top_features]
X_test_selected = X_test[top_features]

# Apply scaling to the selected features
scaler_selected = StandardScaler()
X_train_selected_scaled = scaler_selected.fit_transform(X_train_selected)
X_test_selected_scaled = scaler_selected.transform(X_test_selected)

print(f"\nReducing feature dimension from {X_train.shape[1]} to {len(top_features)}")

# Train the lightweight model
print("\nTraining the lightweight model with selected features...")
lightweight_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
lightweight_model.fit(X_train_selected_scaled, y_train)

# Make predictions on test set
y_pred = lightweight_model.predict(X_test_selected_scaled)
y_pred_proba = lightweight_model.predict_proba(X_test_selected_scaled)[:, 1]

# Evaluate the lightweight model
print("\n====== LIGHTWEIGHT MODEL PERFORMANCE ======")
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# Calculate detailed performance metrics
tn, fp, fn, tp = cm.ravel()
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
roc_auc = roc_auc_score(y_test, y_pred_proba)

print("\nDetailed Performance Metrics:")
print(f"True Positives: {tp}")
print(f"True Negatives: {tn}")
print(f"False Positives: {fp}")
print(f"False Negatives: {fn}")
print(f"Precision: {precision:.4f}")
print(f"Recall (Sensitivity): {recall:.4f}")
print(f"Specificity: {specificity:.4f}")
print(f"F1 Score: {f1:.4f}")
print(f"ROC AUC: {roc_auc:.4f}")

# Test model robustness by testing on different random subsets
print("\nTesting model robustness on different random subsets...")
robustness_scores = []

for i in range(5):
    # Create a random subset of the test data
    X_subset, _, y_subset, _ = train_test_split(X_test_selected, y_test, test_size=0.5, random_state=i)
    X_subset_scaled = scaler_selected.transform(X_subset)
    
    # Predict and calculate accuracy
    y_subset_pred = lightweight_model.predict(X_subset_scaled)
    subset_accuracy = accuracy_score(y_subset, y_subset_pred)
    robustness_scores.append(subset_accuracy)
    
    print(f"Subset {i+1} accuracy: {subset_accuracy:.4f}")

print(f"Mean robustness score: {np.mean(robustness_scores):.4f} (±{np.std(robustness_scores):.4f})")

# Check for adversarial examples - samples that are difficult to classify
print("\nChecking for adversarial examples...")
probs = lightweight_model.predict_proba(X_test_selected_scaled)
uncertainties = 1 - np.max(probs, axis=1)
uncertain_indices = np.argsort(uncertainties)[-10:]  # Top 10 most uncertain predictions

print("Top 10 most uncertain predictions:")
for idx in uncertain_indices:
    pred_class = np.argmax(probs[idx])
    actual_class = y_test.iloc[idx]
    print(f"Sample {idx}: Predicted class: {pred_class}, Actual class: {actual_class}, Confidence: {probs[idx][pred_class]:.4f}")

# Save the model
import joblib
joblib.dump(lightweight_model, 'robust_lightweight_phishing_model.pkl')
joblib.dump(scaler_selected, 'robust_feature_scaler.pkl')
joblib.dump(top_features, 'robust_selected_features.pkl')

# Function to predict with the lightweight model
def predict_phishing(url, html_content=None):
    """
    Predict if a URL is phishing based on selected features.
    
    Args:
        url (str): The URL to check
        html_content (str, optional): HTML content of the webpage if available
        
    Returns:
        bool: True if phishing, False if legitimate
        float: Probability of being a phishing site
    """
    # Extract features from URL and HTML
    features_dict = extract_features(url, html_content)
    
    # Select only the features used by the model
    selected_features = []
    for feature in top_features:
        selected_features.append(features_dict.get(feature, 0))
    
    # Scale the features
    scaled_features = scaler_selected.transform([selected_features])
    
    # Make prediction
    prediction = lightweight_model.predict(scaled_features)[0]
    probability = lightweight_model.predict_proba(scaled_features)[0][1]
    
    return bool(prediction), probability

def extract_features(url, html_content=None):
    """
    Extract features from URL and HTML content.
    
    Args:
        url (str): The URL to extract features from
        html_content (str, optional): HTML content of the webpage
        
    Returns:
        dict: Dictionary of features extracted from URL and HTML
    """
    # Placeholder implementation - this should be extended based on your feature definitions
    features = {}
    
    # Basic URL features
    features['URLLength'] = len(url)
    
    # Domain features
    domain = url.split('//')[-1].split('/')[0]
    features['DomainLength'] = len(domain)
    features['IsDomainIP'] = 1 if all(c.isdigit() or c == '.' for c in domain.split('.')) else 0
    
    # TLD features
    tld = domain.split('.')[-1] if '.' in domain else ''
    features['TLDLength'] = len(tld)
    
    # Character features
    features['NoOfLettersInURL'] = sum(c.isalpha() for c in url)
    features['LetterRatioInURL'] = features['NoOfLettersInURL'] / features['URLLength'] if features['URLLength'] > 0 else 0
    features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url)
    features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / features['URLLength'] if features['URLLength'] > 0 else 0
    features['NoOfOtherSpecialCharsInURL'] = sum(not c.isalnum() and not c.isspace() for c in url)
    features['SpacialCharRatioInURL'] = features['NoOfOtherSpecialCharsInURL'] / features['URLLength'] if features['URLLength'] > 0 else 0
    
    # Security indicators
    features['IsHTTPS'] = 1 if url.startswith('https://') else 0
    
    # HTML features - these would require actual HTML parsing in a real implementation
    if html_content:
        features['LineOfCode'] = html_content.count('\n') + 1
        features['LargestLineLength'] = max(len(line) for line in html_content.split('\n'))
        features['NoOfImage'] = html_content.lower().count('<img')
        features['NoOfCSS'] = html_content.lower().count('<style') + html_content.lower().count('<link')
        features['NoOfJS'] = html_content.lower().count('<script')
        features['HasCopyrightInfo'] = 1 if '©' in html_content or 'copyright' in html_content.lower() else 0
        features['HasDescription'] = 1 if '<meta name="description"' in html_content.lower() else 0
        features['HasSocialNet'] = 1 if any(sn in html_content.lower() for sn in ['facebook', 'twitter', 'instagram', 'linkedin']) else 0
    else:
        # Default values if HTML is not provided
        features['LineOfCode'] = 0
        features['LargestLineLength'] = 0
        features['NoOfImage'] = 0
        features['NoOfCSS'] = 0
        features['NoOfJS'] = 0
        features['HasCopyrightInfo'] = 0
        features['HasDescription'] = 0
        features['HasSocialNet'] = 0
    
    # Fill remaining features with zeros (in a real implementation these would be calculated properly)
    for feature in top_features:
        if feature not in features:
            features[feature] = 0
    
    return features

# Calculate execution time
end_time = time.time()
execution_time = end_time - start_time

# Display summary
print("\n====== SUMMARY ======")
print(f"Total dataset size: {df.shape[0]} URLs")
print(f"Original features: {len(safe_features)}")
print(f"Selected features: {len(top_features)}")
print(f"Feature reduction: {100 - (len(top_features)/len(safe_features))*100:.2f}%")
print(f"Training samples: {X_train.shape[0]}")
print(f"Testing samples: {X_test.shape[0]}")
print(f"Model: Random Forest (n_estimators=100)")
print(f"Accuracy: {accuracy:.4f}")
print(f"F1 Score: {f1:.4f}")
print(f"ROC AUC: {roc_auc:.4f}")
print(f"Cross-validation mean accuracy: {cv_scores.mean():.4f}")
print(f"Execution time: {execution_time:.2f} seconds")
print("=====================")