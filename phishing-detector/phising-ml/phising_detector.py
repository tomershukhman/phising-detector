# 1. Setup: Install dependencies
# pip install kagglehub[pandas-datasets] scikit-learn pandas numpy joblib tldextract requests beautifulsoup4

import kagglehub
from kagglehub import KaggleDatasetAdapter
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
import joblib
from utils import extract_url_features, extract_html_features

warnings.filterwarnings('ignore')

# --- Configuration ---
# Define filenames for the NEWLY ENGINEERED model and objects
model_filename = 'phishing_rf_model_engineered.joblib'
scaler_filename = 'phishing_scaler_engineered.joblib'
imputer_filename = 'phishing_imputer_engineered.joblib'
features_filename = 'phishing_features_engineered.joblib'

# 2. Load Data
print("Loading dataset...")
file_path = "new_data_urls.csv"

df = kagglehub.load_dataset(
  KaggleDatasetAdapter.PANDAS,
  "harisudhan411/phishing-and-legitimate-urls",
  file_path
)

print("First 5 records:", df.head())

# 3. Feature Engineering
print("\n--- Engineering Features from URLs ---")
# Apply the feature extraction functions to each URL
url_features = df['url'].apply(extract_url_features)


# Combine all features with the label
df_engineered = pd.concat([url_features, df['status']], axis=1)
print(f"Engineered features created. Shape: {df_engineered.shape}")
print(f"Columns: {df_engineered.columns.tolist()}")

# 4. Preprocessing
print("\n--- Preprocessing Features ---")

X_engineered = df_engineered.drop('status', axis=1)
y = df_engineered['status']

# Store the final list of feature names
feature_names_list = X_engineered.columns.tolist()
print(f"Features used for training ({len(feature_names_list)}): {feature_names_list}")

# Handle missing values
imputer = SimpleImputer(strategy='median')
X_imputed = imputer.fit_transform(X_engineered)
X_imputed_df = pd.DataFrame(X_imputed, columns=feature_names_list)

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X_imputed_df, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Training set shape: X_train={X_train.shape}, y_train={y_train.shape}")
print(f"Test set shape: X_test={X_test.shape}, y_test={y_test.shape}")

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

X_train_scaled_df = pd.DataFrame(X_train_scaled, columns=feature_names_list)
X_test_scaled_df = pd.DataFrame(X_test_scaled, columns=feature_names_list)

# 5. Model Training
print("\n--- Training Model ---")
rf_clf = RandomForestClassifier(
    n_estimators=200,  # Increased number of trees
    max_depth=15,      # Slightly deeper trees
    min_samples_split=5,
    min_samples_leaf=3,
    class_weight='balanced_subsample',  # Changed to balanced_subsample for better handling
    random_state=42,
    n_jobs=-1
)

rf_clf.fit(X_train_scaled_df, y_train)

# After training, get feature importances and adjust prediction threshold
importances = rf_clf.feature_importances_
feature_importance_df = pd.DataFrame({
    'Feature': feature_names_list,
    'Importance': importances
})
feature_importance_df = feature_importance_df.sort_values(by='Importance', ascending=False)
print("\nTop 15 Most Important Features:")
print(feature_importance_df.head(15))

# Calibrate prediction threshold on validation set
val_probs = rf_clf.predict_proba(X_test_scaled_df)
optimal_threshold = 0.6  # Start with a higher threshold to reduce false positives
y_pred_rf = (val_probs[:, 1] >= optimal_threshold).astype(int)

print("\nModel Evaluation with Adjusted Threshold:")
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_rf))
print("\nClassification Report:\n", classification_report(y_test, y_pred_rf, target_names=['Legitimate (0)', 'Phishing (1)']))

# 6. Evaluation
print("\n--- Model Evaluation ---")
y_pred_rf = rf_clf.predict(X_test_scaled_df)
print("Accuracy:", accuracy_score(y_test, y_pred_rf))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_rf))
print("Classification Report:\n", classification_report(y_test, y_pred_rf, target_names=['Legitimate (0)', 'Phishing (1)']))

# Feature Importances
print("\n--- Feature Importances (Top 15) ---")
importances = rf_clf.feature_importances_
feature_importance_df = pd.DataFrame({'Feature': feature_names_list, 'Importance': importances})
feature_importance_df = feature_importance_df.sort_values(by='Importance', ascending=False)
print(feature_importance_df.head(15))

# Save model and preprocessing objects
print(f"\n--- Saving Model and Preprocessing Objects ---")
joblib.dump(rf_clf, model_filename)
joblib.dump(scaler, scaler_filename)
joblib.dump(imputer, imputer_filename)
joblib.dump(feature_names_list, features_filename)

print("\n--- Training Complete ---")