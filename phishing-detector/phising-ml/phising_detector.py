# 1. Setup: Install dependencies
# pip install kagglehub[pandas-datasets] scikit-learn pandas numpy joblib tldextract requests beautifulsoup4 xgboost imbalanced-learn

import kagglehub
from kagglehub import KaggleDatasetAdapter
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
from imblearn.over_sampling import SMOTE
import warnings
import joblib
from utils import extract_url_features
import os
import numpy as np

warnings.filterwarnings('ignore')

# --- Configuration ---
# Define filenames for the model and objects
model_filename = 'phishing_xgb_model.joblib'
scaler_filename = 'phishing_scaler.joblib'
imputer_filename = 'phishing_imputer.joblib'
features_filename = 'phishing_features.joblib'
extracted_features_csv = 'extracted_features.csv'  # New file to store extracted features

# 2. Load Data and Features
print("Loading dataset...")
file_path = "new_data_urls.csv"

# First check if we have pre-extracted features
if os.path.exists(extracted_features_csv):
    print("Loading pre-extracted features from CSV...")
    df_engineered = pd.read_csv(extracted_features_csv)
    print("Loaded features from", extracted_features_csv)
else:
    print("Extracting features from URLs (this may take a while)...")
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

    # Use the status column directly as our label since it's already correctly encoded
    # (0 for phishing, 1 for legitimate)
    df_engineered = pd.concat([url_features, df['status']], axis=1)
    df_engineered = df_engineered.rename(columns={'status': 'label'})
    
    # Save the extracted features to CSV
    print("Saving extracted features to", extracted_features_csv, "...")
    df_engineered.to_csv(extracted_features_csv, index=False)
    print("Features saved successfully!")

print("Features shape:", df_engineered.shape)
print("Columns:", df_engineered.columns.tolist())

# 4. Preprocessing
print("\n--- Preprocessing Features ---")

X_engineered = df_engineered.drop('label', axis=1)
y = df_engineered['label']

# Check class distribution
class_distribution = y.value_counts()
print("Class distribution:")
print(class_distribution)
print(f"Phishing (0): {class_distribution[0]}, Legitimate (1): {class_distribution[1]}")
print(f"Phishing percentage: {class_distribution[0]/len(y)*100:.2f}%")
print(f"Legitimate percentage: {class_distribution[1]/len(y)*100:.2f}%")

# Store the final list of feature names
feature_names_list = X_engineered.columns.tolist()
print("Features used for training (", len(feature_names_list), "):", feature_names_list)

# Handle missing values
imputer = SimpleImputer(strategy='median')
X_imputed = imputer.fit_transform(X_engineered)
X_imputed_df = pd.DataFrame(X_imputed, columns=feature_names_list)

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X_imputed_df, y, test_size=0.2, random_state=42, stratify=y
)
print("Training set shape: X_train=", X_train.shape, ", y_train=", y_train.shape)
print("Test set shape: X_test=", X_test.shape, ", y_test=", y_test.shape)

# Apply SMOTE to handle class imbalance
print("\n--- Applying SMOTE for Class Balancing ---")
smote = SMOTE(random_state=42)
X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
print("After SMOTE - Training set shape:", X_train_resampled.shape, y_train_resampled.shape)
print("Class distribution after SMOTE:", pd.Series(y_train_resampled).value_counts())

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_resampled)
X_test_scaled = scaler.transform(X_test)

X_train_scaled_df = pd.DataFrame(X_train_scaled, columns=feature_names_list)
X_test_scaled_df = pd.DataFrame(X_test_scaled, columns=feature_names_list)

# 5. Model Training with XGBoost
print("\n--- Training XGBoost Model ---")
xgb_clf = xgb.XGBClassifier(
    n_estimators=300,
    learning_rate=0.1,
    max_depth=6,
    min_child_weight=1,
    gamma=0,
    subsample=0.8,
    colsample_bytree=0.8,
    objective='binary:logistic',
    scale_pos_weight=1,
    random_state=42,
    eval_metric='logloss'
)

# Train the XGBoost model
xgb_clf.fit(
    X_train_scaled_df, 
    y_train_resampled,
    eval_set=[(X_test_scaled_df, y_test)],
    verbose=True
)

# Note: Early stopping can be implemented after training if needed
# Or by using XGBoost's native API instead of sklearn wrapper

# Get feature importance
print("\n--- Feature Importances ---")
feature_importance = xgb_clf.feature_importances_
feature_importance_df = pd.DataFrame({
    'Feature': feature_names_list,
    'Importance': feature_importance
})
feature_importance_df = feature_importance_df.sort_values(by='Importance', ascending=False)
print("Top 15 Most Important Features:")
print(feature_importance_df.head(15))

# 6. Evaluation
print("\n--- Model Evaluation ---")
# Get predictions
y_pred = xgb_clf.predict(X_test_scaled_df)
y_pred_proba = xgb_clf.predict_proba(X_test_scaled_df)[:, 1]

# Calculate metrics
accuracy = accuracy_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_pred_proba)
cm = confusion_matrix(y_test, y_pred)

# Print evaluation metrics
print(f"Accuracy: {accuracy:.4f}")
print(f"ROC AUC: {roc_auc:.4f}")
print("Confusion Matrix:")
print(cm)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Phishing', 'Legitimate']))

# Calculate threshold metrics
thresholds = np.arange(0.1, 1.0, 0.1)
print("\nThreshold Analysis:")
print("Threshold | Accuracy | Precision | Recall")
print("-" * 50)
for threshold in thresholds:
    y_pred_threshold = (y_pred_proba > threshold).astype(int)
    acc = accuracy_score(y_test, y_pred_threshold)
    report = classification_report(y_test, y_pred_threshold, output_dict=True)
    prec = report['1']['precision']  # Precision for legitimate class
    rec = report['1']['recall']      # Recall for legitimate class
    print(f"{threshold:.1f}      | {acc:.4f}   | {prec:.4f}    | {rec:.4f}")

# Save model and preprocessing objects
print("\n--- Saving Model and Preprocessing Objects ---")
joblib.dump(xgb_clf, model_filename)
joblib.dump(scaler, scaler_filename)
joblib.dump(imputer, imputer_filename)
joblib.dump(feature_names_list, features_filename)

print("\n--- Training Complete ---")