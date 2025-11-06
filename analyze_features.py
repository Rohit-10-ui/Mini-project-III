import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import numpy as np

# Load dataset
data = pd.read_csv("datasets/Phishing_Websites_Data.csv")

# Current features being used
current_features = [
    "having_IP_Address",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "age_of_domain",
    "DNSRecord",
]

# All available features (excluding Result)
all_features = list(data.columns[:-1])

# Features NOT currently used
unused_features = [f for f in all_features if f not in current_features]

print("="*70)
print("FEATURE ANALYSIS FOR PHISHING DETECTION")
print("="*70)
print(f"\nCurrently using: {len(current_features)} features")
print(f"Available unused: {len(unused_features)} features")
print(f"\nUnused features:\n{unused_features}")

# Train model with ALL features to see importance
X_all = data[all_features].apply(pd.to_numeric, errors="coerce").fillna(0)
y = pd.to_numeric(data["Result"], errors="coerce")

X_train, X_test, y_train, y_test = train_test_split(
    X_all, y, test_size=0.2, random_state=42, stratify=y
)

# Train RandomForest with all features
rf_all = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
rf_all.fit(X_train, y_train)

# Get feature importances
feature_importance = pd.DataFrame({
    'feature': all_features,
    'importance': rf_all.feature_importances_
}).sort_values('importance', ascending=False)

print("\n" + "="*70)
print("TOP 20 MOST IMPORTANT FEATURES")
print("="*70)
print(feature_importance.head(20).to_string(index=False))

print("\n" + "="*70)
print("TOP 10 UNUSED FEATURES (RECOMMENDED TO ADD)")
print("="*70)
unused_importance = feature_importance[feature_importance['feature'].isin(unused_features)]
print(unused_importance.head(10).to_string(index=False))

print("\n" + "="*70)
print("CURRENT FEATURES RANKING")
print("="*70)
current_importance = feature_importance[feature_importance['feature'].isin(current_features)]
print(current_importance.to_string(index=False))

# Test accuracy with current vs all features
rf_current = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
X_current = data[current_features].apply(pd.to_numeric, errors="coerce").fillna(0)
X_train_curr, X_test_curr, y_train_curr, y_test_curr = train_test_split(
    X_current, y, test_size=0.2, random_state=42, stratify=y
)
rf_current.fit(X_train_curr, y_train_curr)

print("\n" + "="*70)
print("ACCURACY COMPARISON")
print("="*70)
print(f"Current model ({len(current_features)} features): {rf_current.score(X_test_curr, y_test_curr):.4f}")
print(f"All features ({len(all_features)} features):    {rf_all.score(X_test, y_test):.4f}")
print("="*70)
