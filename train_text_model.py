import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from joblib import dump

os.makedirs("models", exist_ok=True)

data = pd.read_csv("datasets/Phishing_Email_SMS_Data.csv")

discriminative_features = [
    "num_urls",
    "url_with_ip",
    "has_shortened_url",
    "urgency_score",
    "financial_score",
    "suspicious_score",
    "threat_score",
    "excessive_punctuation",
    "all_caps_ratio",
    "spelling_quality",
    "sender_mismatch",
    "has_phone_number",
    "requests_personal_info",
    "message_length",
    "suspicious_domain",
]

X = data[discriminative_features].apply(pd.to_numeric, errors="coerce").fillna(0)
y = pd.to_numeric(data["label"], errors="coerce")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=500,
    max_depth=15,
    min_samples_split=10,
    min_samples_leaf=4,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)
accuracy = model.score(X_test, y_test)

model_artifact = {
    "model": model,
    "features": discriminative_features,
    "model_type": "RandomForest",
    "accuracy": accuracy,
}

dump(model_artifact, "models/phishing_text_model.pkl")

print(f"Model trained: {accuracy:.4f} accuracy")
