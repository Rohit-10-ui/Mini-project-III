import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from joblib import dump
import os

os.makedirs("models", exist_ok=True)

data = pd.read_csv("datasets/Phishing_Websites_Data.csv")

selected_features = [
    'having_IP_Address',
    'having_At_Symbol',
    'URL_Length',
    'double_slash_redirecting',
    'HTTPS_token',
    'Shortining_Service',
    'Prefix_Suffix',
    'having_Sub_Domain'
]

X = data[selected_features]
y = data["Result"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

dump(model, "models/phishing_model.pkl")
print(f"Model trained with {len(selected_features)} features!")
print(f"Features: {selected_features}")