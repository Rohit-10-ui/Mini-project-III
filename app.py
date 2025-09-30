from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from features import extract_features
from pymongo import MongoClient
from datetime import datetime

model = joblib.load("models/phishing_model.pkl")

app = Flask(__name__)
CORS(app)

try:
    client = MongoClient("mongodb://localhost:27017/")
    db = client["mydb"]
    url_checks = db["urlchecks"]
    mongodb_connected = True
    print("MongoDB connected")
except Exception as e:
    print(f"MongoDB error: {e}")
    mongodb_connected = False

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Phishing Detection API", "status": "online"})

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        url = data.get("url")
        user_id = data.get("user", "anonymous")

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        print(f"🔍 Analyzing: {url}")

        features_list = extract_features(url)
        
        feature_names = [
            'having_IP_Address', 'having_At_Symbol', 'URL_Length',
            'double_slash_redirecting', 'HTTPS_token', 'Shortining_Service',
            'Prefix_Suffix', 'having_Sub_Domain'
        ]
        
        features_df = pd.DataFrame([features_list], columns=feature_names)

        prediction = model.predict(features_df)[0]
        proba = model.predict_proba(features_df)[0]

        result = "phishing" if prediction == 1 else "legitimate"
        confidence = round(max(proba) * 100, 2)

        print(f"Result: {result} ({confidence}%)")

        response = {
            "url": url,
            "prediction": result,
            "confidence": confidence,
            "checkedAt": datetime.now().isoformat(),
            "user": str(user_id)
        }

        if mongodb_connected:
            try:
                db_entry = {
                    "url": url,
                    "prediction": result,
                    "confidence": confidence,
                    "checkedAt": datetime.now(),
                    "user": str(user_id)
                }
                url_checks.insert_one(db_entry)
                print("Saved to DB")
            except Exception as e:
                print(f"DB save failed: {e}")

        return jsonify(response)

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("Starting Flask API on port 5000...")
    app.run(debug=True, host='0.0.0.0', port=5000)