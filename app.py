from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from features import extract_features
from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv
import warnings

warnings.filterwarnings("ignore")
load_dotenv()

MODEL_PATH = os.getenv("MODEL_PATH", "models/phishing_model_optimized.pkl")

DISCRIMINATIVE_FEATURES = [
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

model = None
FEATURE_NAMES = DISCRIMINATIVE_FEATURES
MODEL_TYPE = "Unknown"
MODEL_ACCURACY = None

def load_model(path):
    artifact = joblib.load(path)
    
    if isinstance(artifact, dict):
        m = artifact.get("model")
        features = artifact.get("features", DISCRIMINATIVE_FEATURES)
        model_type = artifact.get("model_type", "Unknown")
        accuracy = artifact.get("accuracy", None)
        return m, features, model_type, accuracy
    else:
        return artifact, DISCRIMINATIVE_FEATURES, "Unknown", None

try:
    model, FEATURE_NAMES, MODEL_TYPE, MODEL_ACCURACY = load_model(MODEL_PATH)
    print(f"✓ Loaded {MODEL_TYPE} model with {len(FEATURE_NAMES)} features")
    if MODEL_ACCURACY:
        print(f"  Accuracy: {MODEL_ACCURACY:.4f}")
except Exception as e:
    raise RuntimeError(f"Could not load model: {e}")

app = Flask(__name__)
CORS(app)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")

try:
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client["mydb"]
    url_checks = db["urlchecks"]
    mongodb_connected = True
    print("✓ MongoDB connected")
except Exception as e:
    print(f"⚠️  MongoDB not available: {e}")
    mongodb_connected = False

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Phishing Detection API",
        "status": "online",
        "model": {
            "type": MODEL_TYPE,
            "features": len(FEATURE_NAMES),
            "accuracy": MODEL_ACCURACY,
        },
        "database": "connected" if mongodb_connected else "disconnected",
    })

@app.route("/stats", methods=["GET"])
def stats():
    if not mongodb_connected:
        return jsonify({"error": "Database not connected"}), 503
    
    try:
        total = url_checks.count_documents({})
        phishing = url_checks.count_documents({"prediction": "phishing"})
        legitimate = url_checks.count_documents({"prediction": "legitimate"})
        
        from datetime import timedelta
        yesterday = datetime.now() - timedelta(days=1)
        recent = url_checks.count_documents({"checkedAt": {"$gte": yesterday}})
        
        return jsonify({
            "total_checks": total,
            "phishing_detected": phishing,
            "legitimate": legitimate,
            "recent_24h": recent,
            "phishing_rate": round(phishing / total * 100, 2) if total > 0 else 0
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(silent=True) or {}
        url = data.get("url")
        user_id = data.get("user", "anonymous")

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        print(f"\n{'='*60}")
        print(f"Analyzing: {url}")
        print(f"{'='*60}")

        features_list = extract_features(url)

        if not isinstance(features_list, (list, tuple)):
            return jsonify({"error": "Feature extraction failed"}), 500
        
        if len(features_list) != len(FEATURE_NAMES):
            return jsonify({
                "error": "Feature length mismatch",
                "expected": len(FEATURE_NAMES),
                "got": len(features_list)
            }), 500

        # Show extracted features
        print(f"\n{'='*60}")
        print("EXTRACTED FEATURES:")
        print(f"{'='*60}")
        for fname, fval in zip(FEATURE_NAMES, features_list):
            indicator = "🚨 SUSPICIOUS" if fval == 1 else "✓ OK" if fval == -1 else "⚠️  NEUTRAL"
            print(f"{fname:30s} = {fval:2d}  {indicator}")
        print(f"{'='*60}\n")

        features_df = pd.DataFrame([features_list], columns=FEATURE_NAMES)
        prediction = model.predict(features_df)[0]
        
        # Rule-based override for obvious phishing patterns
        suspicious_count = sum(1 for f in features_list if f == 1)
        
        # Override 1: Very young domain (< 7 days) with multiple red flags
        age_of_domain_idx = FEATURE_NAMES.index('age_of_domain') if 'age_of_domain' in FEATURE_NAMES else -1
        if age_of_domain_idx != -1 and features_list[age_of_domain_idx] == 1 and suspicious_count >= 4:
            prediction = 1
            print("⚠️  OVERRIDE: Very young domain with multiple suspicious features")
        
        # Override 2: 100% external resources with young domain
        request_url_idx = FEATURE_NAMES.index('Request_URL') if 'Request_URL' in FEATURE_NAMES else -1
        url_anchor_idx = FEATURE_NAMES.index('URL_of_Anchor') if 'URL_of_Anchor' in FEATURE_NAMES else -1
        if (request_url_idx != -1 and features_list[request_url_idx] == 1 and
            url_anchor_idx != -1 and features_list[url_anchor_idx] == 1 and
            age_of_domain_idx != -1 and features_list[age_of_domain_idx] == 1):
            prediction = 1
            print("⚠️  OVERRIDE: All external resources + suspicious anchors + young domain")
        
        result = "phishing" if prediction == 1 else "legitimate"

        confidence = None
        phishing_probability = None
        
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(features_df)[0]
            classes = list(getattr(model, "classes_", []))
            
            if classes:
                try:
                    pred_idx = classes.index(prediction)
                    confidence = round(float(proba[pred_idx]) * 100, 2)
                except ValueError:
                    confidence = round(float(max(proba)) * 100, 2)
                
                if 1 in classes:
                    phishing_probability = round(float(proba[classes.index(1)]) * 100, 2)
            else:
                confidence = round(float(max(proba)) * 100, 2)

        signals = [FEATURE_NAMES[i] for i, v in enumerate(features_list) if v == 1]

        print(f"\nPREDICTION: {result.upper()}")
        print(f"Confidence: {confidence}%")
        print(f"Phishing Probability: {phishing_probability}%")
        print(f"Suspicious Signals: {signals}\n")

        response = {
            "url": url,
            "prediction": result,
            "confidence": confidence,
            "phishingProbability": phishing_probability,
            "signals": signals,
            "features": dict(zip(FEATURE_NAMES, features_list)),
            "checkedAt": datetime.now().isoformat(),
            "user": str(user_id)
        }

        if mongodb_connected:
            try:
                db_entry = {
                    "url": url,
                    "prediction": result,
                    "confidence": confidence,
                    "phishingProbability": phishing_probability,
                    "signals": signals,
                    "features": dict(zip(FEATURE_NAMES, features_list)),
                    "checkedAt": datetime.now(),
                    "user": str(user_id)
                }
                url_checks.insert_one(db_entry)
            except Exception:
                pass

        return jsonify(response)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "model": {
            "loaded": model is not None,
            "type": MODEL_TYPE,
            "features": len(FEATURE_NAMES),
            "accuracy": MODEL_ACCURACY
        },
        "database": mongodb_connected,
        "timestamp": datetime.now().isoformat()
    })

@app.route("/features", methods=["GET"])
def list_features():
    return jsonify({
        "features": FEATURE_NAMES,
        "count": len(FEATURE_NAMES)
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    
    print("\n" + "="*60)
    print("PHISHING DETECTION API")
    print("="*60)
    print(f"Model: {MODEL_TYPE}")
    print(f"Features: {len(FEATURE_NAMES)}")
    if MODEL_ACCURACY:
        print(f"Accuracy: {MODEL_ACCURACY:.2%}")
    print(f"Database: {'✓ Connected' if mongodb_connected else '✗ Not connected'}")
    print("="*60 + "\n")
    
    app.run(debug=False, host="0.0.0.0", port=port)