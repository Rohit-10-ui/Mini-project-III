from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from text_features import extract_text_features, get_feature_names
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

# Load the trained model
MODEL_PATH = "models/phishing_text_model.pkl"

try:
    model_artifact = joblib.load(MODEL_PATH)
    model = model_artifact['model']
    feature_names = model_artifact['features']
    model_type = model_artifact['model_type']
    model_accuracy = model_artifact['accuracy']
    print(f"✓ Loaded {model_type} model")
    print(f"  Accuracy: {model_accuracy:.4f}")
    print(f"  Features: {len(feature_names)}")
except Exception as e:
    raise RuntimeError(f"Could not load model: {e}")

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Email/SMS Phishing Detection API",
        "status": "online",
        "model": {
            "type": model_type,
            "features": len(feature_names),
            "accuracy": model_accuracy,
        }
    })

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(silent=True) or {}
        text = data.get("text", "")
        sender = data.get("sender", None)
        message_type = data.get("type", "unknown")

        if not text:
            return jsonify({"error": "No text provided"}), 400

        print(f"\n{'='*60}")
        print(f"Analyzing {message_type.upper()}")
        print(f"Text: {text[:100]}...")
        if sender:
            print(f"Sender: {sender}")
        print(f"{'='*60}")

        # Extract features
        features = extract_text_features(text, sender)
        
        # Create DataFrame
        X = pd.DataFrame([features], columns=feature_names)
        
        # Make prediction
        prediction = model.predict(X)[0]
        
        # Get probability if available
        confidence = None
        phishing_probability = None
        
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X)[0]
            confidence = round(float(max(proba)) * 100, 2)
            
            # Assuming class 1 is phishing
            if len(proba) > 1:
                phishing_probability = round(float(proba[1]) * 100, 2)
        
        result = "phishing" if prediction == 1 else "legitimate"
        
        # Create feature analysis
        feature_analysis = {}
        signals = []
        
        for fname, fval in zip(feature_names, features):
            feature_analysis[fname] = fval
            
            # Add to signals if suspicious (value = 1)
            if fval == 1:
                if fname == "num_urls":
                    signals.append("Multiple URLs detected")
                elif fname == "url_with_ip":
                    signals.append("URL contains IP address")
                elif fname == "has_shortened_url":
                    signals.append("Shortened URL detected")
                elif fname == "urgency_score":
                    signals.append("Urgent language detected")
                elif fname == "financial_score":
                    signals.append("Financial keywords detected")
                elif fname == "suspicious_score":
                    signals.append("Suspicious words (prize, lottery, etc.)")
                elif fname == "threat_score":
                    signals.append("Threatening language detected")
                elif fname == "excessive_punctuation":
                    signals.append("Excessive punctuation")
                elif fname == "all_caps_ratio":
                    signals.append("Excessive capitalization")
                elif fname == "spelling_quality":
                    signals.append("Poor spelling quality")
                elif fname == "sender_mismatch":
                    signals.append("Sender domain mismatch")
                elif fname == "has_phone_number":
                    signals.append("Contains phone number")
                elif fname == "requests_personal_info":
                    signals.append("Requests personal information")
                elif fname == "message_length":
                    signals.append("Unusual message length")
                elif fname == "suspicious_domain":
                    signals.append("Suspicious domain detected")
        
        print(f"\nPREDICTION: {result.upper()}")
        print(f"Confidence: {confidence}%")
        print(f"Phishing Probability: {phishing_probability}%")
        print(f"Signals: {len(signals)}")
        
        response = {
            "text": text[:200] + "..." if len(text) > 200 else text,
            "sender": sender,
            "type": message_type,
            "prediction": result,
            "confidence": confidence,
            "phishingProbability": phishing_probability,
            "signals": signals,
            "features": feature_analysis,
            "checkedAt": datetime.now().isoformat()
        }
        
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
            "type": model_type,
            "features": len(feature_names),
            "accuracy": model_accuracy
        },
        "timestamp": datetime.now().isoformat()
    })

@app.route("/features", methods=["GET"])
def list_features():
    return jsonify({
        "features": feature_names,
        "count": len(feature_names)
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5002"))
    debug = os.getenv("DEBUG", "true").lower() == "true"
    
    print("\n" + "="*60)
    print("EMAIL/SMS PHISHING DETECTION API")
    print("="*60)
    print(f"Model: {model_type}")
    print(f"Features: {len(feature_names)}")
    print(f"Accuracy: {model_accuracy:.2%}")
    print(f"Port: {port}")
    print("="*60 + "\n")
    
    app.run(debug=debug, host="0.0.0.0", port=port)
