"""
Test script to verify the improved phishing detection model
"""
import sys
from features import extract_features
import joblib
import pandas as pd

print("="*70)
print("TESTING IMPROVED PHISHING DETECTION MODEL")
print("="*70)

# Load the model
try:
    artifact = joblib.load("models/phishing_model_optimized.pkl")
    model = artifact['model']
    features_list = artifact['features']
    model_type = artifact['model_type']
    accuracy = artifact['accuracy']
    
    print(f"\n✓ Model loaded successfully")
    print(f"  Type: {model_type}")
    print(f"  Features: {len(features_list)}")
    print(f"  Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"\n  Feature list:")
    for i, f in enumerate(features_list, 1):
        print(f"    {i:2d}. {f}")
    
except Exception as e:
    print(f"\n✗ Error loading model: {e}")
    sys.exit(1)

# Test URLs
test_urls = [
    ("https://www.google.com", "legitimate"),
    ("https://www.microsoft.com", "legitimate"),
    ("https://github.com", "legitimate"),
    ("http://125.98.3.123/fake.html", "phishing"),  # IP address
    ("https://paypal-security-update.com-login.tk", "phishing"),  # Fake PayPal
    ("http://www.amazon-account-verify.net", "phishing"),  # Fake Amazon
]

print("\n" + "="*70)
print("TESTING ON SAMPLE URLs")
print("="*70)

correct = 0
total = len(test_urls)

for url, expected in test_urls:
    print(f"\n{'='*70}")
    print(f"Testing: {url}")
    print(f"Expected: {expected.upper()}")
    print(f"{'='*70}")
    
    try:
        # Extract features
        features = extract_features(url)
        
        print(f"\n✓ Extracted {len(features)} features")
        
        # Verify feature count
        if len(features) != len(features_list):
            print(f"\n✗ ERROR: Feature count mismatch!")
            print(f"  Expected: {len(features_list)}")
            print(f"  Got: {len(features)}")
            continue
        
        # Make prediction
        features_df = pd.DataFrame([features], columns=features_list)
        prediction = model.predict(features_df)[0]
        result = "phishing" if prediction == 1 else "legitimate"
        
        # Get confidence if available
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(features_df)[0]
            confidence = max(proba) * 100
            print(f"  Confidence: {confidence:.2f}%")
        
        # Check if correct
        is_correct = (result == expected)
        if is_correct:
            correct += 1
            print(f"\n✓ CORRECT: Predicted {result.upper()}")
        else:
            print(f"\n✗ WRONG: Predicted {result.upper()} but expected {expected.upper()}")
        
    except Exception as e:
        print(f"\n✗ Error testing URL: {e}")
        import traceback
        traceback.print_exc()

print("\n" + "="*70)
print("TEST SUMMARY")
print("="*70)
print(f"Correct predictions: {correct}/{total} ({correct/total*100:.1f}%)")
print("="*70)

if correct == total:
    print("\n🎉 ALL TESTS PASSED! Model is working correctly.")
else:
    print(f"\n⚠️  {total-correct} test(s) failed. Review the results above.")
