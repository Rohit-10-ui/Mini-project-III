"""Quick test to verify GitHub is identified correctly"""
import requests
import json

# Test the API
url = "http://localhost:7000/predict"
test_url = "https://www.github.com"

print(f"Testing: {test_url}")
print("="*60)

response = requests.post(url, json={"url": test_url})
data = response.json()

print(f"\nPrediction: {data['prediction'].upper()}")
print(f"Confidence: {data['confidence']}%")
print(f"Phishing Probability: {data.get('phishingProbability', 'N/A')}%")
print(f"\nSuspicious Signals: {data.get('signals', [])}")
print(f"\nFeatures:")
for name, value in data.get('features', {}).items():
    status = "✓ SAFE" if value == -1 else ("⚠️ NEUTRAL" if value == 0 else "🚨 SUSPICIOUS")
    print(f"  {name:30s} = {value:2d}  {status}")

print("\n" + "="*60)
if data['prediction'] == 'legitimate':
    print("✅ SUCCESS: GitHub correctly identified as LEGITIMATE")
else:
    print("❌ FAILED: GitHub incorrectly flagged as PHISHING")
