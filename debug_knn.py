import os
import joblib
from utils.feature_extractor import extract_features

with open('data/test_attact.log', 'r') as f:
    text = f.read()

base_dir = os.path.dirname(os.path.abspath(__file__))
knn = joblib.load(os.path.join(base_dir, 'models', 'nsl_kdd_model.pkl'))
scaler = joblib.load(os.path.join(base_dir, 'models', 'scaler.pkl'))
le = joblib.load(os.path.join(base_dir, 'models', 'label_encoder.pkl'))

features = extract_features(text, le, scaler)
prediction = knn.predict(features)[0]
confidence = max(knn.predict_proba(features)[0])

print(f"Prediction: {prediction}, Confidence: {confidence}")
