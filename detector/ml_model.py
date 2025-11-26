# ============================================================================
# FILE: detector/ml_model.py
# ============================================================================
import pickle
import pandas as pd
import os
from pathlib import Path

def load_model_artifacts(base_path=None):
    if base_path is None:
        base_path = Path(__file__).resolve().parent / 'ml_models'
    
    model_path = base_path / 'ransomware_detection_model_data2.pkl'
    scaler_path = base_path / 'scaler_data2.pkl'
    feature_path = base_path / 'feature_names_data2.pkl'
    encoders_path = base_path / 'label_encoders_data2.pkl'
    target_encoder_path = base_path / 'target_encoder_data2.pkl'
    
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(scaler_path, 'rb') as f:
        scaler = pickle.load(f)
    with open(feature_path, 'rb') as f:
        features = pickle.load(f)
    with open(encoders_path, 'rb') as f:
        encoders = pickle.load(f)
    with open(target_encoder_path, 'rb') as f:
        target_enc = pickle.load(f)
    
    return model, scaler, features, encoders, target_enc

def predict_ransomware(sample_dict, model, scaler, feature_names, label_encoders, target_encoder):
    sample_df = pd.DataFrame([sample_dict])
    
    for feature in feature_names:
        if feature not in sample_df.columns:
            sample_df[feature] = 0
    
    sample_df = sample_df[feature_names]
    sample_scaled = scaler.transform(sample_df)
    
    prediction = model.predict(sample_scaled)[0]
    probability = model.predict_proba(sample_scaled)[0]

    malware_prob = probability[1]
    if malware_prob > 0.7:
        risk_level = "HIGH"
    elif malware_prob > 0.4:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    if target_encoder:
        class_label = target_encoder.inverse_transform([prediction])[0]
    else:
        class_label = 'Benign' if prediction == 1 else 'Malware'
    
    result = {
        'prediction': class_label,
        'confidence': float(max(probability)) * 100,
        'malware_probability': float(malware_prob) * 100,
        'benign_probability': float(probability[0]) * 100,
        'risk_level': risk_level,
        'recommendation': 'ALLOW' if prediction == 0 else 'BLOCK/QUARANTINE',
        'details': {
            'high_registry_activity': sample_dict.get('registry_total', 0) > 5,
            'suspicious_network': sample_dict.get('network_threats', 0) > 0,
            'malicious_processes': sample_dict.get('processes_malicious', 0) > 0,
            'suspicious_files': sample_dict.get('files_malicious', 0) > 0
        }
    }
    
    return result
