import os
import json
import random
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

def generate_synthetic_eti_data():
    X = []
    y = []

    # 1. BENIGN: typical web traffic (mixed sizes, random arrival times)
    for _ in range(500):
        # 10-bucket histogram
        hist = [random.uniform(0.1, 0.4) for _ in range(10)]
        s = sum(hist)
        hist = [h / s for h in hist]
        
        mean_sz = random.uniform(200, 800)
        var_sz = random.uniform(5000, 30000)
        mean_iat = random.uniform(50, 500)
        var_iat = random.uniform(10000, 90000)
        cv_iat = np.sqrt(var_iat) / mean_iat if mean_iat > 0 else 0.5
        burst_count = random.uniform(5, 30)
        avg_burst_sz = random.uniform(1000, 10000)
        
        features = hist + [mean_sz, var_sz, mean_iat, var_iat, cv_iat, burst_count, avg_burst_sz]
        X.append(features)
        y.append("BENIGN")

    # 2. SUSPICIOUS: Beaconing malware (fixed timing patterns, low IAT variance)
    for _ in range(250):
        hist = [0.0] * 10
        hist[0] = random.uniform(0.6, 0.9)  # mostly small keep-alive packets
        s = sum(hist)
        hist = [h / s for h in hist]
        
        mean_sz = random.uniform(40, 150)
        var_sz = random.uniform(5, 50)
        mean_iat = random.choice([1000, 2000, 5000, 10000])  # beacon interval
        var_iat = random.uniform(0.1, 5.0)  # very low variance!
        cv_iat = np.sqrt(var_iat) / mean_iat
        burst_count = random.uniform(10, 50)
        avg_burst_sz = random.uniform(100, 500)
        
        features = hist + [mean_sz, var_sz, mean_iat, var_iat, cv_iat, burst_count, avg_burst_sz]
        X.append(features)
        y.append("SUSPICIOUS")

    # 3. SUSPICIOUS: Data Exfiltration (large uploads, high byte ratio)
    for _ in range(250):
        hist = [0.0] * 10
        hist[9] = random.uniform(0.7, 0.95)  # mostly large MTU-sized packets
        s = sum(hist)
        hist = [h / s for h in hist]
        
        mean_sz = random.uniform(1200, 1450)
        var_sz = random.uniform(5, 500)
        mean_iat = random.uniform(5, 30)  # back-to-back packets
        var_iat = random.uniform(10, 500)
        cv_iat = np.sqrt(var_iat) / mean_iat
        burst_count = random.uniform(1, 5)
        avg_burst_sz = random.uniform(50000, 500000)
        
        features = hist + [mean_sz, var_sz, mean_iat, var_iat, cv_iat, burst_count, avg_burst_sz]
        X.append(features)
        y.append("SUSPICIOUS")

    # 4. MALICIOUS: Covert DNS Tunneling (tiny uniform payloads over DNS)
    for _ in range(200):
        hist = [0.0] * 10
        hist[0] = 1.0  # all packets are tiny (under 100 bytes)
        
        mean_sz = random.uniform(30, 75)
        var_sz = random.uniform(0.1, 5.0)  # extremely uniform payload sizes
        mean_iat = random.uniform(5, 20)
        var_iat = random.uniform(1, 50)
        cv_iat = np.sqrt(var_iat) / mean_iat
        burst_count = random.uniform(15, 100)
        avg_burst_sz = random.uniform(30, 80)
        
        features = hist + [mean_sz, var_sz, mean_iat, var_iat, cv_iat, burst_count, avg_burst_sz]
        X.append(features)
        y.append("MALICIOUS")

    return np.array(X), np.array(y)

def main():
    print("Generating synthetic dataset for ETI classification...")
    X, y = generate_synthetic_eti_data()
    
    print(f"Dataset shape: {X.shape}, labels: {len(y)}")
    
    # Train Random Forest Classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    
    # Create models directory if it doesn't exist
    os.makedirs("models", exist_ok=True)
    
    # Save the trained model
    joblib.dump(clf, "models/eti_rf_model.pkl")
    print("Model successfully trained and saved to 'models/eti_rf_model.pkl'")

if __name__ == "__main__":
    main()
