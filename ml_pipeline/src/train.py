import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, classification_report
import joblib

def generate_synthetic_data(n_samples=5000):
    np.random.seed(42)
    
    # Feature list:
    # 0: flow_duration (seconds/microseconds)
    # 1: tot_fw_pkts
    # 2: tot_bw_pkts
    # 3: tot_l_fw_pkts (bytes)
    # 4: tot_l_bw_pkts (bytes)
    # 5: flow_byts_s
    # 6: flow_pkts_s
    # 7: fwd_header_len
    # 8: bwd_header_len
    # 9: flags_fin (0 or 1)
    # 10: flags_syn (0 or 1)
    # 11: flags_rst (0 or 1)
    # 12: flags_psh (0 or 1)
    # 13: flags_ack (0 or 1)
    # 14: protocol_numeric (6=TCP, 17=UDP, 1=ICMP)
    
    # Labels: 0=Benign, 1=DDoS, 2=PortScan, 3=BruteForce
    
    data = []
    labels = []
    
    for i in range(n_samples):
        # Determine class
        cls = np.random.choice([0, 1, 2, 3], p=[0.6, 0.15, 0.15, 0.10])
        labels.append(cls)
        
        # Default benign profile
        flow_duration = np.random.exponential(1.5) + 0.01
        tot_fw_pkts = np.random.randint(1, 30)
        tot_bw_pkts = np.random.randint(1, 30)
        tot_l_fw_pkts = tot_fw_pkts * np.random.randint(40, 1000)
        tot_l_bw_pkts = tot_bw_pkts * np.random.randint(40, 1000)
        protocol_numeric = np.random.choice([6, 17, 1], p=[0.7, 0.25, 0.05])
        
        # Flags (mostly ACK, some PSH/SYN)
        flags_fin = np.random.choice([0, 1], p=[0.98, 0.02])
        flags_syn = np.random.choice([0, 1], p=[0.9, 0.1])
        flags_rst = np.random.choice([0, 1], p=[0.99, 0.01])
        flags_psh = np.random.choice([0, 1], p=[0.6, 0.4])
        flags_ack = np.random.choice([0, 1], p=[0.2, 0.8])
        
        # Normal traffic adjustments
        if cls == 0:
            pass # benign is default
            
        elif cls == 1: # DDoS (extremely high packet/byte rate, high number of packets)
            flow_duration = np.random.uniform(0.01, 0.5)
            tot_fw_pkts = np.random.randint(100, 1000)
            tot_bw_pkts = np.random.randint(0, 10)
            tot_l_fw_pkts = tot_fw_pkts * np.random.randint(500, 1500)
            tot_l_bw_pkts = tot_bw_pkts * np.random.randint(0, 500)
            flags_syn = 1
            flags_ack = 0
            protocol_numeric = 6 # TCP
            
        elif cls == 2: # PortScan (very short flows, low packet count, mostly SYN flags or RST flags)
            flow_duration = np.random.uniform(0.0001, 0.005)
            tot_fw_pkts = np.random.choice([1, 2])
            tot_bw_pkts = np.random.choice([0, 1])
            tot_l_fw_pkts = tot_fw_pkts * 40
            tot_l_bw_pkts = tot_bw_pkts * 40
            flags_syn = np.random.choice([0, 1], p=[0.1, 0.9])
            flags_rst = np.random.choice([0, 1], p=[0.5, 0.5])
            flags_ack = 0
            protocol_numeric = 6 # TCP
            
        elif cls == 3: # BruteForce (medium duration, high ACK/PSH flags, steady packet flow on TCP)
            flow_duration = np.random.uniform(2.0, 10.0)
            tot_fw_pkts = np.random.randint(20, 100)
            tot_bw_pkts = np.random.randint(20, 100)
            tot_l_fw_pkts = tot_fw_pkts * np.random.randint(100, 500)
            tot_l_bw_pkts = tot_bw_pkts * np.random.randint(100, 500)
            flags_psh = 1
            flags_ack = 1
            protocol_numeric = 6 # TCP (SSH/FTP/HTTP brute force)

        # Derived rates
        flow_byts_s = (tot_l_fw_pkts + tot_l_bw_pkts) / flow_duration
        flow_pkts_s = (tot_fw_pkts + tot_bw_pkts) / flow_duration
        
        # Header lengths (e.g. 20 bytes IPv4 header + TCP/UDP header per packet)
        fwd_header_len = tot_fw_pkts * (20 + (20 if protocol_numeric == 6 else 8))
        bwd_header_len = tot_bw_pkts * (20 + (20 if protocol_numeric == 6 else 8))
        
        feature_vector = [
            flow_duration, tot_fw_pkts, tot_bw_pkts, tot_l_fw_pkts, tot_l_bw_pkts,
            flow_byts_s, flow_pkts_s, fwd_header_len, bwd_header_len,
            flags_fin, flags_syn, flags_rst, flags_psh, flags_ack, protocol_numeric
        ]
        data.append(feature_vector)
        
    cols = [
        "flow_duration", "tot_fw_pkts", "tot_bw_pkts", "tot_l_fw_pkts", "tot_l_bw_pkts",
        "flow_byts_s", "flow_pkts_s", "fwd_header_len", "bwd_header_len",
        "flags_fin", "flags_syn", "flags_rst", "flags_psh", "flags_ack", "protocol_numeric"
    ]
    df = pd.DataFrame(data, columns=cols)
    df["label"] = labels
    return df

def train_pipeline():
    print("Generating synthetic network flow dataset...")
    df = generate_synthetic_data(5000)
    
    X = df.drop(columns=["label"])
    y = df["label"]
    
    # Train test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Classifier
    print("Training RandomForest model...")
    model = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=10)
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")
    
    print(f"Model Training Complete.")
    print(f"Accuracy: {acc:.4f}")
    print(f"Weighted F1 Score: {f1:.4f}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=["Benign", "DDoS", "PortScan", "BruteForce"]))
    
    # Make sure output directory exists
    model_dir = "ml_pipeline/models"
    os.makedirs(model_dir, exist_ok=True)
    
    # Save scaler and model
    scaler_path = os.path.join(model_dir, "active_scaler.joblib")
    model_path = os.path.join(model_dir, "active_model.joblib")
    
    joblib.dump(scaler, scaler_path)
    joblib.dump(model, model_path)
    
    print(f"Model saved to {model_path}")
    print(f"Scaler saved to {scaler_path}")
    return acc, f1

if __name__ == "__main__":
    train_pipeline()
