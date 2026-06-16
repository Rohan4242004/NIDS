import os
import requests
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

# Target URLs for CIC-IDS2017 sample subsets (using a clean public sample mirror)
DATASET_URL = "https://raw.githubusercontent.com/cybersecurity-datasets/cic-ids2017-sample/main/portscan_ddos_sample.csv"
DATA_DIR = os.path.join("ml_pipeline", "data")
PROCESSED_DIR = os.path.join("ml_pipeline", "data", "processed")
MODEL_DIR = os.path.join("ml_pipeline", "models")

def ensure_directories():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs(MODEL_DIR, exist_ok=True)

def download_dataset():
    """
    Downloads a small, pre-trimmed CSV sample of the CIC-IDS2017 dataset containing Benign, PortScan, and DDoS samples.
    If the remote download fails, it falls back to generating a realistic synthetic dataset to allow local validation.
    """
    ensure_directories()
    csv_path = os.path.join(DATA_DIR, "cicids2017_sample.csv")
    
    if os.path.exists(csv_path):
        print(f"[Prep] Dataset already exists at: {csv_path}")
        return csv_path
        
    print(f"[Prep] Downloading CIC-IDS2017 sample from: {DATASET_URL}...")
    try:
        response = requests.get(DATASET_URL, timeout=15)
        response.raise_for_status()
        with open(csv_path, "wb") as f:
            f.write(response.content)
        print(f"[Prep] Download complete. Saved to: {csv_path}")
        return csv_path
    except Exception as e:
        print(f"[Prep] Download failed: {e}. Generating high-fidelity mock dataset to fallback...")
        return generate_mock_cicids2017(csv_path)

def generate_mock_cicids2017(path):
    """
    Generates a mock pandas DataFrame that matches the features and types of the CIC-IDS2017 CSV columns.
    """
    np.random.seed(42)
    n_samples = 4000
    
    # Standard columns of CIC-IDS2017 (subset)
    cols = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
        "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Max",
        "Fwd IAT Total", "Bwd IAT Total", "Fwd Header Length", "Bwd Header Length",
        "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
        "Packet Length Mean", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
        "ACK Flag Count", "URG Flag Count", "Protocol", "Label"
    ]
    
    data = []
    labels = np.random.choice(["BENIGN", "DDoS", "PortScan"], size=n_samples, p=[0.70, 0.15, 0.15])
    
    for i in range(n_samples):
        label = labels[i]
        
        # Base normal values
        flow_dur = np.random.uniform(10, 5000)
        tot_fw = np.random.randint(1, 30)
        tot_bw = np.random.randint(1, 30)
        l_fw = tot_fw * np.random.uniform(40, 1000)
        l_bw = tot_bw * np.random.uniform(40, 1000)
        proto = np.random.choice([6, 17], p=[0.8, 0.2]) # TCP/UDP
        
        syn_cnt = np.random.choice([0, 1], p=[0.9, 0.1])
        rst_cnt = np.random.choice([0, 1], p=[0.99, 0.01])
        psh_cnt = np.random.choice([0, 1], p=[0.5, 0.5])
        ack_cnt = np.random.choice([0, 1], p=[0.2, 0.8])
        
        # Adjust for attacks
        if label == "DDoS":
            flow_dur = np.random.uniform(1, 100)
            tot_fw = np.random.randint(200, 1000)
            tot_bw = np.random.randint(0, 5)
            l_fw = tot_fw * np.random.uniform(500, 1200)
            l_bw = tot_bw * np.random.uniform(0, 100)
            proto = 6 # TCP
            syn_cnt = 1
            ack_cnt = 0
        elif label == "PortScan":
            flow_dur = np.random.uniform(0.1, 5)
            tot_fw = np.random.choice([1, 2])
            tot_bw = np.random.choice([0, 1])
            l_fw = tot_fw * 40
            l_bw = tot_bw * 40
            proto = 6
            syn_cnt = 1
            rst_cnt = 1
            ack_cnt = 0

        # Speeds
        bytes_s = (l_fw + l_bw) / (flow_dur / 1000000.0)
        pkts_s = (tot_fw + tot_bw) / (flow_dur / 1000000.0)
        
        row = [
            flow_dur, tot_fw, tot_bw, l_fw, l_bw,
            1500, 40, 500, 1500, 40, 500, # lengths
            bytes_s, pkts_s, flow_dur/2, flow_dur,
            flow_dur, flow_dur if tot_bw > 0 else 0,
            tot_fw * 20, tot_bw * 20,
            pkts_s * 0.6, pkts_s * 0.4,
            40, 1500, 450,
            syn_cnt, rst_cnt, psh_cnt, ack_cnt, 0, proto,
            label
        ]
        data.append(row)
        
    # Introduce small number of NaN and Infinite values intentionally to test cleaner logic
    df = pd.DataFrame(data, columns=cols)
    df.loc[np.random.choice(n_samples, 10), "Flow Bytes/s"] = np.inf
    df.loc[np.random.choice(n_samples, 5), "Bwd Packet Length Mean"] = np.nan
    
    df.to_csv(path, index=False)
    print(f"[Prep] Mock dataset generated at: {path}")
    return path

def preprocess_pipeline():
    # 1. Download/Generate
    csv_path = download_dataset()
    
    # 2. Load
    print("[Prep] Loading raw dataset...")
    df = pd.read_csv(csv_path)
    print(f"[Prep] Raw shape: {df.shape}")
    
    # 3. Analyze & Sanitize Columns
    # Strip whitespaces from column headers (CIC-IDS2017 has messy column headers)
    df.columns = df.columns.str.strip()
    
    # Identify non-numeric columns
    print(f"[Prep] Columns found: {list(df.columns[:5])}... Total: {len(df.columns)}")
    
    # 4. Handle Missing and Infinite values
    # In network captures, zero duration causes division by zero, resulting in Infinite bytes/s
    print("[Prep] Cleaning infinite and missing values...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Check nulls before dropping
    nulls = df.isnull().sum().sum()
    print(f"[Prep] Missing/Infinite value cells count: {nulls}")
    
    # Drop rows with nulls
    df.dropna(inplace=True)
    print(f"[Prep] Shape after dropping nulls/infs: {df.shape}")
    
    # 5. Remove unnecessary socket features
    # Socket features (IP addresses, ports, timestamps) lead to ML overfitting.
    # We only keep aggregated flow characteristics.
    socket_features = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Timestamp"]
    features_to_drop = [col for col in socket_features if col in df.columns]
    if features_to_drop:
        print(f"[Prep] Dropping socket features: {features_to_drop}")
        df.drop(columns=features_to_drop, inplace=True)

    # 6. Encode categorical labels
    # Label is categorical: 'BENIGN', 'DDoS', 'PortScan' etc.
    # Map them to integers: BENIGN -> 0, DDoS -> 1, PortScan -> 2, BruteForce -> 3
    print("[Prep] Encoding labels...")
    label_mapping = {
        "BENIGN": 0, "Normal": 0,
        "DDoS": 1, "DDoS-LOIC": 1, "DDoS-HOIC": 1,
        "PortScan": 2, "Port Scan": 2,
        "Bot": 3, "Botnet": 3,
        "BruteForce": 4, "Brute Force": 4, "FTP-Patator": 4, "SSH-Patator": 4,
        "WebAttack": 5, "Web Attack": 5, "Web Attack-Brute Force": 5, "Web Attack-XSS": 5, "Web Attack-Sql Injection": 5
    }

    
    # Map labels, default any unexpected attack label to 3
    df['Label_Encoded'] = df['Label'].map(label_mapping).fillna(3).astype(int)
    
    # Save label encoder reference for backend inference validation
    joblib.dump(label_mapping, os.path.join(MODEL_DIR, "label_mapping.joblib"))
    
    # Remove original label column
    y = df['Label_Encoded']
    X = df.drop(columns=['Label', 'Label_Encoded'])

    # 7. Balance Classes
    # In cybersecurity, normal traffic (BENIGN) usually dominates (>95% of traffic).
    # We down-sample BENIGN class here to balance and improve classifier sensitivity.
    print("[Prep] Balancing classes...")
    class_counts = y.value_counts()
    print(f"[Prep] Class distribution before balancing:\n{class_counts}")
    
    benign_indices = y[y == 0].index
    attack_indices = y[y != 0].index
    
    # Down-sample benign class to twice the total size of attack traffic
    n_benign_needed = min(len(benign_indices), len(attack_indices) * 2)
    if n_benign_needed > 0:
        np.random.seed(42)
        sampled_benign_indices = np.random.choice(benign_indices, size=n_benign_needed, replace=False)
        balanced_indices = np.concatenate([sampled_benign_indices, attack_indices])
        X = X.loc[balanced_indices]
        y = y.loc[balanced_indices]
    
    print(f"[Prep] Class distribution after balancing:\n{y.value_counts()}")

    # 8. Split Dataset
    print("[Prep] Splitting dataset into train/test split...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[Prep] Train set shape: {X_train.shape}, Test set shape: {X_test.shape}")

    # 9. Feature Scaling
    # Standardization shifts features to have mean=0 and std_dev=1, stabilizing weights optimization.
    print("[Prep] Standardizing features...")
    scaler = StandardScaler()
    
    # Select only the features that our real-time sniffer extracts (top 15) to maintain alignment
    # In a full pipeline we would standardise all, but for NIDS we prune to the sniffer features:
    # flow_duration, tot_fw_pkts, tot_bw_pkts, tot_l_fw_pkts, tot_l_bw_pkts,
    # flow_byts_s, flow_pkts_s, fwd_header_len, bwd_header_len,
    # flags_fin, flags_syn, flags_rst, flags_psh, flags_ack, protocol
    
    # We map columns to the sniffer features names to extract them:
    # (Notice mapping rules matching CIC-IDS2017 column names)
    col_mapping = {
        "Flow Duration": "flow_duration",
        "Total Fwd Packets": "tot_fw_pkts",
        "Total Backward Packets": "tot_bw_pkts",
        "Total Length of Fwd Packets": "tot_l_fw_pkts",
        "Total Length of Bwd Packets": "tot_l_bw_pkts",
        "Flow Bytes/s": "flow_byts_s",
        "Flow Packets/s": "flow_pkts_s",
        "Fwd Header Length": "fwd_header_len",
        "Bwd Header Length": "bwd_header_len",
        "SYN Flag Count": "flags_syn",
        "RST Flag Count": "flags_rst",
        "PSH Flag Count": "flags_psh",
        "ACK Flag Count": "flags_ack",
        "Protocol": "protocol_numeric"
    }
    
    # Rename columns to keep compatibility
    X.rename(columns=col_mapping, inplace=True)
    
    # Add FIN flag (defaulting to 0 since it is not always a standalone column in some CIC-IDS CSVs)
    if "flags_fin" not in X.columns:
        X["flags_fin"] = 0
        
    sniffer_features = [
        "flow_duration", "tot_fw_pkts", "tot_bw_pkts", "tot_l_fw_pkts", "tot_l_bw_pkts",
        "flow_byts_s", "flow_pkts_s", "fwd_header_len", "bwd_header_len",
        "flags_fin", "flags_syn", "flags_rst", "flags_psh", "flags_ack", "protocol_numeric"
    ]
    
    # Select only our sniffer features
    X_pruned = X[sniffer_features]
    
    # Split pruned features
    X_train_pruned, X_test_pruned, y_train_pruned, y_test_pruned = train_test_split(
        X_pruned, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale
    X_train_scaled = scaler.fit_transform(X_train_pruned)
    X_test_scaled = scaler.transform(X_test_pruned)
    
    # 10. Save scaled and processed training files
    print("[Prep] Exporting processed assets...")
    joblib.dump(scaler, os.path.join(MODEL_DIR, "active_scaler.joblib"))
    
    # Save np arrays
    np.save(os.path.join(PROCESSED_DIR, "X_train.npy"), X_train_scaled)
    np.save(os.path.join(PROCESSED_DIR, "X_test.npy"), X_test_scaled)
    np.save(os.path.join(PROCESSED_DIR, "y_train.npy"), y_train_pruned.to_numpy())
    np.save(os.path.join(PROCESSED_DIR, "y_test.npy"), y_test_pruned.to_numpy())
    
    print("[Prep] Scaling artifacts and processed matrices exported successfully.")
    
if __name__ == "__main__":
    preprocess_pipeline()
