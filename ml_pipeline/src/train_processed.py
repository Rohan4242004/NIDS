import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, classification_report
import joblib

PROCESSED_DIR = os.path.join("ml_pipeline", "data", "processed")
MODEL_DIR = os.path.join("ml_pipeline", "models")

def train_model():
    # File paths
    X_train_path = os.path.join(PROCESSED_DIR, "X_train.npy")
    y_train_path = os.path.join(PROCESSED_DIR, "y_train.npy")
    X_test_path = os.path.join(PROCESSED_DIR, "X_test.npy")
    y_test_path = os.path.join(PROCESSED_DIR, "y_test.npy")
    
    if not (os.path.exists(X_train_path) and os.path.exists(y_train_path)):
        raise FileNotFoundError("[Trainer] Preprocessed training files not found. Run preprocess.py first.")
        
    print("[Trainer] Loading preprocessed numpy arrays...")
    X_train = np.load(X_train_path)
    y_train = np.load(y_train_path)
    X_test = np.load(X_test_path)
    y_test = np.load(y_test_path)
    
    print(f"[Trainer] Train size: {X_train.shape}, Test size: {X_test.shape}")
    
    # Train Random Forest Classifier
    print("[Trainer] Fitting RandomForest classifier on preprocessed dataset...")
    # Use balanced class weights to help with minor class imbalances
    model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=12, class_weight="balanced")
    model.fit(X_train, y_train)
    
    # Predictions
    y_pred = model.predict(X_test)
    
    # Score
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")
    
    print("\n[Trainer] Training Completed.")
    print(f"Accuracy: {acc:.4%}")
    print(f"Weighted F1-Score: {f1:.4%}")
    
    target_names = ["Benign", "DDoS", "PortScan", "Botnet", "BruteForce", "WebAttack"]
    # Prune target names if some labels aren't in test set
    unique_labels = np.unique(np.concatenate([y_test, y_pred]))
    target_names_filtered = [target_names[i] for i in unique_labels if i < len(target_names)]
    
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=target_names_filtered))
    
    # Export Model
    model_path = os.path.join(MODEL_DIR, "active_model.joblib")
    joblib.dump(model, model_path)
    print(f"[Trainer] Serialised model saved successfully to: {model_path}")

if __name__ == "__main__":
    train_model()
