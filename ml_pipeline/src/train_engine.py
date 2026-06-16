import os
import numpy as np
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import joblib

# Check if xgboost is installed, fallback gracefully if not
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

PROCESSED_DIR = os.path.join("ml_pipeline", "data", "processed")
MODEL_DIR = os.path.join("ml_pipeline", "models")

# Attack classes mapping
CLASSES = ["Normal", "DDoS", "Port Scan", "Botnet", "Brute Force", "Web Attack"]

def train_and_compare():
    X_train_path = os.path.join(PROCESSED_DIR, "X_train.npy")
    y_train_path = os.path.join(PROCESSED_DIR, "y_train.npy")
    X_test_path = os.path.join(PROCESSED_DIR, "X_test.npy")
    y_test_path = os.path.join(PROCESSED_DIR, "y_test.npy")
    
    if not (os.path.exists(X_train_path) and os.path.exists(y_train_path)):
        raise FileNotFoundError("[ML Engine] Preprocessed training files not found. Run preprocess.py first.")
        
    print("[ML Engine] Loading preprocessed numpy arrays...")
    X_train = np.load(X_train_path)
    y_train = np.load(y_train_path)
    X_test = np.load(X_test_path)
    y_test = np.load(y_test_path)
    
    print(f"[ML Engine] Train size: {X_train.shape}, Test size: {X_test.shape}")
    
    # 1. Train Random Forest
    print("\n[ML Engine] 1. Training RandomForest Classifier...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=12, class_weight="balanced")
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    rf_acc = accuracy_score(y_test, rf_preds)
    print(f"RandomForest Accuracy: {rf_acc:.4%}")
    
    # 2. Train XGBoost (if available)
    xgb_acc = -1
    xgb_model = None
    if XGBOOST_AVAILABLE:
        print("\n[ML Engine] 2. Training XGBoost Classifier...")
        # Map labels to 0..N-1 class range (XGBoost requires integer classes starting at 0)
        xgb_model = XGBClassifier(n_estimators=100, random_state=42, max_depth=6, learning_rate=0.1, eval_metric="mlogloss")
        xgb_model.fit(X_train, y_train)
        xgb_preds = xgb_model.predict(X_test)
        xgb_acc = accuracy_score(y_test, xgb_preds)
        print(f"XGBoost Accuracy: {xgb_acc:.4%}")
    else:
        print("\n[ML Engine] 2. XGBoost package is not installed/available. Skipping XGBoost training.")
        
    # 3. Compare Accuracy and select best model
    best_model_name = "RandomForest"
    best_model = rf_model
    best_acc = rf_acc
    best_preds = rf_preds
    
    if XGBOOST_AVAILABLE and xgb_acc > rf_acc:
        best_model_name = "XGBoost"
        best_model = xgb_model
        best_acc = xgb_acc
        best_preds = xgb_preds
        
    print(f"\n==========================================")
    print(f"Best Performing Model: {best_model_name} (Accuracy: {best_acc:.4%})")
    print(f"==========================================")
    
    # 4. Generate Confusion Matrix
    cm = confusion_matrix(y_test, best_preds)
    print("\nConfusion Matrix:")
    print(cm)
    
    # Calculate unique classes present in test data
    unique_classes_test = np.unique(y_test)
    present_classes = [CLASSES[i] for i in unique_classes_test if i < len(CLASSES)]
    
    # 5. Precision, 6. Recall, 7. F1-Score
    precision = precision_score(y_test, best_preds, average="weighted", zero_division=0)
    recall = recall_score(y_test, best_preds, average="weighted", zero_division=0)
    f1 = f1_score(y_test, best_preds, average="weighted", zero_division=0)
    
    print(f"\nEvaluation Metrics (Weighted Average):")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 Score  : {f1:.4f}")
    
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, best_preds, target_names=present_classes, zero_division=0))
    
    # 8. Save best model using joblib
    model_path = os.path.join(MODEL_DIR, "active_model.joblib")
    joblib.dump(best_model, model_path)
    print(f"\n[ML Engine] Best model saved to: {model_path}")
    
    # Save a metadata text file indicating which model was saved
    meta_path = os.path.join(MODEL_DIR, "model_metadata.json")
    import json
    metadata = {
        "best_model": best_model_name,
        "accuracy": float(best_acc),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "trained_at": datetime.utcnow().isoformat() + "Z"
    }
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=4)
        
def predict_traffic(raw_features: list) -> tuple:
    """
    Inference helper function for real-time prediction.
    Args:
        raw_features (list): list of 15 features matching the sniffer format
    Returns:
        tuple: (predicted_class_name: str, confidence_score: float)
    """
    scaler_path = os.path.join(MODEL_DIR, "active_scaler.joblib")
    model_path = os.path.join(MODEL_DIR, "active_model.joblib")
    
    if not (os.path.exists(scaler_path) and os.path.exists(model_path)):
        return "Normal", 1.0 # default baseline
        
    try:
        # Load assets
        scaler = joblib.load(scaler_path)
        model = joblib.load(model_path)
        
        # Scale & predict
        features_arr = np.array(raw_features).reshape(1, -1)
        scaled_features = scaler.transform(features_arr)
        pred_class = model.predict(scaled_features)[0]
        pred_proba = model.predict_proba(scaled_features)[0]
        
        class_name = CLASSES[pred_class] if pred_class < len(CLASSES) else "Unknown"
        confidence = float(pred_proba[pred_class])
        return class_name, confidence
    except Exception as e:
        print(f"[Prediction Function] Error running inference: {e}")
        return "Normal", 0.5

if __name__ == "__main__":
    train_and_compare()
