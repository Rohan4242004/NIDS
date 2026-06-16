from app.ml.detection_engine import nids_detector

class InferenceEngine:
    def __init__(self):
        pass

    @property
    def scaler(self):
        return nids_detector.scaler

    @property
    def model(self):
        return nids_detector.model

    @property
    def labels(self):
        return ["Benign", "DDoS", "PortScan", "BruteForce", "Botnet", "WebAttack"]

    def load_model(self):
        nids_detector.load_model_assets()

    def predict(self, feature_vector: list) -> tuple:
        """
        Predict intrusion class and confidence score using the unified detection engine.
        Input feature vector contains 15 fields.
        Returns: (label: str, confidence: float)
        """
        return nids_detector.predict_flow(feature_vector)

# Singleton instance
ml_engine = InferenceEngine()
