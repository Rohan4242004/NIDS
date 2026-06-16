import pytest
from app.ml.detection_engine import nids_detector
from app.models.traffic_log import TrafficLog
from app.models.model_prediction import ModelPrediction
from app.models.alert import Alert

def test_heuristic_fallbacks():
    # DDoS profile (high packets, high packets/s, SYN flag)
    # [duration, tot_fw, tot_bw, tot_l_fw, tot_l_bw, bytes_s, pkts_s, fw_hdr, bw_hdr, fin, syn, rst, psh, ack, proto]
    ddos_features = [0.1, 600, 0, 100000, 0, 1000000.0, 6000.0, 24000, 0, 0, 1, 0, 0, 0, 6]
    label, confidence = nids_detector.predict_flow(ddos_features)
    assert label == "DDoS"
    assert confidence > 0.8
    
    # Port Scan profile (very low forward packets, SYN flag)
    scan_features = [0.001, 1, 0, 40, 0, 40000.0, 1000.0, 40, 0, 0, 1, 0, 0, 0, 6]
    label, confidence = nids_detector.predict_flow(scan_features)
    assert label == "Port Scan"
    
    # Benign profile (normal packets, no flags)
    benign_features = [1.5, 10, 10, 1500, 1500, 2000.0, 13.3, 400, 400, 0, 0, 0, 0, 1, 17]
    label, confidence = nids_detector.predict_flow(benign_features)
    assert label == "Benign"

def test_analyze_and_log_flow_persistence(db):
    flow_details = {
        "src_ip": "10.0.0.5",
        "src_port": 4444,
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "protocol": "TCP",
        "duration": 0.05,
        "total_packets": 605,
        "total_bytes": 120000
    }
    # DDoS feature profile
    features = [0.05, 605, 0, 120000, 0, 2400000.0, 12100.0, 24200, 0, 0, 1, 0, 0, 0, 6]
    
    res = nids_detector.analyze_and_log_flow(db, flow_details, features)
    
    assert res["prediction"] == "DDoS"
    assert res["severity"] == "CRITICAL"
    assert res["log_id"] is not None
    assert res["alert_id"] is not None
    
    # Verify rows exist in DB
    log = db.query(TrafficLog).filter(TrafficLog.id == res["log_id"]).first()
    assert log is not None
    assert log.src_ip == "10.0.0.5"
    
    pred = db.query(ModelPrediction).filter(ModelPrediction.log_id == res["log_id"]).first()
    assert pred is not None
    assert pred.predicted_attack_type_id == 2 # DDoS ID
    
    alert = db.query(Alert).filter(Alert.id == res["alert_id"]).first()
    assert alert is not None
    assert alert.severity == "CRITICAL"
    assert alert.status == "UNRESOLVED"
