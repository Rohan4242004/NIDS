from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import or_
from datetime import datetime


from app.database.connection import get_db
from app.auth.deps import get_current_user
from app.models.user import User
from app.models.traffic_log import TrafficLog
from app.models.system_log import SystemLog
from app.api.schemas import TrafficLogResponse, SystemLogResponse

router = APIRouter()

@router.get("/", response_model=List[TrafficLogResponse])
def get_traffic_logs(
    skip: int = 0,
    limit: int = 100,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(TrafficLog)
    
    if search:
        query = query.filter(
            or_(
                TrafficLog.src_ip.like(f"%{search}%"),
                TrafficLog.dst_ip.like(f"%{search}%")
            )
        )
        
    logs = query.order_by(TrafficLog.created_at.desc()).offset(skip).limit(limit).all()
    return logs

@router.get("/{log_id}", response_model=TrafficLogResponse)
def get_traffic_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    log = db.query(TrafficLog).filter(TrafficLog.id == log_id).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Traffic log with ID {log_id} not found"
        )
    return log


from app.api.schemas import FlowIngest
from app.ml.detection_engine import nids_detector
from app.packet_capture.sniffer import sniffer_daemon

@router.post("/ingest", status_code=status.HTTP_201_CREATED)
def ingest_network_flow(
    flow: FlowIngest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Ingestion endpoint for external NIDS packet-capture sensors.
    Receives aggregated bidirectional flow telemetry and runs ML inference.
    """
    try:
        # Build flow details dict from the ingest schema
        flow_details = {
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "duration": flow.duration,
            "total_packets": flow.total_packets,
            "total_bytes": flow.total_bytes
        }
        
        # Analyze and log the flow using the unified detection engine
        res = nids_detector.analyze_and_log_flow(db, flow_details, flow.features, background_tasks)
        
        prediction_label = res["prediction"]
        confidence = res["confidence"]
        severity = res["severity"]
        alert_id = res["alert_id"]
        log_id = res["log_id"]
        
        # Broadcast via WebSocket channel
        if sniffer_daemon.websocket_broadcast_cb:
            payload = {
                "event": "new_flow" if prediction_label == "Benign" else "alert_triggered",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "data": {
                    "log_id": log_id,
                    "alert_id": alert_id,
                    "severity": severity if prediction_label != "Benign" else "INFO",
                    "attack_type": prediction_label,
                    "source": f"{flow.src_ip}:{flow.src_port}",
                    "destination": f"{flow.dst_ip}:{flow.dst_port}",
                    "flow_details": {
                        "protocol": flow.protocol,
                        "duration_sec": round(flow.duration, 3),
                        "total_bytes": flow.total_bytes,
                        "total_packets": flow.total_packets
                    },
                    "confidence": round(confidence, 3)
                }
            }
            sniffer_daemon.websocket_broadcast_cb(payload)
            
        return {
            "status": "success",
            "log_id": log_id,
            "prediction": prediction_label,
            "confidence": confidence,
            "alert_triggered": alert_id is not None
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest network flow: {str(e)}"
        )

@router.get("/system/logs", response_model=List[SystemLogResponse])
def get_system_logs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve backend system audit logs.
    """
    sys_logs = db.query(SystemLog).order_by(SystemLog.created_at.desc()).offset(skip).limit(limit).all()
    return sys_logs

