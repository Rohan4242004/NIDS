import csv
import io
import json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.auth.deps import get_current_admin
from app.models.user import User
from app.models.alert import Alert
from app.models.traffic_log import TrafficLog

router = APIRouter()

def stream_csv_records(db: Session, report_type: str, filter_start, filter_end):
    # Buffer to render CSV rows in chunks
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    
    if report_type == "alerts":
        writer.writerow([
            "Alert ID", "Traffic Log ID", "Source IP:Port", "Destination IP:Port",
            "Attack Type", "Severity", "Status", "Resolution Notes", "Created At"
        ])
    else:
        writer.writerow([
            "Log ID", "Source IP", "Source Port", "Destination IP",
            "Destination Port", "Protocol", "Duration (sec)", "Total Packets",
            "Total Bytes", "Captured At"
        ])
        
    yield buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)
    
    offset = 0
    limit_val = 1000
    
    while True:
        if report_type == "alerts":
            query = db.query(Alert)
            if filter_start:
                query = query.filter(Alert.created_at >= filter_start)
            if filter_end:
                query = query.filter(Alert.created_at <= filter_end)
            records = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit_val).all()
        else:
            query = db.query(TrafficLog)
            if filter_start:
                query = query.filter(TrafficLog.created_at >= filter_start)
            if filter_end:
                query = query.filter(TrafficLog.created_at <= filter_end)
            records = query.order_by(TrafficLog.created_at.desc()).offset(offset).limit(limit_val).all()
            
        if not records:
            break
            
        for r in records:
            if report_type == "alerts":
                writer.writerow([
                    r.id,
                    r.log_id,
                    f"{r.traffic_log.src_ip}:{r.traffic_log.src_port}" if r.traffic_log else "N/A",
                    f"{r.traffic_log.dst_ip}:{r.traffic_log.dst_port}" if r.traffic_log else "N/A",
                    r.attack_type.name if r.attack_type else "Unknown",
                    r.severity,
                    r.status,
                    r.notes or "",
                    r.created_at.isoformat()
                ])
            else:
                writer.writerow([
                    r.id,
                    r.src_ip,
                    r.src_port,
                    r.dst_ip,
                    r.dst_port,
                    r.protocol,
                    r.duration,
                    r.total_packets,
                    r.total_bytes,
                    r.created_at.isoformat()
                ])
                
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)
        
        offset += limit_val

def stream_json_records(db: Session, report_type: str, filter_start, filter_end):
    yield "[\n"
    
    offset = 0
    limit_val = 1000
    first = True
    
    while True:
        if report_type == "alerts":
            query = db.query(Alert)
            if filter_start:
                query = query.filter(Alert.created_at >= filter_start)
            if filter_end:
                query = query.filter(Alert.created_at <= filter_end)
            records = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit_val).all()
        else:
            query = db.query(TrafficLog)
            if filter_start:
                query = query.filter(TrafficLog.created_at >= filter_start)
            if filter_end:
                query = query.filter(TrafficLog.created_at <= filter_end)
            records = query.order_by(TrafficLog.created_at.desc()).offset(offset).limit(limit_val).all()
            
        if not records:
            break
            
        for r in records:
            if not first:
                yield ",\n"
            first = False
            
            if report_type == "alerts":
                item = {
                    "id": r.id,
                    "log_id": r.log_id,
                    "attack_type": r.attack_type.name if r.attack_type else "Unknown",
                    "severity": r.severity,
                    "status": r.status,
                    "notes": r.notes,
                    "source": f"{r.traffic_log.src_ip}:{r.traffic_log.src_port}" if r.traffic_log else "0.0.0.0",
                    "destination": f"{r.traffic_log.dst_ip}:{r.traffic_log.dst_port}" if r.traffic_log else "0.0.0.0",
                    "created_at": r.created_at.isoformat()
                }
            else:
                item = {
                    "id": r.id,
                    "src_ip": r.src_ip,
                    "src_port": r.src_port,
                    "dst_ip": r.dst_ip,
                    "dst_port": r.dst_port,
                    "protocol": r.protocol,
                    "duration_sec": r.duration,
                    "total_packets": r.total_packets,
                    "total_bytes": r.total_bytes,
                    "created_at": r.created_at.isoformat()
                }
                
            yield json.dumps(item, indent=2)
            
        offset += limit_val
        
    yield "\n]"

@router.get("/export")
def export_reports(
    report_type: str = Query("alerts", pattern="^(alerts|traffic)$"),
    export_format: str = Query("csv", pattern="^(csv|json)$"),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin)
):
    """
    Export NIDS security alerts or network traffic logs as a CSV or JSON streaming file (admin only).
    """
    # 1. Parse Date Filters
    filter_start = None
    filter_end = None
    try:
        if start_date:
            # support ISO date or simple YYYY-MM-DD
            if "T" in start_date:
                filter_start = datetime.fromisoformat(start_date.replace("Z", ""))
            else:
                filter_start = datetime.strptime(start_date, "%Y-%m-%d")
        if end_date:
            if "T" in end_date:
                filter_end = datetime.fromisoformat(end_date.replace("Z", ""))
            else:
                filter_end = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1) - timedelta(seconds=1)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid date format. Use YYYY-MM-DD or ISO format. Error: {str(e)}"
        )

    # 2. Format Output
    filename = f"nids_{report_type}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if export_format == "json":
        return StreamingResponse(
            stream_json_records(db, report_type, filter_start, filter_end),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}.json"}
        )
    
    else:  # csv
        return StreamingResponse(
            stream_csv_records(db, report_type, filter_start, filter_end),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}.csv"}
        )
