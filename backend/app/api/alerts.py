from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.auth.deps import get_current_user
from app.models.user import User
from app.models.alert import Alert
from app.models.blocked_ip import BlockedIP
from app.api.schemas import AlertResponse, AlertUpdate, AlertHistoryResponse, BlockedIPResponse, BlockedIPBase
from app.services.alert_service import alert_service

router = APIRouter()

@router.get("/", response_model=List[AlertResponse])
def get_alerts(
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Alert)
    if status_filter:
        query = query.filter(Alert.status == status_filter.upper())
    if severity_filter:
        query = query.filter(Alert.severity == severity_filter.upper())
        
    alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()
    return alerts

@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(
    alert_id: int,
    alert_update: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Retrieve existing alert to check presence
    alert_check = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert_check:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    # Update and write transition history trace using AlertService
    alert = alert_service.update_alert_status(
        db=db,
        alert_id=alert_id,
        status=alert_update.status,
        notes=alert_update.notes,
        changed_by=current_user.username
    )
    return alert

@router.get("/{alert_id}/history", response_model=List[AlertHistoryResponse])
def get_alert_history(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )
    return alert.history

@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )
    db.delete(alert)
    db.commit()
    return None

@router.get("/blocked-ips", response_model=List[BlockedIPResponse])
def get_blocked_ips(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve list of blocked IPs.
    """
    return db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()

@router.post("/blocked-ips", response_model=BlockedIPResponse, status_code=status.HTTP_201_CREATED)
def block_ip(
    blocked_in: BlockedIPBase,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Add a firewall block rule for a specific IP.
    """
    existing = db.query(BlockedIP).filter(BlockedIP.ip_address == blocked_in.ip_address).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"IP address {blocked_in.ip_address} is already blocked."
        )
    new_block = BlockedIP(
        ip_address=blocked_in.ip_address,
        blocked_reason=blocked_in.blocked_reason,
        expires_at=blocked_in.expires_at,
        status="ACTIVE"
    )
    db.add(new_block)
    db.commit()
    db.refresh(new_block)
    return new_block

@router.delete("/blocked-ips/{ip_id}", status_code=status.HTTP_204_NO_CONTENT)
def unblock_ip(
    ip_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Remove a firewall block rule.
    """
    ip_block = db.query(BlockedIP).filter(BlockedIP.id == ip_id).first()
    if not ip_block:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Blocked IP record with ID {ip_id} not found."
        )
    db.delete(ip_block)
    db.commit()
    return None
