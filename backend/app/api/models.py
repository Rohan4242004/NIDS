from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.auth.deps import get_current_user, get_current_admin
from app.models.user import User
from app.models.ml_model import MLModel
from app.api.schemas import MLModelResponse

router = APIRouter()

@router.get("/", response_model=List[MLModelResponse])
def get_ml_models(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(MLModel).all()

@router.post("/{model_id}/activate", response_model=MLModelResponse)
def activate_ml_model(
    model_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin)
):
    model = db.query(MLModel).filter(MLModel.id == model_id).first()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ML Model with ID {model_id} not found"
        )
        
    # Deactivate all models
    db.query(MLModel).update({MLModel.is_active: False})
    
    # Activate selected model
    model.is_active = True
    db.commit()
    db.refresh(model)
    
    # Hot-reload in-memory detection engine model assets
    try:
        from app.ml.detection_engine import nids_detector
        nids_detector.load_model_assets(model_path=model.filepath)
        nids_detector.model_version = model.version
    except Exception as e:
        print(f"[API Models] Error hot-reloading active model weights: {e}")
        
    return model
