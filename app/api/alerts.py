from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional, Dict, Any
from app.schemas.alert_schema import AlertResponse, AlertStatusUpdate, AlertStatus
from app.database.repository import DatabaseRepository
from app.alerts.alert_manager import AlertManager

router = APIRouter(prefix="/alerts", tags=["alerts"])


def get_repository() -> DatabaseRepository:
    return DatabaseRepository()


def get_alert_manager(repo: DatabaseRepository = Depends(DatabaseRepository)) -> AlertManager:
    return AlertManager(repo)


@router.get("", response_model=List[AlertResponse])
def list_alerts(
    severity: Optional[str] = None,
    rule_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    repo: DatabaseRepository = Depends(DatabaseRepository)
):
    try:
        alerts = repo.get_alerts(
            limit=limit,
            offset=offset,
            severity=severity,
            rule_name=rule_name,
            source_ip=source_ip,
            status=status
        )
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{alert_id}")
def get_alert(
    alert_id: int,
    manager: AlertManager = Depends(get_alert_manager)
):
    try:
        alert = manager.get_alert_details(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{alert_id}/status")
def update_status(
    alert_id: int,
    payload: Dict[str, Any],
    manager: AlertManager = Depends(get_alert_manager)
):
    valid_statuses = {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
    status = payload.get("status")
    if not status or status not in valid_statuses:
        raise HTTPException(status_code=400, detail="Invalid status")

    success = manager.update_status(alert_id, status)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found or update failed")
    return {"status": "success"}
