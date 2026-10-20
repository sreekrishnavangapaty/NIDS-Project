from fastapi import APIRouter, Depends
from app.database.repository import DatabaseRepository
from app.analytics import statistics

router = APIRouter(prefix="/statistics", tags=["statistics"])


@router.get("")
def get_dashboard_stats(repo: DatabaseRepository = Depends(DatabaseRepository)):
    return statistics.get_dashboard_stats(repo)


@router.get("/alerts")
def get_alert_stats(repo: DatabaseRepository = Depends(DatabaseRepository)):
    return statistics.get_alert_statistics(repo)


@router.get("/detection")
def get_detection_stats(repo: DatabaseRepository = Depends(DatabaseRepository)):
    return statistics.get_detection_statistics(repo)
