from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional
from app.schemas.packet_schema import NetworkEventResponse
from app.database.repository import DatabaseRepository

router = APIRouter(prefix="/traffic", tags=["traffic"])


@router.get("", response_model=List[dict])
def list_events(
    protocol: Optional[str] = None,
    source_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    repo: DatabaseRepository = Depends(DatabaseRepository)
):
    return repo.get_events(limit=limit, offset=offset, protocol=protocol, source_ip=source_ip, dest_ip=dest_ip)


@router.get("/protocols")
def protocol_distribution(repo: DatabaseRepository = Depends(DatabaseRepository)):
    return repo.get_protocol_distribution()


@router.get("/top-sources")
def top_sources(repo: DatabaseRepository = Depends(DatabaseRepository)):
    return repo.get_top_source_ips(limit=10)


@router.get("/top-ports")
def top_ports(repo: DatabaseRepository = Depends(DatabaseRepository)):
    return repo.get_top_destination_ports(limit=10)
