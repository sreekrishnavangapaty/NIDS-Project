"""FastAPI application entry point."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
from contextlib import asynccontextmanager

from app.database.connection import init_db
from app.api import alerts, traffic, statistics

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting NIDS API...")
    init_db()
    yield
    logger.info("Shutting down NIDS API...")


app = FastAPI(
    title="NIDS API",
    description="Network Intrusion Detection System API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router)
app.include_router(traffic.router)
app.include_router(statistics.router)


@app.get("/health", tags=["health"])
def health_check():
    return {"status": "ok"}
