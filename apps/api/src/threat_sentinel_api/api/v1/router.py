from fastapi import APIRouter

from threat_sentinel_api.api.v1.routes.health import router as health_router
from threat_sentinel_api.api.v1.routes.scans import router as scans_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])
api_router.include_router(scans_router, tags=["scans"])
