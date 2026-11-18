from fastapi import APIRouter

from threat_sentinel_api.api.v1.routes.account import router as account_router
from threat_sentinel_api.api.v1.routes.health import router as health_router
from threat_sentinel_api.api.v1.routes.organizations import router as organizations_router
from threat_sentinel_api.api.v1.routes.scans import router as scans_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])
api_router.include_router(account_router)
api_router.include_router(organizations_router)
api_router.include_router(scans_router, tags=["scans"])
