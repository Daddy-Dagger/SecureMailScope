"""API route modules."""

from backend.app.api.analysis import router as analysis_router
from backend.app.api.reports import router as reports_router

__all__ = [
    "analysis_router",
    "reports_router",
]
