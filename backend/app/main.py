"""SecureMailScope FastAPI application entry point."""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.analysis import router as analysis_router


def _allowed_origins() -> list[str]:
    configured = os.getenv(
        "SECUREMAILSCOPE_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


app = FastAPI(title="SecureMailScope", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(analysis_router)


@app.get("/health")
def health() -> dict[str, str]:
    """Return a small readiness response for local development."""
    return {"status": "ok", "service": "SecureMailScope"}

