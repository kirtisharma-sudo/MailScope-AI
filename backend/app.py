import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse

from config import get_settings
from routes import analyze, analytics, campaigns, reports


# -------------------------------------------------------------------
# Paths
# -------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_FILE = BASE_DIR / "frontend" / "mailscope-ai-v5.html"


# -------------------------------------------------------------------
# App setup
# -------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
settings = get_settings()

app = FastAPI(
    title="MailScope AI Backend",
    version=settings.ANALYSIS_VERSION,
    description=(
        "AI-Powered Email Threat Detection, Geolocation and "
        "Forensic Intelligence Platform — backend for SIH26106."
    ),
)


# -------------------------------------------------------------------
# CORS
# -------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# -------------------------------------------------------------------
# API routes
# -------------------------------------------------------------------

app.include_router(analyze.router)
app.include_router(analytics.router)
app.include_router(campaigns.router)
app.include_router(reports.router)


# -------------------------------------------------------------------
# Frontend
# -------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def serve_frontend():
    if FRONTEND_FILE.is_file():
        return FileResponse(FRONTEND_FILE)

    return JSONResponse(
        status_code=404,
        content={
            "detail": f"Frontend build not found at {FRONTEND_FILE}"
        },
    )


# -------------------------------------------------------------------
# Health
# -------------------------------------------------------------------

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "mode": "demo" if settings.DEMO_MODE else "live",
        "supabase_configured": bool(settings.SUPABASE_URL),
        "nlp_model_path_exists": __import__("os").path.isdir(
            settings.NLP_MODEL_PATH
        ),
        "analysis_version": settings.ANALYSIS_VERSION,
    }


@app.get("/health", include_in_schema=False)
async def health_root():
    return await health()


# -------------------------------------------------------------------
# Error handling
# -------------------------------------------------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
):
    logging.exception(
        "Unhandled error on %s",
        request.url.path,
    )

    return JSONResponse(
        status_code=500,
        content={
            "detail": (
                "Internal error. See server logs. "
                "No email content is included in logs."
            )
        },
    )
