import logging
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse

from config import get_settings
from routes import analyze, analytics, campaigns, reports

logging.basicConfig(level=logging.INFO)
settings = get_settings()

app = FastAPI(
    title="MailScope AI Backend",
    version=settings.ANALYSIS_VERSION,
    description="AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform — backend for SIH26106.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(analyze.router)
app.include_router(analytics.router)
app.include_router(campaigns.router)
app.include_router(reports.router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Never crash the whole process because one downstream call (e.g. an
    # external threat-intel API) misbehaves — always return a structured error.
    logging.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal error. See server logs. No email content is included in logs."})


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "mode": "demo" if settings.DEMO_MODE else "live",
        "supabase_configured": bool(settings.SUPABASE_URL),
        "nlp_model_path_exists": __import__("os").path.isdir(settings.NLP_MODEL_PATH),
        "analysis_version": settings.ANALYSIS_VERSION,
    }


# Render (and most PaaS health checks / uptime monitors) expect a plain
# GET /health. Kept as a thin alias so the existing /api/health contract
# used by the frontend and tests is completely unchanged.
@app.get("/health", include_in_schema=False)
async def health_root():
    return await health()


# --- Serve the existing static frontend from this same service -------------
# The frontend is one self-contained HTML file (no separate JS/CSS/image
# assets to mount). Serving it from here means the deployed app has a
# single public URL and same-origin API calls work with zero CORS
# configuration for the primary demo flow. This does not change the
# frontend file itself or how it talks to the API — see MAILSCOPE.backendBase
# in the frontend for the (now same-origin-aware) API base logic.
_FRONTEND_FILE = Path(__file__).resolve().parent.parent / "frontend" / "mailscope-ai-v5.html"


@app.get("/", include_in_schema=False)
async def serve_frontend():
    if _FRONTEND_FILE.is_file():
        return FileResponse(_FRONTEND_FILE)
    return JSONResponse(status_code=404, content={"detail": "Frontend build not found at " + str(_FRONTEND_FILE)})
