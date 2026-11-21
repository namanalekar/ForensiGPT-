from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.models.db_models import init_db
from app.api.routes_cases import router as cases_router
from app.api.routes_upload import router as upload_router
from app.api.routes_settings import router as settings_router
from app.api.routes_analysis import router as analysis_router
from app.api.routes_correlation import router as correlation_router
from app.api.routes_reports import router as reports_router
from app.api.routes_chat import router as chat_router
from app.api.routes_compare import router as compare_router
from app.api.routes_reputation import router as reputation_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure directories and database tables exist
    settings.ensure_directories()
    init_db()
    yield

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="ForensiGPT: AI-Powered Image, File & Log Forensics Investigator",
    lifespan=lifespan
)

# Enable CORS for local Vite development and Docker deployment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(cases_router, prefix="/api")
app.include_router(upload_router, prefix="/api")
app.include_router(settings_router, prefix="/api")
app.include_router(analysis_router, prefix="/api")
app.include_router(correlation_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(chat_router, prefix="/api")
app.include_router(compare_router, prefix="/api")
app.include_router(reputation_router, prefix="/api")

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "gemini_model": settings.GEMINI_MODEL,
        "privacy_mode_default": settings.PRIVACY_MODE_DEFAULT
    }
