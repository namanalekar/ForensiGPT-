from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "ForensiGPT"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Gemini configuration
    GEMINI_API_KEY: str = Field(default="", description="Google Gemini API Key")
    GEMINI_MODEL: str = Field(default="gemini-3.5-flash", description="Gemini Model Identifier")

    # Storage paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    UPLOAD_DIR: Path = DATA_DIR / "vault"
    REPORT_DIR: Path = DATA_DIR / "reports"
    VISUALS_DIR: Path = DATA_DIR / "visuals"
    DB_PATH: Path = DATA_DIR / "forensigpt.db"

    # Security limits
    MAX_UPLOAD_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB default
    ALLOWED_IMAGE_EXTENSIONS: set[str] = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".tif"}
    ALLOWED_LOG_EXTENSIONS: set[str] = {".log", ".txt", ".csv", ".syslog"}
    ALLOWED_DOC_EXTENSIONS: set[str] = {".pdf"}

    # Retention & Rate Limiting
    RETENTION_HOURS: int = 24
    RATE_LIMIT_PER_MINUTE: int = 120
    PRIVACY_MODE_DEFAULT: bool = False

    # Optional Hash Reputation
    VIRUSTOTAL_API_KEY: str = ""

    def ensure_directories(self) -> None:
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        self.REPORT_DIR.mkdir(parents=True, exist_ok=True)
        self.VISUALS_DIR.mkdir(parents=True, exist_ok=True)

settings = Settings()
settings.ensure_directories()
