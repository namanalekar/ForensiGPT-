import pytest
from pathlib import Path
import tempfile
import shutil
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings
from app.models.db_models import init_db

@pytest.fixture
def client():
    # Use temporary directory for tests
    temp_dir = Path(tempfile.mkdtemp())
    settings.DATA_DIR = temp_dir / "data"
    settings.UPLOAD_DIR = settings.DATA_DIR / "vault"
    settings.REPORT_DIR = settings.DATA_DIR / "reports"
    settings.VISUALS_DIR = settings.DATA_DIR / "visuals"
    settings.DB_PATH = settings.DATA_DIR / "test_forensigpt.db"
    settings.ensure_directories()
    init_db()

    with TestClient(app) as test_client:
        yield test_client

    shutil.rmtree(temp_dir, ignore_errors=True)
