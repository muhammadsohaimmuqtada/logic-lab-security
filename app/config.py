import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = Path(os.environ.get("LOGICLAB_INSTANCE", BASE_DIR / "instance"))


class Config:
    DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", INSTANCE_DIR / "logiclab.db"))
    SECURITY_LOG_PATH = Path(os.environ.get("SECURITY_LOG_PATH", INSTANCE_DIR / "security.log"))
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
    LAB_FLAG_SECRET = os.environ.get("LAB_FLAG_SECRET") or SECRET_KEY
    LAB_MODE = os.environ.get("LAB_MODE", "1") == "1"
    MAX_CONTENT_LENGTH = 128 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"


class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "logic-lab-test-secret"
    LAB_FLAG_SECRET = "logic-lab-test-flag-secret"
    SESSION_COOKIE_SECURE = False
