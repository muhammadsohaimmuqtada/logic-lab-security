import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = Path(os.environ.get("LOGICLAB_INSTANCE", BASE_DIR / "instance"))


def _persistent_secret(env_name: str, path: Path) -> str:
    configured = os.environ.get(env_name)
    if configured:
        return configured

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        existing = ""
    if existing:
        return existing

    generated = secrets.token_hex(32)
    try:
        path.write_text(generated, encoding="utf-8")
        path.chmod(0o600)
    except OSError:
        # Read-only deployments still get an unpredictable process-local secret.
        # Operators that need persistence should provide the environment variable.
        pass
    return generated


def _secret_path(filename: str) -> Path:
    database = Path(os.environ.get("DATABASE_PATH", INSTANCE_DIR / "logiclab.db"))
    return database.parent / filename


class Config:
    DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", INSTANCE_DIR / "logiclab.db"))
    SECURITY_LOG_PATH = Path(os.environ.get("SECURITY_LOG_PATH", INSTANCE_DIR / "security.log"))
    SECRET_KEY = _persistent_secret("FLASK_SECRET_KEY", _secret_path(".flask-secret"))
    LAB_FLAG_SECRET = _persistent_secret("LAB_FLAG_SECRET", _secret_path(".lab-flag-secret"))
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
