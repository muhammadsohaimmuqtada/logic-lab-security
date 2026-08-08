import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = Path(os.environ.get("LOGICLAB_INSTANCE", BASE_DIR / "instance"))


def _load_or_create_secret(env_name: str, filename: str) -> str:
    configured = (os.environ.get(env_name) or "").strip()
    if configured:
        return configured

    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    target = INSTANCE_DIR / filename
    if target.exists():
        value = target.read_text(encoding="utf-8").strip()
        if value:
            return value

    value = secrets.token_urlsafe(48)
    tmp = INSTANCE_DIR / f".{filename}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    tmp.write_text(value + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
        try:
            os.link(tmp, target)
        except FileExistsError:
            pass
    finally:
        tmp.unlink(missing_ok=True)

    persisted = target.read_text(encoding="utf-8").strip()
    if not persisted:
        raise RuntimeError(f"Unable to initialize {env_name}")
    return persisted


class Config:
    DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", INSTANCE_DIR / "logiclab.db"))
    SECRET_KEY = _load_or_create_secret("FLASK_SECRET_KEY", ".flask-secret")
    LAB_FLAG_SECRET = _load_or_create_secret("LAB_FLAG_SECRET", ".flag-secret")
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
