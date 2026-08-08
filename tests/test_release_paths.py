from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_compose_does_not_ship_fixed_crypto_secrets():
    source = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "local-docker-training-secret-change-me" not in source
    assert "FLASK_SECRET_KEY:" not in source
    assert "LAB_FLAG_SECRET:" not in source
    assert 'GUNICORN_BIND: "0.0.0.0:8000"' in source
    assert '"127.0.0.1:8000:8000"' in source


def test_gunicorn_defaults_to_loopback_outside_container():
    source = (ROOT / "gunicorn.conf.py").read_text(encoding="utf-8")
    assert 'os.environ.get("GUNICORN_BIND", "127.0.0.1:8000")' in source


def test_env_example_does_not_ship_placeholder_secrets():
    source = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "generate-a-long-random-value" not in source
    assert "generate-a-separate-random-flag-secret" not in source
    assert "FLASK_SECRET_KEY=\n" in source
    assert "LAB_FLAG_SECRET=\n" in source
