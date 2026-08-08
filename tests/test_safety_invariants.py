from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_app_contains_no_shell_execution_primitives():
    root = ROOT / "app"
    source = "\n".join(p.read_text(encoding="utf-8") for p in root.glob("*.py"))
    forbidden = ["os.system(", "subprocess.", "shell=True", "eval(", "exec("]
    for token in forbidden:
        assert token not in source


def test_lab_server_binds_loopback_in_entrypoint():
    source = (ROOT / "app" / "app.py").read_text(encoding="utf-8")
    assert 'host="127.0.0.1"' in source


def test_container_is_published_only_on_loopback():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert '"127.0.0.1:8000:8000"' in compose
    assert "GUNICORN_BIND: 0.0.0.0:8000" in compose


def test_repository_contains_no_known_runtime_secret_defaults():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "local-docker-training-secret-change-me" not in compose
    assert "FLASK_SECRET_KEY=\n" in env_example
    assert "LAB_FLAG_SECRET=\n" in env_example
