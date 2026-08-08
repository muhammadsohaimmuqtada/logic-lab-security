from pathlib import Path


def test_app_contains_no_shell_execution_primitives():
    root = Path(__file__).resolve().parents[1] / "app"
    source = "\n".join(p.read_text(encoding="utf-8") for p in root.glob("*.py"))
    forbidden = ["os.system(", "subprocess.", "shell=True", "eval(", "exec("]
    for token in forbidden:
        assert token not in source


def test_lab_server_binds_loopback_in_entrypoint():
    source = (Path(__file__).resolve().parents[1] / "app" / "app.py").read_text(encoding="utf-8")
    assert 'host="127.0.0.1"' in source
