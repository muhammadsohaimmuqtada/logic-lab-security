from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dist" / "logic-lab-learner.zip"
EXCLUDED_FILES = {"docs/INSTRUCTOR_GUIDE.md", "challenges/manifest.yml", "tests/test_challenge_contracts.py", "tests/test_expansion_contracts.py"}
EXCLUDED_PARTS = {".git", ".venv", "__pycache__", "instance", "dist"}


def include(path: Path) -> bool:
    rel = path.relative_to(ROOT).as_posix()
    if any(part in EXCLUDED_PARTS for part in path.parts):
        return False
    if rel in EXCLUDED_FILES:
        return False
    return path.is_file()


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if OUT.exists():
        OUT.unlink()
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in ROOT.rglob("*"):
            if include(path):
                zf.write(path, path.relative_to(ROOT))
    print(OUT)


if __name__ == "__main__":
    main()
