"""Strip trailing whitespace from all .py files under the workspace.

Run from the repository root (this script expects to be run at the workspace root).
"""
from pathlib import Path


def strip_file(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    new_lines = [line.rstrip() for line in text.splitlines()]
    new_text = "\n".join(new_lines) + ("\n" if text.endswith("\n") else "")
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")
        return True
    return False


def main():
    root = Path(__file__).resolve().parents[1]
    ignore_dirs = {".venv", "venv", "env", "__pycache__", ".git"}
    exts = {".py", ".html", ".js", ".css", ".md", ".json", ".sql", ".yml", ".yaml", ".ini", ".cfg", ".txt"}
    py_files = [
        p
        for p in root.rglob("*")
        if p.suffix.lower() in exts and not any(part in ignore_dirs for part in p.parts)
    ]
    changed = 0
    for p in py_files:
        if strip_file(p):
            print(f"Stripped trailing whitespace: {p}")
            changed += 1
    print(f"Done. Files changed: {changed}")


if __name__ == "__main__":
    main()
