#!/usr/bin/env python3
"""
Scan repository files and append a hidden copyright claim where safe.

Rules:
- If file already contains the claim, skip.
- If file type supports comments, append a commented claim at the end.
- For formats that don't support comments (e.g., JSON), create a sidecar file
  named ".copyrights" in the same directory listing the file and claim.

Run from repository root: `python scripts/add_copyright_claims.py`
"""
from pathlib import Path
import os
import sys

CLAIM = "Copyright (c) Liam Suorsa and Mika Suorsa"

COMMENTERS = {
    '.py': lambda s: f"# {s}",
    '.sh': lambda s: f"# {s}",
    '.ps1': lambda s: f"# {s}",
    '.env': lambda s: f"# {s}",
    '.yml': lambda s: f"# {s}",
    '.yaml': lambda s: f"# {s}",
    '.toml': lambda s: f"# {s}",
    '.ini': lambda s: f"# {s}",
    '.cfg': lambda s: f"# {s}",
    '.md': lambda s: f"<!-- {s} -->",
    '.html': lambda s: f"<!-- {s} -->",
    '.htm': lambda s: f"<!-- {s} -->",
    '.css': lambda s: f"/* {s} */",
    '.js': lambda s: f"/* {s} */",
    '.jsx': lambda s: f"/* {s} */",
    '.ts': lambda s: f"/* {s} */",
    '.tsx': lambda s: f"/* {s} */",
    '.sql': lambda s: f"-- {s}",
    '.txt': lambda s: f"# {s}",
    '.rst': lambda s: f".. {s}",
}

SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', 'instance', 'logs', 'deploy'}

ROOT = Path('.').resolve()

def is_binary(path: Path) -> bool:
    try:
        with path.open('rb') as f:
            chunk = f.read(4096)
            return b'\0' in chunk
    except Exception:
        return True

def commenter_for(path: Path):
    ext = path.suffix.lower()
    if ext in COMMENTERS:
        return COMMENTERS[ext]
    name = path.name
    if name.lower() in ('dockerfile', 'makefile'):
        return lambda s: f"# {s}"
    return None

def append_claim(path: Path, comment_func):
    try:
        with path.open('a', encoding='utf-8', errors='ignore') as f:
            f.write('\n')
            f.write(comment_func(CLAIM))
            f.write('\n')
        return True
    except Exception as e:
        print(f"Failed to append to {path}: {e}")
        return False

def add_sidecar(path: Path):
    sidecar = path.parent / '.copyrights'
    try:
        with sidecar.open('a', encoding='utf-8', errors='ignore') as f:
            f.write(f"{path.name}: {CLAIM}\n")
        return True
    except Exception as e:
        print(f"Failed to write sidecar for {path}: {e}")
        return False

def main():
    modified = []
    sidecars = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk('.'):
        # prune skip dirs
        parts = Path(dirpath).parts
        if any(p in SKIP_DIRS for p in parts):
            continue
        for fname in filenames:
            path = Path(dirpath) / fname
            # skip symlinks
            try:
                if path.is_symlink():
                    continue
            except Exception:
                continue
            # skip hidden git or binary files
            if is_binary(path):
                continue
            scanned += 1
            try:
                text = path.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue
            if CLAIM in text:
                continue
            comment_func = commenter_for(path)
            if comment_func:
                ok = append_claim(path, comment_func)
                if ok:
                    modified.append(str(path))
            else:
                ok = add_sidecar(path)
                if ok:
                    sidecars.append(str(path))

    print(f"Scanned files: {scanned}")
    print(f"Modified files: {len(modified)}")
    for p in modified[:200]:
        print(f" M {p}")
    if sidecars:
        print(f"Created/Updated sidecars for: {len(sidecars)} files (example list):")
        for p in sidecars[:200]:
            print(f" S {p}")

if __name__ == '__main__':
    main()
