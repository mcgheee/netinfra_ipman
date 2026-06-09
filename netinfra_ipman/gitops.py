from __future__ import annotations

import subprocess
from pathlib import Path

from .config import AppConfig


def git(args: list[str], cwd: str | Path) -> str:
    return subprocess.check_output(["git", *args], cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()


def ensure_clean_checkout(config: AppConfig) -> None:
    if not config.git_enabled:
        return
    repo = Path(config.git_repo_path)
    git(["checkout", config.git_branch], repo)
    status = git(["status", "--porcelain"], repo)
    if status:
        raise RuntimeError("Git working tree is not clean")


def commit_changes(config: AppConfig, message: str, paths: list[str]) -> None:
    if not config.git_enabled:
        return
    repo = Path(config.git_repo_path)
    git(["add", *paths], repo)
    git(["commit", "-m", message], repo)
    if config.git_push:
        git(["push", config.git_remote, config.git_branch], repo)
