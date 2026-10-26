from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .config import AppConfig


def git(args: list[str], cwd: str | Path) -> str:
    """Run local Git without exposing command output or inherited Git routing."""
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, env=environment, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise RuntimeError("Local Git operation failed; check repository configuration and permissions") from None
    return result.stdout


def _checkout(config: AppConfig) -> tuple[Path, str]:
    repo = Path(config.git_repo_path).resolve()
    root = Path(git(["rev-parse", "--show-toplevel"], repo).strip()).resolve()
    if root != repo:
        raise RuntimeError("git_repo_path must be the Git checkout root")
    source = Path(config.netinfra_path).resolve()
    if not source.is_relative_to(repo) or source == repo or ".git" in source.relative_to(repo).parts:
        raise RuntimeError("NetInfra source must be a file inside the configured Git checkout")
    backup = Path(config.backup_dir).resolve()
    if not source.is_file():
        raise RuntimeError("NetInfra source must be an existing file")
    source_root = Path(git(["rev-parse", "--show-toplevel"], source.parent).strip()).resolve()
    if source_root != repo:
        raise RuntimeError("NetInfra source belongs to a different Git checkout")
    if backup.is_relative_to(repo):
        raise RuntimeError("backup_dir must be outside the Git checkout")
    branch = git(["symbolic-ref", "--quiet", "--short", "HEAD"], repo).strip()
    if branch != config.git_branch:
        raise RuntimeError("Git checkout is not on the configured branch; switch branches outside the application")
    return repo, source.relative_to(repo).as_posix()


def _target_status(repo: Path, target: str) -> None:
    # NUL-delimited porcelain preserves spaces, quotes and newlines in filenames.
    entries = git(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"], repo).split("\0")
    for entry in entries:
        if not entry:
            continue
        if entry[:2] not in {" M", "M ", "MM"} or entry[3:] != target:
            raise RuntimeError("Git working tree contains changes other than the intended source modification")


def ensure_clean_checkout(config: AppConfig) -> None:
    """Validate the exact repository and current branch, without switching it."""
    if not config.git_enabled:
        return
    repo, _ = _checkout(config)
    if git(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"], repo):
        raise RuntimeError("Git working tree is not clean")


def commit_changes(config: AppConfig, message: str, paths: list[str]) -> None:
    """Commit only the saved NetInfra path; never push or include other changes."""
    if not config.git_enabled:
        return
    repo, target = _checkout(config)
    if len(paths) != 1 or Path(paths[0]).resolve() != Path(config.netinfra_path).resolve():
        raise RuntimeError("Git commit must include only the configured NetInfra source")
    _target_status(repo, target)
    git(["add", "--", target], repo)
    _target_status(repo, target)
    git(["commit", "--only", "-m", message, "--", target], repo)


def retry_commit_changes(config: AppConfig, message: str, paths: list[str]) -> None:
    """Retry a saved file, accepting only its modified/staged state."""
    commit_changes(config, message, paths)
