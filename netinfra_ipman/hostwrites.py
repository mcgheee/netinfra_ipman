"""Revision-bound host transactions for the single-worker application.

The process lock coordinates app writers, not external editors. External writers
must coordinate operationally; a revision check cannot provide a filesystem CAS.
"""
from __future__ import annotations

from dataclasses import dataclass
import difflib
import hashlib
import os
from pathlib import Path
import secrets
import stat
import tempfile
import threading
import time
from typing import Any

from . import gitops
from .netinfra import NetInfraError, _parse, build_inventory, serialize_netinfra


class HostWriteError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True)
class Preview:
    token: str
    revision: str
    proposed_revision: str
    diff: str
    findings: list[str]


@dataclass(frozen=True)
class WriteResult:
    revision: str
    backup: str
    git_status: str
    git_error: str = ""
    retry_token: str = ""


@dataclass(frozen=True)
class _Pending:
    actor: str
    settings: tuple[Any, ...]
    revision: str
    proposed: bytes
    expires: float
    message: str
    backup: str = ""


_WRITE_LOCK = threading.RLock()


def _revision(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _findings(content: bytes) -> list[str]:
    try:
        inventory = build_inventory(_parse(content))
        return [f"{item.path}: {item.message}" for item in inventory.diagnostics]
    except (NetInfraError, ValueError, TypeError, RecursionError):
        return ["Proposal is not a valid NetInfra YAML document"]


class HostWriteService:
    preview_ttl = 900
    max_pending = 256

    def __init__(self, config):
        self.config = config
        self._previews: dict[str, _Pending] = {}
        self._retries: dict[str, _Pending] = {}

    def _settings(self) -> tuple[Any, ...]:
        config = self.config
        return (str(Path(config.netinfra_path).resolve()),
                str(Path(config.backup_dir).resolve()), config.backup_retention,
                config.git_enabled, str(Path(config.git_repo_path).resolve()), config.git_branch)

    def _prune(self) -> None:
        now = time.monotonic()
        for pending in (self._previews, self._retries):
            for token in list(pending):
                if pending[token].expires <= now:
                    del pending[token]
            while len(pending) > self.max_pending:
                del pending[next(iter(pending))]

    def _get(self, pending: dict[str, _Pending], actor: str, token: str) -> _Pending:
        self._prune()
        entry = pending.get(token)
        if entry is None or entry.actor != actor:
            raise HostWriteError("Review token is invalid or expired; preview again", 409)
        if entry.settings != self._settings():
            raise HostWriteError("Settings changed; preview again", 409)
        return entry

    def _read(self) -> bytes:
        try:
            return Path(self.config.netinfra_path).read_bytes()
        except OSError as exc:
            raise HostWriteError("Cannot read the NetInfra file", 500) from exc

    def _check_revision(self, expected: str) -> bytes:
        content = self._read()
        if _revision(content) != expected:
            raise HostWriteError("NetInfra changed; refresh and preview again", 409)
        return content

    def preview(self, actor: str, revision: str, operation: str, payload: str = "",
                host_index: int | None = None) -> Preview:
        with _WRITE_LOCK:
            self._prune()
            before = self._check_revision(revision)
            try:
                data = _parse(before)
                if not isinstance(data, dict):
                    raise HostWriteError("NetInfra must be a mapping")
                hosts = data.setdefault("Hosts", [])
                if not isinstance(hosts, list):
                    raise HostWriteError("Hosts must be a list")
                if operation in {"update", "delete"}:
                    if type(host_index) is not int or not 0 <= host_index < len(hosts):
                        raise HostWriteError("Host index is invalid", 404)
                if operation in {"create", "update"}:
                    host = _parse(payload.encode("utf-8"))
                    if not isinstance(host, dict):
                        raise HostWriteError("Host YAML must be a mapping")
                    if operation == "create":
                        hosts.append(host)
                    else:
                        hosts[host_index] = host
                elif operation == "delete":
                    del hosts[host_index]
                elif operation == "import":
                    batch = _parse(payload.encode("utf-8"))
                    if isinstance(batch, dict):
                        if set(batch) != {"Hosts"}:
                            raise HostWriteError("Import wrapper must contain only Hosts")
                        batch = batch["Hosts"]
                    if not isinstance(batch, list) or not batch:
                        raise HostWriteError("Import YAML must be a nonempty host list or Hosts wrapper")
                    hosts.extend(batch)
                else:
                    raise HostWriteError("Unknown host operation")
                proposed = serialize_netinfra(data)
            except (NetInfraError, ValueError, TypeError, RecursionError) as exc:
                raise HostWriteError("Invalid host YAML proposal") from exc
            findings = _findings(proposed)
            token = ""
            if not findings:
                token = secrets.token_urlsafe(32)
                self._previews[token] = _Pending(actor, self._settings(), revision, proposed,
                    time.monotonic() + self.preview_ttl, f"Host {operation}")
                self._prune()
            diff = "".join(difflib.unified_diff(before.decode("utf-8").splitlines(keepends=True),
                proposed.decode("utf-8").splitlines(keepends=True), fromfile="NetInfra (current)",
                tofile="NetInfra (proposed)"))
            return Preview(token, revision, _revision(proposed), diff, findings)

    def _backup_directory(self, source: Path) -> Path:
        directory = Path(self.config.backup_dir).resolve()
        # Worktrees use a .git file, ordinary repositories a .git directory.
        roots = [ancestor for ancestor in source.parents if (ancestor / ".git").exists()]
        if self.config.git_enabled:
            roots.append(Path(self.config.git_repo_path).resolve())
        if any(directory == root or root in directory.parents for root in roots):
            raise HostWriteError("Backup directory must be outside the Git checkout")
        if directory == source or source in directory.parents:
            raise HostWriteError("Invalid backup directory")
        return directory

    def _backup(self, source: Path, content: bytes) -> Path:
        directory = self._backup_directory(source)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        prefix = f"ipman-{hashlib.sha256(str(source).encode()).hexdigest()[:16]}-"
        fd, name = tempfile.mkstemp(prefix=prefix, suffix=".bak", dir=directory)
        path = Path(name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            self._sync_directory(directory)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return path

    @staticmethod
    def _sync_directory(directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _replace(self, source: Path, proposed: bytes, revision: str) -> None:
        mode = stat.S_IMODE(source.stat().st_mode)
        fd, name = tempfile.mkstemp(prefix=f".{source.name}.", dir=source.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), mode)
                handle.write(proposed)
                handle.flush()
                os.fsync(handle.fileno())
            self._sync_directory(source.parent)
            self._check_revision(revision)
            os.replace(temporary, source)
            # Once replacement succeeds it must never be reported as unsaved.
            try:
                self._sync_directory(source.parent)
            except OSError:
                pass
        finally:
            temporary.unlink(missing_ok=True)

    def _retain(self, source: Path, backup: Path) -> None:
        prefix = f"ipman-{hashlib.sha256(str(source).encode()).hexdigest()[:16]}-"
        try:
            paths = sorted(backup.parent.glob(f"{prefix}*.bak"),
                           key=lambda item: item.stat().st_mtime_ns, reverse=True)
            for path in paths[max(1, self.config.backup_retention):]:
                path.unlink()
        except OSError:
            # Retention failure cannot turn an already-saved file into a failure.
            pass

    def apply(self, actor: str, token: str) -> WriteResult:
        with _WRITE_LOCK:
            entry = self._get(self._previews, actor, token)
            before = self._check_revision(entry.revision)
            findings = _findings(entry.proposed)
            if findings:
                raise HostWriteError("Proposal failed validation: " + "; ".join(findings))
            source = Path(self.config.netinfra_path).resolve()
            self._backup_directory(source)
            try:
                gitops.ensure_clean_checkout(self.config)
                backup = self._backup(source, before)
                self._replace(source, entry.proposed, entry.revision)
            except HostWriteError:
                raise
            except (OSError, RuntimeError) as exc:
                raise HostWriteError("File was not saved; check storage and Git checkout", 409) from exc
            del self._previews[token]
            revision = _revision(entry.proposed)
            self._retain(source, backup)
            if not self.config.git_enabled:
                return WriteResult(revision, str(backup), "disabled")
            try:
                self._check_revision(revision)
                gitops.commit_changes(self.config, entry.message, [str(source)])
            except (RuntimeError, HostWriteError) as exc:
                retry_token = secrets.token_urlsafe(32)
                self._retries[retry_token] = _Pending(actor, entry.settings, revision,
                    entry.proposed, time.monotonic() + self.preview_ttl, entry.message, str(backup))
                self._prune()
                return WriteResult(revision, str(backup), "failed", str(exc), retry_token)
            return WriteResult(revision, str(backup), "committed")

    def retry_commit(self, actor: str, token: str) -> WriteResult:
        with _WRITE_LOCK:
            entry = self._get(self._retries, actor, token)
            self._check_revision(entry.revision)
            try:
                gitops.retry_commit_changes(self.config, entry.message,
                    [str(Path(self.config.netinfra_path).resolve())])
            except RuntimeError as exc:
                return WriteResult(entry.revision, entry.backup, "failed", str(exc), token)
            del self._retries[token]
            return WriteResult(entry.revision, entry.backup, "committed")
