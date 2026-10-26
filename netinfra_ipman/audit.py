from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
import json
import logging
import logging.handlers
import os
from pathlib import Path
import re
from typing import Any

from .config import AppConfig, SECRET_FIELDS


_REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(r"password|passwd|secret|token|authorization|cookie|credential|private.?key|pkce|verifier", re.I)
_SECRET_ASSIGNMENT = re.compile(
    r"\b(password|passwd|[\w.-]*secret|[\w.-]*token|authorization|cookie|credential|code_verifier)"
    r"(\s*[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)", re.I,
)
_BEARER = re.compile(r"\bBearer\s+[^\s,;]+", re.I)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def source_ip(request: Any, config: AppConfig) -> str:
    """Honor forwarding only through an explicitly trusted, valid proxy chain."""
    try:
        peer = ip_address(request.client.host)
    except (AttributeError, ValueError):
        return "unknown"
    trusted = tuple(ip_network(value, strict=True) for value in config.trusted_proxies)
    if not any(peer in network for network in trusted):
        return str(peer)
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return str(peer)
    try:
        # A malformed element invalidates the entire header, including its prefix.
        chain = [ip_address(value.strip()) for value in forwarded.split(",")]
    except ValueError:
        return str(peer)
    current = peer
    for address in reversed(chain):
        if not any(current in network for network in trusted):
            break
        current = address
    return str(current)


class _PrivateRotatingHandler(logging.handlers.RotatingFileHandler):
    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.fchmod(fd, 0o600)
            return os.fdopen(fd, self.mode, encoding=self.encoding, errors=self.errors)
        except BaseException:
            os.close(fd)
            raise


@dataclass
class AuditEvent:
    timestamp: str
    user: str
    source_ip: str
    action: str
    summary: str
    before: Any = None
    after: Any = None


class AuditLogger:
    def __init__(self, config: AppConfig):
        self.config = config
        self.logger = logging.Logger("netinfra_ipman.audit")
        self.logger.propagate = False
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(message)s")
        if config.audit_to_file:
            path = Path(config.audit_log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = _PrivateRotatingHandler(
                path, maxBytes=config.audit_max_bytes,
                backupCount=config.audit_backup_count, encoding="utf-8",
            )
            # Respect reduced retention and secure surviving legacy backups too.
            prefix = path.name + "."
            for backup in path.parent.iterdir():
                suffix = backup.name.removeprefix(prefix)
                if backup.name.startswith(prefix) and suffix.isdecimal():
                    if int(suffix) > config.audit_backup_count:
                        backup.unlink()
                    else:
                        backup.chmod(0o600)
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        if config.audit_to_syslog:
            handler = logging.handlers.SysLogHandler(address="/dev/log")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        if not self.logger.handlers:
            self.logger.addHandler(logging.NullHandler())

    def close(self) -> None:
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            handler.close()

    def _redact(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {
                self._redact(str(key)): _REDACTED if _SECRET_KEY.search(str(key)) else self._redact(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self._redact(item) for item in value]
        if isinstance(value, str):
            for name in SECRET_FIELDS:
                secret = getattr(self.config, name)
                if secret:
                    value = value.replace(secret, _REDACTED)
            value = _SECRET_ASSIGNMENT.sub(lambda match: match[1] + match[2] + _REDACTED, value)
            value = _BEARER.sub("Bearer " + _REDACTED, value)
            return _JWT.sub(_REDACTED, value)
        return value

    def record(self, user: str, source_ip: str, action: str, summary: str, before: Any = None, after: Any = None) -> None:
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            user=user, source_ip=source_ip, action=action, summary=summary,
            before=before, after=after,
        )
        payload = self._redact(asdict(event))
        for name in ("before", "after"):
            if isinstance(payload[name], str):
                # Never record complete YAML/text snapshots containing unknown secrets.
                payload[name] = _REDACTED
        message = json.dumps(payload, sort_keys=True)
        # One oversized event must not defeat the on-disk storage bound.
        if len(message.encode("utf-8")) + 1 >= self.config.audit_max_bytes:
            payload.update(before=None, after=None, summary="Oversized audit detail omitted")
            for name in ("user", "source_ip", "action"):
                payload[name] = str(payload[name])[:16]
            message = json.dumps(payload, sort_keys=True)
        self.logger.info(message)

    def recent_events(self, limit: int = 100) -> list[dict]:
        """Return bounded active-log history, never raw legacy credential payloads."""
        if not self.config.audit_to_file or limit <= 0:
            return []
        events: deque[dict] = deque(maxlen=min(limit, 1000))
        try:
            with Path(self.config.audit_log_file).open(encoding="utf-8") as handle:
                for line in handle:
                    try:
                        event = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    if not isinstance(event, dict):
                        continue
                    # Old logs contain complete YAML documents as scalar snapshots.
                    for name in ("before", "after"):
                        if name in event and not isinstance(event[name], (dict, list, type(None))):
                            event[name] = _REDACTED
                    events.append(self._redact(event))
        except (OSError, UnicodeError):
            return []
        return list(events)
