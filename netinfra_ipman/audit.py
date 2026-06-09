from __future__ import annotations

import json
import logging
import logging.handlers
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import AppConfig


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
        self.logger = logging.getLogger("netinfra_ipman.audit")
        self.logger.handlers.clear()
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(message)s")
        if config.audit_to_file:
            path = Path(config.audit_log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(path, encoding="utf-8")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        if config.audit_to_syslog:
            handler = logging.handlers.SysLogHandler(address="/dev/log")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        if not self.logger.handlers:
            self.logger.addHandler(logging.NullHandler())

    def record(self, user: str, source_ip: str, action: str, summary: str, before: Any = None, after: Any = None) -> None:
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            user=user,
            source_ip=source_ip,
            action=action,
            summary=summary,
            before=before,
            after=after,
        )
        self.logger.info(json.dumps(asdict(event), sort_keys=True))
