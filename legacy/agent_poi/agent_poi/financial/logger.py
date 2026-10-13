"""Structured Enterprise Audit Logger for Financial Agent Operations.

Provides consistent logging adhering to standard Python logging,
avoiding raw print calls in production modules.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class StructuredAuditFormatter(logging.Formatter):
    """Formats log records as structured JSON for enterprise audit ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "audit_event"):
            log_obj["audit_event"] = record.audit_event
        if hasattr(record, "extra_data"):
            log_obj["extra_data"] = record.extra_data
        return json.dumps(log_obj)


def get_financial_logger(name: str = "agent_poi.financial") -> logging.Logger:
    """Retrieve configured logger with structured audit handler."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def log_audit_event(
    logger: logging.Logger,
    event_type: str,
    message: str,
    extra_data: Optional[Dict[str, Any]] = None,
    level: int = logging.INFO,
) -> None:
    """Log an explicit audit event for invariant checks and tool dispatches."""
    extra = {"audit_event": event_type, "extra_data": extra_data or {}}
    logger.log(level, f"[{event_type}] {message}", extra=extra)
