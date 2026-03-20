"""
Structured JSON tracer for Overwatch V2 engagements.

Every agent action is emitted as a JSON log record with a unique trace_id,
engagement_id, timing information, and token/cost accounting.
"""
from __future__ import annotations

import json
import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Optional


# ──────────────────────────── JSON formatter ────────────────────────────

class _JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON for structured log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        # Attach any extra fields passed via the extra= kwarg
        for key, value in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
            }:
                if not key.startswith("_"):
                    payload[key] = value
        return json.dumps(payload, default=str)


def _build_json_logger(name: str) -> logging.Logger:
    """Return a logger that emits JSON to stdout."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(logging.DEBUG)
    return logger


# ──────────────────────────── Tracer ────────────────────────────

class Tracer:
    """
    Emit structured JSON trace events for a single engagement.

    Usage::

        tracer = Tracer(engagement_id="42")
        tracer.trace(
            event_type="tool_call",
            agent_id="recon-abc123",
            action="nmap_scan",
            target="192.168.1.0/24",
            result={"hosts_up": 12},
            tokens=350,
            cost=0.0015,
            duration_ms=4200,
        )

        with tracer.span("recon_phase"):
            # ... do work ...
            pass
    """

    def __init__(
        self,
        engagement_id: str,
        logger_name: str = "overwatch",
    ) -> None:
        self.engagement_id = str(engagement_id)
        self._logger = _build_json_logger(logger_name)

    # ── Core trace method ──────────────────────────────────────────

    def trace(
        self,
        event_type: str,
        agent_id: Optional[str] = None,
        action: Optional[str] = None,
        target: Optional[str] = None,
        result: Optional[Dict[str, Any]] = None,
        tokens: int = 0,
        cost: float = 0.0,
        duration_ms: int = 0,
    ) -> None:
        """
        Emit a single structured trace event.

        Args:
            event_type:   Category of event (e.g. ``tool_call``, ``finding``,
                          ``agent_spawned``, ``engagement_start``).
            agent_id:     UUID of the agent emitting the event.
            action:       Specific action performed (e.g. ``nmap_scan``).
            target:       Host / URL the action targeted.
            result:       Arbitrary result payload (kept as-is in the log).
            tokens:       Claude API tokens consumed for this event.
            cost:         Dollar cost incurred for this event.
            duration_ms:  Wall-clock time in milliseconds.
        """
        self._logger.info(
            "trace",
            extra={
                "trace_id": str(uuid.uuid4()),
                "engagement_id": self.engagement_id,
                "event_type": event_type,
                "agent_id": agent_id,
                "action": action,
                "target": target,
                "result": result,
                "tokens": tokens,
                "cost": cost,
                "duration_ms": duration_ms,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            },
        )

    # ── Span context manager ───────────────────────────────────────

    @contextmanager
    def span(self, name: str) -> Generator[None, None, None]:
        """
        Context manager that records the start and end of a named span.

        Emits two events: ``span_start`` and ``span_end`` with elapsed
        ``duration_ms`` on exit (whether successful or not).

        Example::

            with tracer.span("webapp_enumeration"):
                await agent.enumerate_endpoints()
        """
        span_id = str(uuid.uuid4())
        start_ns = _monotonic_ns()

        self._logger.info(
            "span_start",
            extra={
                "trace_id": span_id,
                "engagement_id": self.engagement_id,
                "event_type": "span_start",
                "span_name": name,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            },
        )
        try:
            yield
        finally:
            duration_ms = (_monotonic_ns() - start_ns) // 1_000_000
            self._logger.info(
                "span_end",
                extra={
                    "trace_id": span_id,
                    "engagement_id": self.engagement_id,
                    "event_type": "span_end",
                    "span_name": name,
                    "duration_ms": duration_ms,
                    "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                },
            )


# ──────────────────────────── helpers ────────────────────────────

def _monotonic_ns() -> int:
    """Return monotonic nanoseconds (Python 3.7+)."""
    import time
    return time.monotonic_ns()
