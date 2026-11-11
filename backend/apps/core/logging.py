"""Logs técnicos en JSON con redacción de datos sensibles (R14; Principio VI)."""

from __future__ import annotations

import json
import logging
import re

from apps.core.middleware import _request_id

SENSITIVE_KEYS = ("password", "token", "secret", "code", "otp", "session", "cookie", "authorization")
_KV_RE = re.compile(
    r"(?i)\b(" + "|".join(SENSITIVE_KEYS) + r")([\w-]*)\s*[=:]\s*(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
REDACTED = "[REDACTADO]"


def redact(text: str) -> str:
    """Sustituye el valor de cualquier par clave=valor o clave: valor cuya clave sea sensible."""
    return _KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}={REDACTED}", text)


class RedactionFilter(logging.Filter):
    """Redacta el mensaje y los argumentos de cada registro antes de emitirlo."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - nunca romper el logging
            message = str(record.msg)
        record.msg = redact(message)
        record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        request_id = _request_id.get()
        payload = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": str(request_id) if request_id else None,
        }
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)
