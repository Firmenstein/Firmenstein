"""Lossless diagnostic text with recognizable credentials removed."""
import os
import re


def diagnostic_reason(error: BaseException) -> str:
    text = f"{type(error).__name__}: {error}"
    for name, secret in os.environ.items():
        if len(secret) >= 8 and any(key in name.upper() for key in ("TOKEN", "SECRET", "PASSWORD", "API_KEY")):
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)(bearer\s+)[^\s\"',;]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)((?:api[_-]?key|authorization|\w*token|password|session_id)[\"']?\s*[=:]\s*[\"']?)[^\s\"',;&]+", r"\1[REDACTED]", text)
    text = re.sub(r"(https?://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", text)
    return re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", "[REDACTED]", text)
