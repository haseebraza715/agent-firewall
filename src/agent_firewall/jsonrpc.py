from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast


def request_key(request_id: Any) -> str:
    """Return a type-preserving, stable key for a JSON-RPC request id."""
    return json.dumps(request_id, sort_keys=True, separators=(",", ":"))


def decode_message(line: bytes) -> Mapping[str, Any] | None:
    """Decode one JSON-RPC line, returning None for malformed/non-object input."""
    try:
        message = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return cast(Mapping[str, Any], message) if isinstance(message, dict) else None


def encode_message(message: Mapping[str, Any]) -> bytes:
    """Encode one compact UTF-8 JSON-RPC line."""
    return (
        json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")
