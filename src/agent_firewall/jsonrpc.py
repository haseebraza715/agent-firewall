from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast


def request_key(request_id: Any) -> str:
    """Return a type-preserving, stable key for a JSON-RPC request id."""
    return json.dumps(request_id, sort_keys=True, separators=(",", ":"))


class DuplicateKeys(ValueError):
    """The line parses as JSON but an object contains duplicate keys."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeys(f"duplicate key {key!r}")
        result[key] = value
    return result


def decode_message(line: bytes) -> Mapping[str, Any] | None:
    """Decode one JSON-RPC line, returning None for malformed/non-object input.

    Raises ``ValueError`` for input that parses but must not be trusted to any
    single interpretation: objects with duplicate keys (a lenient parser on
    the other side could act on a different view of the message than the one
    this process decoded) and lines nested too deeply to build safely.
    Callers route both to their fail-closed path.
    """
    try:
        message = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
    except RecursionError as exc:
        raise ValueError("JSON message is nested too deeply") from exc
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return cast(Mapping[str, Any], message) if isinstance(message, dict) else None


def encode_message(message: Mapping[str, Any]) -> bytes:
    """Encode one compact UTF-8 JSON-RPC line.

    Raises ``ValueError`` when the message is nested too deeply to encode.
    """
    try:
        encoded = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
    except RecursionError as exc:
        raise ValueError("JSON message is nested too deeply") from exc
    return (encoded + "\n").encode("utf-8")
