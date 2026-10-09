"""In-process tracking for recently active authenticated users."""

from __future__ import annotations

import os
import threading
import time
from typing import Any

from app.core.config import settings


_last_seen: dict[str, float] = {}
_lock = threading.Lock()


def _idle_ttl_seconds() -> float:
    token_lifetime_seconds = float(settings.security.access_token_expire_minutes * 60)
    try:
        configured_ttl = float(os.getenv("SESSION_IDLE_TTL_SECONDS", str(token_lifetime_seconds)))
    except ValueError:
        return token_lifetime_seconds
    return max(configured_ttl, token_lifetime_seconds)


def touch(user_id: Any) -> None:
    if user_id is None:
        return
    with _lock:
        _last_seen[str(user_id)] = time.monotonic()


def is_active(user_id: int) -> bool:
    if user_id is None:
        return False
    now = time.monotonic()
    ttl = _idle_ttl_seconds()
    with _lock:
        last_seen = _last_seen.get(str(user_id))
        if last_seen is None:
            return False
        if now - last_seen >= ttl:
            _last_seen.pop(str(user_id), None)
            return False
        return True


def clear(user_id: Any) -> None:
    if user_id is None:
        return
    with _lock:
        _last_seen.pop(str(user_id), None)


def has_active_users() -> bool:
    now = time.monotonic()
    ttl = _idle_ttl_seconds()
    with _lock:
        expired = [user_id for user_id, last_seen in _last_seen.items() if now - last_seen >= ttl]
        for user_id in expired:
            del _last_seen[user_id]
        return bool(_last_seen)