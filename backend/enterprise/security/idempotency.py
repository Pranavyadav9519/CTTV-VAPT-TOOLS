import threading
import time
from functools import wraps
from typing import Callable

from flask import request, current_app, jsonify
import uuid


# ---------------------------------------------------------------------------
# In-memory fallback store (used when Redis is not configured)
# NOTE: This fallback is suitable for development or single-worker deployments
# only. It does not synchronize across multiple processes (e.g., Gunicorn
# workers). In production, configure REDIS_URL for correct behaviour.
# ---------------------------------------------------------------------------
_mem_lock = threading.Lock()
_mem_store: dict[str, tuple[str, float]] = {}  # key -> (value, expires_at)
_MEM_TTL = 3600  # seconds


def _mem_set_nx(key: str, value: str, ex: int) -> bool:
    """Set key only if it doesn't exist. Returns True if set, False if already existed."""
    now = time.time()
    with _mem_lock:
        # Evict expired entry if present
        existing = _mem_store.get(key)
        if existing and existing[1] < now:
            del _mem_store[key]
        if key in _mem_store:
            return False
        _mem_store[key] = (value, now + ex)
        return True


def _mem_get(key: str) -> str | None:
    now = time.time()
    with _mem_lock:
        entry = _mem_store.get(key)
        if not entry:
            return None
        if entry[1] < now:
            del _mem_store[key]
            return None
        return entry[0]


def _mem_set(key: str, value: str, ex: int) -> None:
    now = time.time()
    with _mem_lock:
        _mem_store[key] = (value, now + ex)


def _mem_delete(key: str) -> None:
    with _mem_lock:
        _mem_store.pop(key, None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(success: bool, data: dict | None, code: str | None, message: str | None, request_id: str):
    return (
        jsonify(
            {
                "success": success,
                "data": data if data is not None else None,
                "error": {"code": code, "message": message} if code else None,
                "request_id": request_id,
            }
        ),
        200 if success else 400,
    )


def _get_redis_client():
    """Try to get a Redis client from the app config. Returns None if unavailable."""
    try:
        redis_url = current_app.config.get("REDIS_URL")
        if not redis_url:
            return None
        from redis import Redis
        client = Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=2)
        client.ping()
        return client
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------

def idempotency_required(fn: Callable):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        key = request.headers.get("Idempotency-Key")
        if not key:
            return _make_response(False, None, "idempotency.missing", "Idempotency-Key header required", request_id)

        redis_key = f"idempotency:{key}"

        client = _get_redis_client()

        if client is not None:
            # Redis path
            existing = client.get(redis_key)
            if existing:
                return (
                    jsonify({"success": True, "data": {"idempotency_key": key, "result": existing}, "error": None, "request_id": request_id}),
                    200,
                )
            set_result = client.set(redis_key, "IN_PROGRESS", nx=True, ex=3600)
            if not set_result:
                return _make_response(False, None, "idempotency.conflict", "Idempotency key already in use", request_id)
            try:
                response = fn(*args, **kwargs)
                try:
                    client.set(redis_key, str(response), ex=3600)
                except Exception:
                    current_app.logger.warning("Failed to persist idempotency result in Redis")
                return response
            except Exception as exc:
                client.delete(redis_key)
                current_app.logger.exception("Idempotency handler error: %s", exc)
                raise
        else:
            # In-memory fallback
            existing = _mem_get(redis_key)
            if existing:
                return (
                    jsonify({"success": True, "data": {"idempotency_key": key, "result": existing}, "error": None, "request_id": request_id}),
                    200,
                )
            if not _mem_set_nx(redis_key, "IN_PROGRESS", _MEM_TTL):
                return _make_response(False, None, "idempotency.conflict", "Idempotency key already in use", request_id)
            try:
                response = fn(*args, **kwargs)
                try:
                    _mem_set(redis_key, str(response), _MEM_TTL)
                except Exception:
                    pass
                return response
            except Exception as exc:
                _mem_delete(redis_key)
                current_app.logger.exception("Idempotency handler error: %s", exc)
                raise

    return wrapper
