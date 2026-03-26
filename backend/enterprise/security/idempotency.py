from functools import wraps
from typing import Callable
from flask import request, current_app, jsonify
from app.extensions import init_redis
import uuid


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


def idempotency_required(fn: Callable):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        key = request.headers.get("Idempotency-Key")
        tenant_id = request.headers.get("X-Tenant-ID")
        if not key:
            return _make_response(False, None, "idempotency.missing", "Idempotency-Key required", request_id)
        if not tenant_id:
            return _make_response(False, None, "tenant.missing", "Tenant-ID required", request_id)

        client = init_redis(current_app)
        if client is None:
            return _make_response(False, None, "redis.unavailable", "Redis not configured", request_id)

        redis_key = f"tenant:{tenant_id}:idempotency:{key}"
        existing = client.get(redis_key)
        if existing:
            return (
                jsonify(
                    {
                        "success": True,
                        "data": {"idempotency_key": key, "result": existing},
                        "error": None,
                        "request_id": request_id,
                    }
                ),
                200,
            )

        # atomic set if not exists
        if hasattr(client, "set"):
            set_result = client.set(redis_key, "IN_PROGRESS", ex=3600)
            if not set_result:
                return _make_response(False, None, "idempotency.conflict", "Idempotency key already in use", request_id)
        else:
            client.set(redis_key, "IN_PROGRESS", ex=3600)

        try:
            response = fn(*args, **kwargs)
            # store result summary for idempotency lookups
            try:
                client.set(redis_key, str(response), ex=3600)
            except Exception:
                current_app.logger.warning("Failed to persist idempotency result")
            return response
        except Exception as exc:
            client.delete(redis_key)
            current_app.logger.exception("Idempotency handler error: %s", exc)
            raise

    return wrapper
