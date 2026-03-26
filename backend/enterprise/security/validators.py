from functools import wraps
from flask import request, jsonify
from pydantic import BaseModel, ValidationError
from typing import Optional


class ScanStartSchema(BaseModel):
    network_range: str
    scan_type: Optional[str] = 'full'
    notify: Optional[bool] = False
    idempotency_key: Optional[str] = None
    tenant_id: Optional[str] = None


def validate_schema(schema_class):
    """Flask decorator to validate JSON body against a pydantic schema.

    On success, attaches the parsed model to `request.validated`.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                payload = request.get_json() or {}
                validated = schema_class.parse_obj(payload)
                request.validated = validated
            except ValidationError as e:
                return jsonify({'success': False, 'errors': e.errors()}), 400
            return fn(*args, **kwargs)

        return wrapper

    return decorator
