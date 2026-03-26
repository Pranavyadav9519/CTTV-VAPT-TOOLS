from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
import os
import uuid
from typing import Any, Dict

auth_bp = Blueprint("auth", __name__)


def _response(success: bool, data: Dict[str, Any] | None, code: str | None, message: str | None, request_id: str, status: int):
    payload = {
        "success": success,
        "data": data if data is not None else None,
        "error": {"code": code, "message": message} if code else None,
        "request_id": request_id,
    }
    return jsonify(payload), status


@auth_bp.route("/token", methods=["POST"])
def token() -> Any:
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    body = request.get_json() or {}
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "").strip()

    admin_user = os.getenv("ADMIN_USER")
    admin_pass = os.getenv("ADMIN_PASS")
    if not admin_user or not admin_pass:
        return _response(False, None, "auth.not_configured", "Authentication is not configured on this server", request_id, 500)

    if not username or not password:
        return _response(False, None, "auth.missing_credentials", "Username and password are required", request_id, 400)

    if username != admin_user or password != admin_pass:
        return _response(False, None, "auth.invalid_credentials", "Invalid username or password", request_id, 401)

    roles_env = os.getenv("ADMIN_ROLES", "admin")
    roles = [r.strip() for r in roles_env.split(",") if r.strip()]

    identity = {"username": username, "roles": roles}
    token = create_access_token(identity=identity)

    data = {"access_token": token, "token_type": "bearer"}
    return _response(True, data, None, None, request_id, 200)
