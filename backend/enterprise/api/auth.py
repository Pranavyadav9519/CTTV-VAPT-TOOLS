from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
import bcrypt
import hmac
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


def _verify_password(plain_password: str, stored_credential: str) -> bool:
    """Verify a password against a stored credential.

    Supports two formats for ADMIN_PASS:
      1. bcrypt hash (starts with ``$2b$`` / ``$2a$``) — compared via bcrypt.
         Generate with: python -c "import bcrypt; print(bcrypt.hashpw(b'mypass', bcrypt.gensalt()).decode())"
      2. Plain string (legacy / dev) — compared via constant-time ``hmac.compare_digest``
         to prevent timing attacks.
    """
    if stored_credential.startswith(("$2b$", "$2a$")):
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            stored_credential.encode("utf-8"),
        )
    return hmac.compare_digest(plain_password, stored_credential)


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

    if not hmac.compare_digest(username, admin_user) or not _verify_password(password, admin_pass):
        return _response(False, None, "auth.invalid_credentials", "Invalid username or password", request_id, 401)

    roles_env = os.getenv("ADMIN_ROLES", "admin")
    roles = [r.strip() for r in roles_env.split(",") if r.strip()]

    identity = {"username": username, "roles": roles}
    access_token = create_access_token(identity=identity)

    data = {"access_token": access_token, "token_type": "bearer"}
    return _response(True, data, None, None, request_id, 200)
