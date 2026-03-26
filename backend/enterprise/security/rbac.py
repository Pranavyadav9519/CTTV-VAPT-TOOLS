from functools import wraps
from flask import abort
from flask_jwt_extended import verify_jwt_in_request, get_jwt


def has_role(role: str) -> bool:
    try:
        claims = get_jwt()
        roles = claims.get('roles', []) or []
        return role in roles
    except Exception:
        return False


def roles_required(*required_roles):
    """Decorator to require at least one role from `required_roles` in JWT claims.

    Usage:
        @roles_required('admin', 'operator')
        def endpoint():
            ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            roles = set(claims.get('roles', []) or [])
            if not roles.intersection(set(required_roles)):
                abort(403)
            return fn(*args, **kwargs)

        return wrapper

    return decorator
