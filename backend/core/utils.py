"""
Utility Functions and Helpers
Security, validation, and common utilities
"""

from functools import wraps
from typing import Optional, List, Dict, Any
from datetime import datetime
import re
import logging
import uuid
import json

from flask import request, jsonify, g
from flask_jwt_extended import verify_jwt_in_request, get_jwt

logger = logging.getLogger(__name__)


# ============================================================================
# SECURITY UTILITIES
# ============================================================================

class SecurityUtils:
    """Security-related utilities"""

    @staticmethod
    def sanitize_input(value: str, max_length: int = 1000) -> str:
        """Sanitize user input to prevent injection attacks"""
        if not isinstance(value, str):
            return str(value)

        # Remove null bytes
        value = value.replace('\x00', '')

        # Truncate to max length
        value = value[:max_length]

        return value.strip()

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format"""
        import ipaddress

        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_network_range(network: str) -> bool:
        """Validate network CIDR notation"""
        import ipaddress

        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def validate_password_strength(password: str) -> tuple:
        """Validate password strength and return (is_valid, errors)"""
        errors = []

        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")

        if not re.search(r'[a-z]', password):
            errors.append("Password must contain lowercase letters")

        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain uppercase letters")

        if not re.search(r'[0-9]', password):
            errors.append("Password must contain numbers")

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain special characters")

        return len(errors) == 0, errors

    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate a secure random token"""
        import secrets
        return secrets.token_urlsafe(length)


# ============================================================================
# REQUEST DECORATORS
# ============================================================================

def get_request_id() -> str:
    """Get or generate request ID from header"""
    request_id = request.headers.get('X-Request-ID')
    if not request_id:
        request_id = str(uuid.uuid4())
    return request_id


def require_auth(f):
    """Require JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from backend.core.errors import AuthenticationError

        try:
            verify_jwt_in_request()
            g.request_id = get_request_id()
            return f(*args, **kwargs)
        except Exception as e:
            logger.warning(f"Authentication failed: {e}")
            raise AuthenticationError()

    return decorated_function


def require_role(*roles):
    """Require specific role(s)"""
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            from backend.core.errors import AuthorizationError

            claims = get_jwt()
            user_roles = claims.get('roles', [])

            if not any(role in user_roles for role in roles):
                logger.warning(f"Insufficient permissions for user")
                raise AuthorizationError("Insufficient permissions")

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_tenant_header(f):
    """Require X-Tenant-ID header"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from backend.core.errors import ValidationError

        tenant_id = request.headers.get('X-Tenant-ID')
        if not tenant_id:
            raise ValidationError("X-Tenant-ID header is required")

        g.tenant_id = tenant_id
        return f(*args, **kwargs)

    return decorated_function


def validate_json(*required_fields):
    """Validate JSON request body"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from backend.core.errors import ValidationError

            if not request.is_json:
                raise ValidationError("Content-Type must be application/json")

            data = request.get_json()
            if not data:
                raise ValidationError("Request body cannot be empty")

            missing = [field for field in required_fields if field not in data]
            if missing:
                raise ValidationError(f"Missing required fields: {', '.join(missing)}")

            g.json_data = data
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def log_action(action_name: str):
    """Log an action to audit trail"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from backend.core.repositories import AuditLogRepository
            from flask_jwt_extended import get_jwt

            try:
                claims = get_jwt()
                user_id = claims.get('sub')

                # Log action
                AuditLogRepository.log_action(
                    user_id=user_id,
                    tenant_id=g.get('tenant_id'),
                    action=action_name,
                    ip_address=request.remote_addr,
                    details={
                        'path': request.path,
                        'method': request.method
                    }
                )
            except:
                pass  # Don't fail request if audit logging fails

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# ============================================================================
# PAGINATION
# ============================================================================

class Pagination:
    """Pagination helper"""

    @staticmethod
    def get_params() -> tuple:
        """Extract pagination parameters from request"""
        skip = int(request.args.get('skip', 0))
        limit = int(request.args.get('limit', 50))

        # Validate
        skip = max(0, skip)
        limit = min(1000, max(1, limit))  # Max 1000 items per page

        return skip, limit

    @staticmethod
    def paginate_response(items: List[Any], total: int, skip: int, limit: int) -> Dict:
        """Create paginated response"""
        return {
            'items': items,
            'pagination': {
                'skip': skip,
                'limit': limit,
                'total': total,
                'pages': (total + limit - 1) // limit
            }
        }


# ============================================================================
# JSON HELPERS
# ============================================================================

class JSONUtils:
    """JSON serialization helpers"""

    @staticmethod
    def serialize_datetime(obj):
        """JSON serializer for datetime objects"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    @staticmethod
    def to_json(obj: Dict[str, Any]) -> str:
        """Convert dict to JSON string"""
        return json.dumps(obj, default=JSONUtils.serialize_datetime)

    @staticmethod
    def from_json(json_str: str) -> Dict[str, Any]:
        """Parse JSON string to dict"""
        return json.loads(json_str)


# ============================================================================
# IPADDRESS HELPERS
# ============================================================================

class IPUtils:
    """IP address utilities"""

    @staticmethod
    def is_internal_ip(ip: str) -> bool:
        """Check if IP is internal (RFC 1918)"""
        import ipaddress

        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except:
            return False

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate IP address"""
        import ipaddress

        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False

    @staticmethod
    def expand_network(network: str) -> List[str]:
        """Expand network CIDR to list of IPs (limit to 256 for safety)"""
        import ipaddress

        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())

            # Limit expansion to prevent DOS
            if len(hosts) > 256:
                return []

            return [str(ip) for ip in hosts]
        except:
            return []
