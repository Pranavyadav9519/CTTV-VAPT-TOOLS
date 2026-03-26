"""
Error Handling and Custom Exceptions
Provides consistent error responses across API
"""

from flask import jsonify, request
from typing import Optional, Dict, Any
import logging
import uuid

logger = logging.getLogger(__name__)


class APIException(Exception):
    """Base exception for API errors"""

    def __init__(self, message: str, error_code: str, status_code: int = 400,
                 details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)

    def to_response(self, request_id: str) -> tuple:
        """Convert exception to JSON response"""
        return jsonify({
            'success': False,
            'data': None,
            'error': {
                'code': self.error_code,
                'message': self.message,
                'details': self.details
            },
            'request_id': request_id
        }), self.status_code


class ValidationError(APIException):
    """Validation error"""
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(message, "validation.failed", 400, details)


class AuthenticationError(APIException):
    """Authentication error"""
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, "auth.failed", 401)


class AuthorizationError(APIException):
    """Authorization error"""
    def __init__(self, message: str = "Access denied"):
        super().__init__(message, "auth.forbidden", 403)


class NotFoundError(APIException):
    """Resource not found"""
    def __init__(self, resource: str):
        super().__init__(f"{resource} not found", "resource.not_found", 404)


class ConflictError(APIException):
    """Resource conflict"""
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(message, "resource.conflict", 409, details)


class TooManyRequestsError(APIException):
    """Rate limit exceeded"""
    def __init__(self, message: str = "Too many requests"):
        super().__init__(message, "rate_limit.exceeded", 429)


class InternalServerError(APIException):
    """Internal server error"""
    def __init__(self, message: str = "Internal server error"):
        super().__init__(message, "server.error", 500)


def success_response(data: Any = None, request_id: str = None,
                     status_code: int = 200) -> tuple:
    """Create a successful API response"""
    if request_id is None:
        request_id = str(uuid.uuid4())

    return jsonify({
        'success': True,
        'data': data,
        'error': None,
        'request_id': request_id
    }), status_code


def error_response(error_code: str, message: str, request_id: str = None,
                   status_code: int = 400, details: Optional[Dict] = None) -> tuple:
    """Create an error API response"""
    if request_id is None:
        request_id = str(uuid.uuid4())

    return jsonify({
        'success': False,
        'data': None,
        'error': {
            'code': error_code,
            'message': message,
            'details': details or {}
        },
        'request_id': request_id
    }), status_code


def register_error_handlers(app):
    """Register error handlers with Flask app"""

    @app.errorhandler(APIException)
    def handle_api_exception(error):
        request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        logger.warning(f"API Exception [{request_id}]: {error.error_code} - {error.message}")
        return error.to_response(request_id)

    @app.errorhandler(400)
    def handle_bad_request(error):
        request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        return error_response(
            "request.invalid",
            "Bad request",
            request_id,
            400
        )

    @app.errorhandler(401)
    def handle_unauthorized(error):
        request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        return error_response(
            "auth.required",
            "Authentication required",
            request_id,
            401
        )

    @app.errorhandler(403)
    def handle_forbidden(error):
        request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        return error_response(
            "auth.forbidden",
            "Access denied",
            request_id,
            403
        )

    @app.errorhandler(404)
    def handle_not_found(error):
        request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        return error_response(
            "resource.not_found",
            "Resource not found",
            request_id,
            404
        )

    @app.errorhandler(500)
    def handle_internal_error(error):
        request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        logger.error(f"Internal error [{request_id}]: {str(error)}")
        return error_response(
            "server.error",
            "Internal server error",
            request_id,
            500
        )

    logger.info("Error handlers registered")
