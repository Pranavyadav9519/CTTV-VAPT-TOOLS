import os
import importlib.util
import sys
from types import ModuleType

# Make `import app.extensions` and similar submodule imports resolve to the
# backend app directory when running from the repository root.
__path__ = [os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend', 'app'))]

# Load the backend/app package module and expose its public API here so tests
# and scripts can `from app import create_app` when running from repository root.
_backend_init = os.path.abspath(
	os.path.join(os.path.dirname(__file__), '..', 'backend', 'app', '__init__.py')
)

spec = importlib.util.spec_from_file_location('app', _backend_init)
_backend_app: ModuleType | None = None


def _load_backend():
	global _backend_app
	if _backend_app is not None:
		return _backend_app

	_backend_app = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
	# Register as package 'app' so relative imports resolve inside backend code.
	pkg_dir = os.path.dirname(_backend_init)
	_backend_app.__path__ = [pkg_dir]  # type: ignore[attr-defined]
	sys.modules['app'] = _backend_app
	# Provide safe defaults during dynamic load if not already present.
	os.environ.setdefault('SECRET_KEY', 'test-secret-key-0123456789abcdef')
	os.environ.setdefault('JWT_SECRET_KEY', os.environ['SECRET_KEY'])
	if spec and spec.loader:
		spec.loader.exec_module(_backend_app)  # type: ignore[attr-defined]
	return _backend_app


def create_app(*args, **kwargs):
	"""Lazy proxy to backend.app.create_app."""
	mod = _load_backend()
	return getattr(mod, 'create_app')(*args, **kwargs)


__all__ = ["create_app"]
