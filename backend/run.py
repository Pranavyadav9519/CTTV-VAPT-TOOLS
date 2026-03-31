"""
VAPT Tool - Application Launcher
Starts either the standalone app or enterprise app based on configuration.

Usage:
  python backend/run.py              # Uses standalone app (default, fully featured)
  FLASK_ENV=enterprise python backend/run.py  # Uses enterprise app

The standalone app (backend/app.py) is recommended for:
  - Complete functionality with all frontend routes
  - Development and testing
  - Simple deployments

The enterprise app (backend/enterprise/__init__.py) is recommended for:
  - Multi-tenant SaaS deployments
  - Advanced role-based access control (RBAC)
  - Celery async task support
  - Rate limiting via Redis
"""

import os
import sys
import logging

# Add project root to Python path so imports work correctly
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def main():
    """Launch the appropriate Flask application based on environment."""
    import importlib.util
    from pathlib import Path
    
    flask_env = os.environ.get('FLASK_ENV', 'development').lower()
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = flask_env == 'development'

    # Determine which app to use
    if 'enterprise' in flask_env:
        logger.info("🚀 Starting ENTERPRISE app (backend/enterprise/__init__.py)")
        logger.info("   - API endpoints at /api/ with JWT auth + RBAC")
        logger.info("   - Celery async tasks enabled")
        logger.info("   - Rate limiting enabled")
        try:
            from backend.enterprise import create_app
            app = create_app(flask_env)
        except ImportError as e:
            logger.error(f"❌ Failed to import enterprise app: {e}")
            logger.info("   Falling back to standalone app...")
            # Load backend/app.py directly to avoid backend/app/ directory collision
            app_file = Path(__file__).parent / "app.py"
            spec = importlib.util.spec_from_file_location("backend_app_module", app_file)
            app_module = importlib.util.module_from_spec(spec)
            sys.modules["backend_app_module"] = app_module
            spec.loader.exec_module(app_module)
            app = app_module.app
    else:
        logger.info("🚀 Starting STANDALONE app (backend/app.py)")
        logger.info("   - All frontend routes available (/, /css/*, /js/*)")
        logger.info("   - Socket.IO support for live scan updates")
        logger.info("   - Direct database operations (no async queue)")
        # Load backend/app.py directly to avoid backend/app/ directory collision
        app_file = Path(__file__).parent / "app.py"
        spec = importlib.util.spec_from_file_location("backend_app_module", app_file)
        app_module = importlib.util.module_from_spec(spec)
        sys.modules["backend_app_module"] = app_module
        spec.loader.exec_module(app_module)
        app = app_module.app

    # Log important info
    logger.info(f"   Host: {host}")
    logger.info(f"   Port: {port}")
    logger.info(f"   Debug: {debug}")
    logger.info("\n✅ Application initialized successfully")
    logger.info("📖 Access the application at http://localhost:{port}")
    logger.info("   API docs: http://localhost:{port}/api/docs")
    logger.info("   Health check: http://localhost:{port}/health\n")

    # Run the app
    try:
        if os.name == 'nt':
            # Windows: use threading for SocketIO
            app.run(host=host, port=port, debug=debug)
        else:
            # Unix: try eventlet, fall back to threading
            try:
                import eventlet
                app.run(host=host, port=port, debug=debug)
            except (ImportError, Exception):
                app.run(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        logger.info("\n⏹️ Application stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Application error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
