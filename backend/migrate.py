from app import create_app
from app.extensions import db, migrate


def make_app():
    app = create_app()
    migrate.init_app(app, db)
    return app


app = make_app()

if __name__ == '__main__':
    print('Run migration commands via flask-migrate or alembic; example:')
    print('  flask db upgrade')
