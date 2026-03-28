def test_smoke_models(app):
    # Simple smoke test to ensure models and DB create successfully
    from backend.enterprise.extensions import db
    from backend.enterprise.models.user import User

    u = User(username='tester', email='t@x.com', password_hash='x')
    db.session.add(u)
    db.session.commit()

    assert u.id is not None
