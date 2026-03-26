def test_smoke_models(app):
    # Simple smoke test to ensure models and DB create successfully
    from app.extensions import db
    from app.models.user import User

    u = User(tenant_id='t1', username='tester', email='t@x.com', password_hash='x')
    db.session.add(u)
    db.session.commit()

    assert u.id is not None
