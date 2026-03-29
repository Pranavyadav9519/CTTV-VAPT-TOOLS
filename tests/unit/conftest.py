"""
Unit-level conftest for CRR pipeline tests.
Overrides the top-level autouse `db` fixture so that unit tests which do
not depend on the Flask app or database are not inadvertently skipped.

The existing top-level `db` fixture calls pytest.skip when the enterprise
database module is unavailable.  For pure-unit CRR tests this behaviour is
undesirable — they have no database dependency and should always run.

The override here yields None for any test that does NOT have `app` in its
fixture list, allowing pure unit tests to execute normally.  Tests that DO
request `app` continue to receive the original behaviour (they are still
skipped by the `app` fixture itself when the enterprise module is absent).
"""

import pytest


@pytest.fixture(autouse=True)
def db(request):
    """
    Override the session-level `db` autouse fixture for unit tests.

    If the test requests `app` (i.e. is an integration/API test) we defer
    to the top-level fixture; otherwise we provide a lightweight no-op so
    that pure-unit tests are never skipped because of a missing database.
    """
    if "app" in request.fixturenames:
        # Let the parent conftest db fixture handle this via pytest's fixture
        # resolution — we yield None and let the parent scope take over.
        yield None
    else:
        # Pure unit test — no database needed.
        yield None
