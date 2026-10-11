"""Root test fixtures: keep the whole unit suite independent of Docker.

Contract (documented in the tests' own docstrings): Rspamd is ALWAYS faked in
unit tests via a FastAPI dependency override; only the explicitly opt-in
integration files (``tests/api/test_analysis_integration.py``,
``tests/authentication/test_rspamd_integration.py``) use the real Dockerized
container and skip when it is not running. The autouse fixture below restores
that contract for every test module that forgot to install the fake itself:
without it, any POST to ``/analyze-email`` would hit the network in strict
mode and fail with an unrelated 503 whenever the local Rspamd container is
stopped.

Per-module fakes (e.g. the ``fake_rspamd``/``failing_rspamd`` fixtures in
``tests/api/conftest.py``) are installed AFTER this one and win, because a
later dependency override replaces an earlier one for the same dependency.

NOTE ON FASTAPI OVERRIDE SCOPING: a dependency override applies to the app
instance it is set on, and only to routers included by that instance. Tests
that build a fresh app with ``create_app()`` install the fake on the fresh
instance too, via ``tests.fake_rspamd.install_fake_rspamd``.
"""

from __future__ import annotations

import pytest

from fake_rspamd import install_fake_rspamd

# Module-name tails of the files that intentionally exercise the REAL
# Rspamd connection path. Compared against ``request.module.__name__``'s
# last component (a module name has NO ".py" suffix).
_LIVE_INTEGRATION_MODULES = (
    "test_analysis_integration",
    "test_rspamd_integration",
)


@pytest.fixture(autouse=True)
def fake_rspamd_globally(request):
    """Install the deterministic FakeRspamdClient unless the module is live."""

    if request.module.__name__.rsplit(".", 1)[-1] in _LIVE_INTEGRATION_MODULES:
        yield
        return

    from app.api import dependencies
    from app.main import app as fastapi_app

    key = dependencies.get_rspamd_client
    # install_fake_rspamd uses setdefault: if another override is already
    # installed, it is not ours and its owner cleans it up.
    had_override = key in fastapi_app.dependency_overrides
    install_fake_rspamd(fastapi_app)
    installed_override = fastapi_app.dependency_overrides.get(key)
    yield
    # Remove only the override this fixture installed. The stored value is
    # the ``lambda: fake`` wrapper — compare THAT by identity, never the
    # fake itself (a wrong comparison here leaks the fake into later tests,
    # including the live integration files that must hit real Rspamd).
    if (
        not had_override
        and fastapi_app.dependency_overrides.get(key) is installed_override
    ):
        fastapi_app.dependency_overrides.pop(key, None)
