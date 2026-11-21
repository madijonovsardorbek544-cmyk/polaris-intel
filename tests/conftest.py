import pytest


@pytest.fixture(autouse=True)
def _open_access_for_keyless_tests(monkeypatch):
    # Production fails closed without keys; most tests exercise keyless dev mode on purpose.
    monkeypatch.setenv("POLARIS_ALLOW_OPEN_ACCESS", "true")
