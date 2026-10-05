import pytest
from fastapi.testclient import TestClient

from app.main import API_CSP, SECURITY_HEADERS, app

client = TestClient(app)
ALICE = {"Authorization": "Bearer demo-token-alice"}
BOB = {"Authorization": "Bearer demo-token-bob"}


@pytest.mark.parametrize(
    "path, headers, expected_status",
    [
        ("/notes/1", ALICE, 200),  # success
        ("/notes/1", BOB, 404),  # IDOR attempt
        ("/notes/1", {"Authorization": "Bearer fake-token"}, 401),  # bad token
        ("/notes/abc", ALICE, 422),  # validation error
    ],
)
def test_security_headers_on_every_api_response(path, headers, expected_status):
    r = client.get(path, headers=headers)
    assert r.status_code == expected_status
    for name, value in SECURITY_HEADERS.items():
        assert r.headers.get(name) == value, f"missing or wrong {name}"
    assert r.headers.get("Content-Security-Policy") == API_CSP


def test_docs_still_load_without_strict_csp():
    r = client.get("/docs")
    assert r.status_code == 200
    assert "Content-Security-Policy" not in r.headers
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
