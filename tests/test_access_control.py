from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
ALICE = {"Authorization": "Bearer demo-token-alice"}
BOB = {"Authorization": "Bearer demo-token-bob"}


def test_owner_can_read_own_note():
    assert client.get("/notes/1", headers=ALICE).status_code == 200


def test_user_cannot_read_another_users_note():
    # The IDOR test: Bob asks for Alice's note by ID.
    assert client.get("/notes/1", headers=BOB).status_code == 404


def test_missing_and_forbidden_look_identical():
    forbidden = client.get("/notes/1", headers=BOB)
    missing = client.get("/notes/999", headers=BOB)
    assert forbidden.status_code == missing.status_code
    assert forbidden.json() == missing.json()


def test_no_token_is_rejected():
    assert client.get("/notes/1").status_code in (401, 403)


def test_owner_cannot_be_set_from_request_body():
    r = client.post("/notes", headers=BOB, json={"text": "hi", "owner": "alice"})
    assert r.json()["owner"] == "bob"
