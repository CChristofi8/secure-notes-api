from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

app = FastAPI(title="Secure Notes API")
bearer = HTTPBearer()

# Demo data only. A real app would use a database and hashed, expiring tokens.
TOKENS = {"demo-token-alice": "alice", "demo-token-bob": "bob"}
NOTES = {
    1: {"id": 1, "owner": "alice", "text": "Alice's private note"},
    2: {"id": 2, "owner": "bob", "text": "Bob's private note"},
}


class NoteIn(BaseModel):
    text: str


def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    user = TOKENS.get(creds.credentials)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    return user


@app.get("/notes/{note_id}")
def read_note(note_id: int, user: str = Depends(current_user)):
    note = NOTES.get(note_id)
    # Same response for "missing" and "not yours", so attackers cannot
    # discover which note IDs exist (prevents IDOR and ID enumeration).
    if note is None or note["owner"] != user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Note not found")
    return note


@app.get("/notes")
def list_notes(user: str = Depends(current_user)):
    return [n for n in NOTES.values() if n["owner"] == user]


@app.post("/notes", status_code=status.HTTP_201_CREATED)
def create_note(body: NoteIn, user: str = Depends(current_user)):
    note_id = max(NOTES) + 1
    # Owner comes from the token, never from the request body
    # (prevents mass assignment of ownership).
    NOTES[note_id] = {"id": note_id, "owner": user, "text": body.text}
    return NOTES[note_id]
