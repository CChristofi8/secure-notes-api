from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

app = FastAPI(title="Secure Notes API")
bearer = HTTPBearer()

# Security headers for a JSON API, following the OWASP REST Security Cheat Sheet.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",  # no MIME sniffing of responses
    "X-Frame-Options": "DENY",  # never render responses in a frame
    "Cache-Control": "no-store",  # private notes must not be cached
    "Referrer-Policy": "no-referrer",
    # Stops other sites embedding API responses as cross-origin resources
    # (added after the OWASP ZAP scan flagged it).
    "Cross-Origin-Resource-Policy": "same-origin",
    # Browsers only honour HSTS over HTTPS; it takes effect once deployed behind TLS.
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
}
API_CSP = "default-src 'none'; frame-ancestors 'none'"
# The interactive docs load scripts and styles from a CDN, so they are exempt
# from the strict API Content Security Policy.
DOCS_PATHS = {"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    # Runs outside FastAPI's exception handling, so error responses
    # (401, 404, 422) get the headers too.
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.url.path not in DOCS_PATHS:
        response.headers.setdefault("Content-Security-Policy", API_CSP)
    return response

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
