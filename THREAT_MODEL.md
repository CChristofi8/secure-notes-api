# Threat Model: Secure Notes API

## System overview
- Client sends HTTPS requests with a bearer token
- FastAPI app validates the token, checks ownership, returns notes
- Data store (in-memory for the demo; a database in production)

## Data flow
Client -> (trust boundary: internet) -> FastAPI -> (trust boundary) -> data store

## Assets
- Users' private notes
- Authentication tokens

## STRIDE analysis

| Threat | Example in this API | Mitigation in code | Status |
|---|---|---|---|
| Spoofing | Attacker guesses or steals a token | Token check in `current_user`; production: hashed, expiring tokens | Partial (demo tokens) |
| Tampering | Attacker sets `owner` in POST body | Owner taken from the token, never the body | Mitigated, tested |
| Repudiation | User denies creating a note | No audit log yet | Open: add logging |
| Information disclosure | IDOR: Bob reads note 1 | Ownership check; same 404 for missing and forbidden | Mitigated, tested |
| Denial of service | Flooding POST /notes | No rate limiting yet | Open |
| Elevation of privilege | User reaches admin functions | No admin endpoints exist; deny by default | Mitigated by design |

## Residual risks and next steps
- Replace demo tokens with OAuth2/JWT with expiry
- Add audit logging and rate limiting
- Run DAST (for example OWASP ZAP baseline) against a running instance
