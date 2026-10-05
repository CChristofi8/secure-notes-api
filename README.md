# Secure Notes API

A small FastAPI service built to demonstrate secure API design and an automated security pipeline.

![Security pipeline](https://github.com/CChristofi8/secure-notes-api/actions/workflows/security.yml/badge.svg)

## What it demonstrates

- **Access control and IDOR prevention:** users can read only their own notes.
- **No ID enumeration:** "missing" and "not yours" return the same 404 response.
- **Mass-assignment prevention:** the note owner comes from the token, never from the request body.
- **Tests that prove it:** `tests/test_access_control.py`
- **Automated security pipeline** (GitHub Actions), run on every push:
  - SAST with Semgrep
  - Dependency vulnerability scanning with pip-audit
  - Secrets scanning with Gitleaks
  - SBOM generation with CycloneDX (downloadable artefact)
- **Threat model:** STRIDE analysis in [THREAT_MODEL.md](THREAT_MODEL.md)
- **Write-up:** [IDOR: breaking it in a lab, preventing it in code](docs/idor-writeup.md) connects the PortSwigger IDOR lab to the fix and tests in this repo.

## The vulnerable version and the fix

A naive implementation looks like this:

```python
@app.get("/notes/{note_id}")
def read_note(note_id: int, user: str = Depends(current_user)):
    return NOTES[note_id]  # no ownership check
```

The user is authenticated, but nothing checks that the note belongs to them, so any logged-in user can read anyone's note by changing the ID in the URL. This is an **insecure direct object reference (IDOR)**, a form of broken access control (OWASP Top 10, A01).

The fix checks ownership and returns the same response whether the note is missing or belongs to someone else:

```python
note = NOTES.get(note_id)
if note is None or note["owner"] != user:
    raise HTTPException(status.HTTP_404_NOT_FOUND, "Note not found")
return note
```

## Findings the pipeline caught

| Date | Tool | Finding | Fix |
|---|---|---|---|
| 2026-10-05 | Semgrep (`github-actions-mutable-action-tag`) | Four GitHub Actions used mutable tags (`@v4`, `@v5`, `@v2`). The owner of a tag can silently repoint it, which opens a supply-chain attack path. | Pinned every action to its full 40-character commit SHA, with the version kept in a comment. |
| 2026-10-05 | Pipeline design | Pinning actions to commit SHAs stops them receiving updates, including security fixes. | Added Dependabot (`.github/dependabot.yml`) for GitHub Actions and pip. It opens weekly pull requests that update the SHA and version comment, and every update must pass this pipeline before it is merged. |
| 2026-10-05 | Pipeline design | Installing Semgrep into the app's environment downgraded a dependency the app relies on (`opentelemetry-api`). | Each security tool now runs in its own virtual environment. |

## Run it

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
pytest -v
uvicorn app.main:app --reload
```

Then open http://127.0.0.1:8000/docs and use `demo-token-alice` or `demo-token-bob` as the bearer token.

## Notes

The tokens are demo values for local testing only. See the threat model for production recommendations.
