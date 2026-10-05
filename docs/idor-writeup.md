# IDOR: Breaking It in a Lab, Preventing It in Code

This write-up connects two pieces of work: solving the PortSwigger Web Security Academy lab **"Insecure direct object references"**, and the access control in this repository that prevents the same class of flaw.

## 1. The attack: PortSwigger lab

**Lab:** [Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references) (Access control, Apprentice level). I solved it without using the published solution.

**Setup:** the lab's live chat feature lets you download a transcript of your conversation. The goal is to find the password of the user `carlos` and log in as him.

**What I did:**

1. Used the live chat, then clicked "View transcript" with Burp Suite proxying the traffic.
2. In Burp's HTTP history, saw that the transcript was fetched from a URL ending in a number, for example `/download-transcript/2.txt`.
3. Sent the request to Repeater and changed the number to `1.txt`.
4. The server returned another user's chat transcript. It contained a password, which I used to log in as `carlos`.

**What I noticed:** [YOUR OWN WORDS: one or two sentences on what tipped you off, for example the sequential number in the filename, or the file being served without any check on who was asking.]

**Root cause:** the server trusted the identifier in the URL. It checked *what* was being requested, but not *who* was asking or whether they owned it. Sequential identifiers made the flaw trivial to exploit. A random identifier alone would not have fixed it, though, because the missing piece is the ownership check.

## 2. The fix: this repository

The vulnerable pattern, translated into this API:

```python
@app.get("/notes/{note_id}")
def read_note(note_id: int, user: str = Depends(current_user)):
    return NOTES[note_id]  # authenticated, but no ownership check
```

The fix in [`app/main.py`](../app/main.py):

```python
note = NOTES.get(note_id)
if note is None or note["owner"] != user:
    raise HTTPException(status.HTTP_404_NOT_FOUND, "Note not found")
return note
```

Three decisions are worth explaining:

| Decision | Why |
|---|---|
| Check ownership on every object access, server side | Authentication says who the user is. Authorisation must still be checked per object. That was the gap in the lab. |
| Return 404 for both "missing" and "not yours" | A 403 would confirm that the object exists, which lets an attacker enumerate valid IDs. |
| Take the owner from the token, never from the request | Prevents the related mass-assignment flaw, where a user sets `owner` in the request body. |

## 3. The proof: tests

[`tests/test_access_control.py`](../tests/test_access_control.py) runs on every push in the security pipeline:

- `test_user_cannot_read_another_users_note`: Bob requests Alice's note by ID and gets a 404. This is the lab's attack, automated as a regression test.
- `test_missing_and_forbidden_look_identical`: no ID enumeration.
- `test_owner_cannot_be_set_from_request_body`: no mass assignment.

## 4. What I would do in a real codebase

- Centralise the ownership check, for example as a dependency or a query filter scoped to the current user, so a new endpoint cannot forget it.
- Prefer non-sequential identifiers (UUIDs) as defence in depth. They are not a substitute for the check.
- Add an IDOR test for every endpoint that takes an object ID, not just one.
- Review code specifically for endpoints that accept identifiers from the client, whether in the URL, query string, body, or headers.

## References

- PortSwigger, [Access control vulnerabilities](https://portswigger.net/web-security/access-control) and [Insecure direct object references](https://portswigger.net/web-security/access-control/idor)
- OWASP Top 10, [A01 Broken Access Control](https://owasp.org/Top10/)
- OWASP API Security Top 10, API1: Broken Object Level Authorization
