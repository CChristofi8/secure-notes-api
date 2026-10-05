# Burp Suite Self-Test: Attacking My Own API

After solving the PortSwigger access control labs, I tested this API with the same techniques: Burp Suite Proxy, Repeater, and Intruder, against a local instance (`uvicorn app.main:app`). The goal was to confirm that the access control holds against the attacks I had just used to break the labs.

**Scope:** `GET /notes/{id}`, `GET /notes`, and `POST /notes`, tested as user `bob` (`demo-token-bob`). Bob owns note 2. Alice owns note 1.

## Results

| # | Attack | Request | Result | Verdict |
|---|---|---|---|---|
| 1 | IDOR (the lab's attack) | `GET /notes/1` as Bob | 404 `{"detail":"Note not found"}` | Blocked |
| 2 | Legitimate access | `GET /notes/2` as Bob | 200, Bob's note returned | Works |
| 3 | ID enumeration | `GET /notes/999` as Bob, compared with test 1 | 404, with a body and length (27 bytes) identical to test 1 | Blocked: "missing" and "not yours" look the same |
| 4 | No authentication | `Authorization` header removed | 401 `{"detail":"Not authenticated"}` | Blocked |
| 5 | Forged token | `Bearer fake-token` | 401 `{"detail":"Invalid token"}` | Blocked |
| 6 | Mass assignment | `POST /notes` with `{"text":"x","owner":"alice"}` | 201, `"owner":"bob"` | Blocked: the owner is taken from the token |
| 7 | Bad input | `GET /notes/abc`, `GET /notes/-1` | 422 (validation), 404 | Handled |
| 8 | Method tampering | `DELETE /notes/1` | 405 Method Not Allowed | Blocked |
| 9 | Automated enumeration | Intruder, IDs 1 to 20 | Every ID that Bob does not own returned an identical 404 | Blocked |

## Findings

| Finding | Severity | Status |
|---|---|---|
| Responses carried no security headers (only `content-type` and `content-length`) | Low | **Fixed.** Middleware now adds `nosniff`, `X-Frame-Options`, `Cache-Control: no-store`, `Referrer-Policy`, HSTS, and a strict CSP, covered by `tests/test_security_headers.py`. |
| No rate limiting: Intruder sent requests as fast as it could with no throttling | Medium (in production) | **Open.** Already recorded in [THREAT_MODEL.md](../THREAT_MODEL.md). |
| The 422 response reveals the parameter name and expected type | Informational | Accepted. This is standard FastAPI behaviour and reveals nothing sensitive. |
| Missing and invalid tokens return different messages ("Not authenticated" and "Invalid token") | Informational | Accepted. Neither message reveals anything about valid tokens or users. |

## Takeaways

- The ownership check, the identical 404 responses, and taking the owner from the token held against every access control attack from the labs.
- Manual testing found something the automated tools missed: the missing security headers. Neither Semgrep nor the unit tests check response headers, so the self-test covered a gap in the pipeline. The fix is now locked in with tests.
- The rate-limiting gap is known and documented. It is the next fix to make before any real deployment.
