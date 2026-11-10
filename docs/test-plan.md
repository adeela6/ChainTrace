# ChainTrace Test Plan

Owner: D. Reviewers: A, B, C.

This plan lists every test ChainTrace needs, what each one expects, and whose code it depends on. Expected results come straight from the team's shared formats doc (block format, verification result schema, error codes, audit format, validation limits). If a format changes there, this plan changes with it.

## 1. How tests are run

```bash
pytest                          # everything
pytest tests/unit               # engine functions (B writes, D reviews)
pytest tests/api                # endpoints, roles, misuse (D)
pytest tests/evaluation         # T1-T6, T-final (D)
coverage run -m pytest && coverage report
```

`docs/test-results.md` is generated from a pytest run, never edited by hand.

**Isolation rule:** tests never touch your real `.env`, `chaintrace.db` or `storage/`. The shared test setup in `tests/conftest.py` points every setting at a temporary folder and uses a throwaway master key. Each evaluation test starts from a fresh copy of the seeded state and breaks exactly one thing.

## 2. What the tests depend on

| Needed from | What | Unblocks |
|---|---|---|
| A | App factory (`create_app(settings)` or equivalent) so each test gets its own database | All API and evaluation tests |
| A | SQLAlchemy models, error envelope, `audit.log()` | Seed script, API tests |
| B | `canonical_json()`, hashing, keys, signing, verifier (stubs first) | Engine unit test review, fixtures, T1-T5 |
| C | Pages calling the agreed routes | Accessibility check, end-to-end demo run |
| D + B | `scripts/seed_demo_data.py` and fixtures | T1-T6, metrics |

## 3. Requirements to tests

Every requirement has at least one test. "Code owner" is whose code is being tested.

| Requirement | Code owner | Tests |
|---|---|---|
| FR-1 Case and evidence registration | A | API-REG-*, validation boundaries (section 6), T-final |
| FR-2 SHA-256 hashing | B | Engine unit tests, T2 |
| FR-3 Signed transfer + ACCEPT | B | API-XFER-*, T3, T4 |
| FR-4 Append-only blocks | B (A: triggers, lock) | T1, T5, trigger tests, concurrent append test |
| FR-5 Verification + result schema | B | T1-T5, schema shape test, verification history test |
| FR-6 Audit log + export | A | Audit tests (section 7), T6 |
| Login, sessions, CSRF, rate limits, password hashing | A | API-AUTH-*, misuse tests (section 5) |
| Role permissions | A | Permission matrix (section 4) |
| Server-side redaction | A | T6, viewer tests |
| Case report export | C | Export tests, T6 |
| Accessibility | C | Manual checklist (section 9) |

## 4. Permission matrix

One parametrized test per cell. "Member" means the user is in `case_members` for that case. Every denial must also write an `ACCESS_DENIED` audit event with outcome `DENIED`.

Not logged in → `401 UNAUTHENTICATED` on every route except `POST /auth/login`.

| Route | admin | analyst (member) | analyst (not member) | viewer (member) | viewer (not member) |
|---|---|---|---|---|---|
| `POST /auth/logout`, `GET /auth/me` | ok | ok | ok | ok | ok |
| `POST /cases` | 403 | ok | ok | 403 | 403 |
| `GET /cases` | all cases | own cases only | own cases only | own cases only | own cases only |
| `GET /cases/{id}` | ok | ok | 404 | ok, redacted | 404 |
| `POST /cases/{id}/evidence` | 403 | ok | 404 | 403 | see Q6 |
| `GET /evidence/{id}` | ok | ok | 404 | ok, redacted | 404 |
| `POST /evidence/{id}/transfers` | 403 | ok if custodian, else 409 `NOT_CUSTODIAN` | 404 | 403 | see Q6 |
| `POST /transfers/{id}/accept` | 403 | ok if receiver, else see Q7 | 404 | 403 | see Q6 |
| `POST /verify/chain` | ok | ok | ok | 403 | 403 |
| `POST /verify/evidence/{id}` | ok | ok | 404 | 403 | 403 |
| `GET /verifications` | ok | ok | ok | 403 | 403 |
| `GET /cases/{id}/export` | ok | ok | 404 | 403 | 403 |
| `GET /admin/audit`, `/admin/audit/export` | ok | 403 | 403 | 403 | 403 |
| `POST /admin/users`, `PATCH /admin/users/{id}` | ok | 403 | 403 | 403 | 403 |
| `GET` / `PUT /admin/config` | ok | 403 | 403 | 403 | 403 |

"ok" means 200 or 201; see Q8.

## 5. API and misuse tests (`tests/api/`)

**Auth and sessions**
- API-AUTH-01 Correct login returns a session cookie with `HttpOnly` and `SameSite=Strict`, plus a CSRF token.
- API-AUTH-02 Wrong username and wrong password both return `401 INVALID_CREDENTIALS` with an identical message.
- API-AUTH-03 The 6th login attempt within a minute (same IP + username) returns `429 RATE_LIMITED` and writes a `RATE_LIMITED` audit event.
- API-AUTH-04 After 30 idle minutes (clock moved forward in the test), requests return `401 UNAUTHENTICATED` and a `SESSION_EXPIRED` event is written.
- API-AUTH-05 After logout, the old cookie no longer works and the session row is gone.
- API-AUTH-06 A deactivated user (`is_active = false`) can't log in.
- API-AUTH-07 Stored password hashes start with `$argon2id$`.

**CSRF**
- API-CSRF-01 Every state-changing route without `X-CSRF-Token` returns `403 CSRF_FAILED`.
- API-CSRF-02 A token from a different session returns `403 CSRF_FAILED`.

**Registration (FR-1)**
- API-REG-01 A valid upload stores the file as `storage/evidence/<id>.bin`, records the right SHA-256, and appends one REGISTER block.
- API-REG-02 The same file twice in one case returns `409 DUPLICATE_EVIDENCE` and nothing is appended.
- API-REG-03 The same file in a different case is accepted silently, and the audit event has `"duplicate_of_other_case": true`.
- API-REG-04 A file name like `../../etc/passwd` is stored sanitized, and the storage path never contains it.

**Transfers (FR-3)**
- API-XFER-01 A valid transfer appends TRANSFER, but custody does not change until ACCEPT.
- API-XFER-02 ACCEPT appends a block and moves custody to the receiver.
- API-XFER-03 A wrong re-auth password is rejected (code: see Q5) and nothing is appended.
- API-XFER-04 The 11th transfer within a minute returns `429 RATE_LIMITED`.

**Errors**
- API-ERR-01 Every error response matches the envelope `{"error": {"code", "message", "request_id"}}`, and `request_id` is a UUID.
- API-ERR-02 No error body contains a stack trace, SQL, a file path or exception class names.
- API-ERR-03 A non-UUID ID in a URL returns `404 NOT_FOUND`.
- API-ERR-04 Unknown JSON fields return `400 VALIDATION_ERROR`.

**Injection**
- API-INJ-01 SQL-like input (`' OR 1=1 --`) in the username, title and reason is stored as plain text and changes nothing else.
- API-INJ-02 `<script>` in a title or reason comes back unchanged as JSON data (C's pages must show it as text, see section 9).

**Ledger safety**
- API-LEDGER-01 `UPDATE` and `DELETE` on `blocks` and `audit_events` are rejected by the triggers.
- API-LEDGER-02 Two transfers sent at the same time never get the same block index, and the chain still passes.

## 6. Validation boundary tests

Each limit is tested just inside and just outside.

| Input | Accepted | Rejected (expected code) |
|---|---|---|
| File size | 1 byte; exactly 25 MB | 0 bytes (`VALIDATION_ERROR`); 25 MB + 1 byte (`413 FILE_TOO_LARGE`) |
| File type | one real file per allowed type | `.exe` (`INVALID_FILE_TYPE`); a text file renamed `.png` (`INVALID_FILE_TYPE`) |
| Original file name | 255 characters | 256 characters (`VALIDATION_ERROR`); path separators and control characters stripped |
| Username | 3 and 32 characters, `a-z 0-9 _ .` | 2 and 33 characters; a space or `-` |
| Password | 10 characters | 9 characters |
| Case title | 1 and 120 characters | empty; 121 characters |
| Description / reason | 1000 characters | 1001 characters |
| Request body | 26 MB | over 26 MB |
| Config change | After an admin lowers the size limit, the next upload above it is rejected | |

## 7. Audit log tests

- AUD-01 Each of the 18 event types is written by the action that should produce it.
- AUD-02 Every event has all the agreed fields, a UTC timestamp in the agreed format and a valid `outcome`.
- AUD-03 `LOGIN_FAILED` records the typed username and nothing else.
- AUD-04 `CONFIG_CHANGED` records both the old and the new value.
- AUD-05 Never-log scan: after a full workflow, no audit row, server log line or export contains a password, session ID, CSRF token, private key, the master key or file contents (searched using the real values from the test run).

## 8. Evaluation tests (`tests/evaluation/`)

Each test copies the seeded state, breaks exactly one thing, and asserts on the exact check name and block index.

| ID | Setup | Expected result |
|---|---|---|
| T1 Tampered record | Edit `payload_json` of block 5 in a copy of the DB (triggers dropped for the test) | `FAIL`, `first_failure` = `BLOCK_HASH_VALID` at block 5 |
| T2 Altered file | Flip one byte of `storage/evidence/<id>.bin` | `FAIL`, `FILE_HASH_MATCH` for that evidence; other evidence still passes |
| T3 Invalid signature | (a) transfer signed with another user's key; (b) a stored block with one signature byte flipped | (a) `422 INVALID_SIGNATURE`, nothing appended; (b) `FAIL` at `SIGNATURE_VALID` |
| T4 Duplicate transfer | (a) same transfer sent twice; (b) a transfer while one is pending; (c) a transfer by a non-custodian | `409 DUPLICATE_TRANSFER` / `409 NOT_CUSTODIAN`; block count unchanged |
| T5 Chain validation | Clean chain of 50+ blocks; then delete a middle block | `PASS` with empty `checks` on the clean chain; `FAIL` at `PREV_HASH_LINK` after deletion (see Q3) |
| T6 Privacy review | Viewer opens a case and evidence; admin exports a report and the audit log | Viewer sees no file names, descriptions, reasons or usernames; no secrets anywhere (AUD-05) |
| T-final | Malformed JSON, 30 MB file, fake `.png`, wrong-role request, repeated submit, server restart mid-workflow | Correct error codes, no stack traces, data intact after restart, chain still `PASS` |

**Every failure result is also checked for shape:** all fields of the verification result schema are present, `status` is `FAIL`, `checks` lists only failed checks, and `first_failure` matches the first entry. Clean results have `status: PASS` and an empty `checks` list.

**T-final restart:** start the server with uvicorn as a separate process, create a transfer, kill the process, start it again, accept the transfer, then verify the chain. Marked slow so it can be skipped during quick runs.

## 9. Manual checks

These can't be fully automated; D records each one with a screenshot in `docs/test-results.md`.

- Accessibility (C builds, D checks): every input has a label; every action works by keyboard only; text contrast is at least 4.5:1; error messages are announced as text, not only by colour.
- Titles and reasons containing `<script>` show as text on every page.
- Confirmation dialogs appear before transfer, accept and config changes.
- Frontend buttons hidden by role still return 403 when called directly (covered by section 4).

## 10. Metrics

Recorded in `docs/test-results.md` after every full run.

| Metric | Target | How it's measured |
|---|---|---|
| Pass rate | at least 80% | Passed tests ÷ all tests, from the pytest results file |
| False positives | 0 | Verify 20 clean seeded chains; any `FAIL` is a false positive |
| False negatives | 0 | Verify every tampered fixture (T1, T2, T3b, T5); any `PASS` is a false negative |
| Verification time | reported | Median of 5 runs of `POST /verify/chain` at 100, 1,000 and 10,000 blocks |
| API latency | reported | Median and 95th percentile over 30 calls each for register, transfer and verify |

## 11. Done means

- Every row in sections 3 to 8 has a test, and every test is in the results table.
- Pass rate is at least 80%, with 0 false positives and 0 false negatives.
- T1-T6 and T-final all pass.
- No test is skipped without a written reason.

## 12. Open questions for the team

Tests for these are written once the team agrees an answer.

- **Q1 Upload rate limit:** the tech stack says upload is rate-limited, but the validation limits only give numbers for login (5/min) and transfer (10/min). What is the upload limit?
- **Q2 Case verification:** the result schema has a `case` scope, but there is no `POST /verify/case/{id}` route. Add the route, or drop the scope?
- **Q3 Check order:** deleting a middle block breaks both `PREV_HASH_LINK` and `INDEX_SEQUENTIAL` at the same block. T5 expects `PREV_HASH_LINK` as `first_failure`, so the verifier needs a fixed check order. Proposed order per block, which keeps T5 as agreed: `PREV_HASH_LINK`, `INDEX_SEQUENTIAL`, `BLOCK_HASH_VALID`, `SIGNATURE_VALID`, `CUSTODY_CONTINUITY`, then `FILE_HASH_MATCH`. Does B agree?
- **Q4 Deleting the newest blocks goes undetected:** hash linking catches a removed middle block, but not removing the last few blocks; the shorter chain is still perfectly linked. Proposal: store the chain head (last index + hash) in every `verification_results` row and every exported report, and have the verifier report `FAIL` if the chain is now shorter than a recorded head. Also, the evidence table's `current_custodian_id` will no longer match the chain, which `CUSTODY_CONTINUITY` can check.
- **Q5 Wrong password on transfer or accept:** is it `401 INVALID_CREDENTIALS`? A 401 may make C's frontend think the session ended. Proposal: `403 FORBIDDEN` with its own message, or a new code such as `REAUTH_FAILED`.
- **Q6 Role or visibility first:** a viewer who isn't a member calls `POST /cases/{id}/evidence`. Is that 403 (role checked first) or 404 (visibility checked first)? Proposal: 404 whenever the user can't see the record, so a 403 never confirms that a case exists.
- **Q7 Accept by the wrong analyst:** an analyst who isn't the receiver calls accept. Is that 403 `FORBIDDEN`, 404 or a 409 code?
- **Q8 Success codes:** 201 for creates (case, evidence, transfer, user) and 200 for everything else?
- **Q9 Login response:** what is the field name of the CSRF token in the login response body (for example `csrf_token`)?
- **Q10 Transfer target:** must `to_user_id` be an active analyst who is a member of the case? Transferring to yourself, an admin or a viewer should be rejected; with which code?
- **Q11 Test setup:** A, please expose an app factory and a way to drop and recreate the triggers in tests, so T1 can tamper with a DB copy without editing production code.
