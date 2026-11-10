# ChainTrace Test Plan

Owner: D. Reviewers: A, B, C.

This plan lists every test ChainTrace needs, what each one expects, and whose code it depends on. Expected results come straight from the team's shared formats doc (block format, verification result schema, error codes, audit format, validation limits), plus the follow-up decisions in section 12, which add to that doc. If a format changes there, this plan changes with it.

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
| A | `create_app(settings)` so each test gets its own database | All API and evaluation tests |
| A | Trigger names published as constants | T1 (the test drops the triggers itself in a copy of the database) |
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
| FR-4 Append-only blocks | B (A: triggers, lock) | T1, T5, T5b, trigger tests, concurrent append test |
| FR-5 Verification + result schema | B | T1-T5b, schema shape test, first-failure rule, case scope, verification history test |
| FR-6 Audit log + export | A | Audit tests (section 7), T6 |
| Login, sessions, CSRF, rate limits, password hashing | A | API-AUTH-*, misuse tests (section 5) |
| Role permissions | A | Permission matrix (section 4) |
| Server-side redaction | A | T6, viewer tests |
| Case report export | C | Export tests, T6 |
| Accessibility | C | Manual checklist (section 9) |

## 4. Permission matrix

One parametrized test per cell. "Member" means the user is in `case_members` for that case. Every denial must also write an `ACCESS_DENIED` audit event with outcome `DENIED`.

**Checks run in this order:** session (`401 UNAUTHENTICATED`), then role (`403 FORBIDDEN`), then record lookup and membership (`404 NOT_FOUND`). The role check comes before any lookup, so a 403 is identical for a real case and a made-up ID.

Not logged in → `401 UNAUTHENTICATED` on every route except `POST /auth/login`.

`201` = creates a record or adds a block. `200` = everything else, including verification.

| Route | admin | analyst (member) | analyst (not member) | viewer (member) | viewer (not member) |
|---|---|---|---|---|---|
| `POST /auth/logout`, `GET /auth/me` | 200 | 200 | 200 | 200 | 200 |
| `POST /cases` | 403 | 201 | 201 | 403 | 403 |
| `GET /cases` | 200, all cases | 200, own cases | 200, own cases | 200, own cases | 200, own cases |
| `GET /cases/{id}` | 200 | 200 | 404 | 200, redacted | 404 |
| `POST /cases/{id}/evidence` | 403 | 201 | 404 | 403 | 403 |
| `GET /evidence/{id}` | 200 | 200 | 404 | 200, redacted | 404 |
| `POST /evidence/{id}/transfers` | 403 | 201 if custodian, else 409 `NOT_CUSTODIAN` | 404 | 403 | 403 |
| `POST /transfers/{id}/accept` | 403 | 201 if receiver, else 409 `NOT_RECEIVER` | 404 | 403 | 403 |
| `POST /verify/chain` | 200 | 200 | 200 | 403 | 403 |
| `POST /verify/case/{id}` | 200 | 200 | 404 | 403 | 403 |
| `POST /verify/evidence/{id}` | 200 | 200 | 404 | 403 | 403 |
| `GET /verifications` | 200 | 200 | 200 | 403 | 403 |
| `GET /cases/{id}/export` | 200 | 200 | 404 | 403 | 403 |
| `GET /admin/audit`, `/admin/audit/export` | 200 | 403 | 403 | 403 | 403 |
| `POST /admin/users` | 201 | 403 | 403 | 403 | 403 |
| `PATCH /admin/users/{id}` | 200 | 403 | 403 | 403 | 403 |
| `GET` / `PUT /admin/config` | 200 | 403 | 403 | 403 | 403 |

Extra check: for each 403 cell on a route with an ID, the response for a real ID and for a random UUID must be byte-for-byte identical apart from `request_id`.

## 5. API and misuse tests (`tests/api/`)

**Auth and sessions**
- API-AUTH-01 Correct login returns a session cookie with `HttpOnly` and `SameSite=Strict`, plus `csrf_token` in the body; `GET /auth/me` returns the same `csrf_token`.
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
- API-REG-05 The 11th upload within a minute by one user returns `429 RATE_LIMITED`.

**Transfers (FR-3)**
- API-XFER-01 A valid transfer returns 201 and appends TRANSFER, but custody does not change until ACCEPT.
- API-XFER-02 ACCEPT returns 201, appends a block and moves custody to the receiver.
- API-XFER-03 A wrong password on transfer or accept returns `403 REAUTH_FAILED` (never 401), nothing is appended, and the session still works afterwards.
- API-XFER-04 The 11th transfer within a minute returns `429 RATE_LIMITED`.
- API-XFER-05 An invalid recipient returns `422 INVALID_RECIPIENT` with the same message in every case: an inactive analyst, an analyst who isn't a case member, the sender themselves, an admin, a viewer, and a random UUID.
- API-XFER-06 Accept by a case member who isn't the receiver returns `409 NOT_RECEIVER`.
- API-XFER-07 Accepting a transfer that's already accepted returns `409 TRANSFER_NOT_PENDING`, and nothing is appended.

**Errors**
- API-ERR-01 Every error response matches the envelope `{"error": {"code", "message", "request_id"}}`, and `request_id` is a UUID.
- API-ERR-02 No error body contains a stack trace, SQL, a file path or exception class names.
- API-ERR-03 A non-UUID ID in a URL returns `404 NOT_FOUND`.
- API-ERR-04 Unknown JSON fields return `400 VALIDATION_ERROR`.

**Injection**
- API-INJ-01 SQL-like input (`' OR 1=1 --`) in the username, title and reason is stored as plain text and changes nothing else.
- API-INJ-02 `<script>` in a title or reason comes back unchanged as JSON data (C's pages must show it as text, see section 9).

**Ledger safety**
- API-LEDGER-01 `UPDATE` and `DELETE` on `blocks`, `audit_events` and `verification_results` are rejected by the triggers.
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
- AUD-06 Every `VERIFICATION_RUN` event records `head_index` and `head_hash`, matching the stored verification result.
- AUD-05 Never-log scan: after a full workflow, no audit row, server log line or export contains a password, session ID, CSRF token, private key, the master key or file contents (searched using the real values from the test run).

## 8. Evaluation tests (`tests/evaluation/`)

Each test copies the seeded state, breaks exactly one thing, and asserts on the exact check name and block index.

| ID | Setup | Expected result |
|---|---|---|
| T1 Tampered record | Copy the DB file, drop the triggers in the copy with plain `sqlite3` (using A's trigger-name constants), edit `payload_json` of block 5 | `FAIL`, `first_failure` = `BLOCK_HASH_VALID` at block 5 |
| T2 Altered file | Flip one byte of `storage/evidence/<id>.bin` | `FAIL`, `FILE_HASH_MATCH` for that evidence; other evidence still passes |
| T3 Invalid signature | (a) transfer signed with another user's key; (b) a stored block with one signature byte flipped | (a) `422 INVALID_SIGNATURE`, nothing appended; (b) `FAIL` at `SIGNATURE_VALID` |
| T4 Duplicate transfer | (a) same transfer sent twice; (b) a transfer while one is pending; (c) a transfer by a non-custodian | `409 DUPLICATE_TRANSFER` / `409 NOT_CUSTODIAN`; block count unchanged |
| T5 Chain validation | Clean chain of 50+ blocks; then delete a middle block | `PASS` with empty `checks` on the clean chain; `FAIL` with `first_failure` = `PREV_HASH_LINK` at the gap (`INDEX_SEQUENTIAL` is also listed in `checks`) |
| T5b Truncation | Verify the clean chain (records the head); delete the newest 3 blocks; verify again. Separately: replace the head block with a different valid-looking block | `FAIL` at `CHAIN_HEAD_CONSISTENT` in both cases |
| T6 Privacy review | Viewer opens a case and evidence; admin exports a report and the audit log | Viewer sees no file names, descriptions, reasons or usernames; no secrets anywhere (AUD-05) |
| T-final | Malformed JSON, 30 MB file, fake `.png`, wrong-role request, repeated submit, server restart mid-workflow | Correct error codes, no stack traces, data intact after restart, chain still `PASS` |

**Every result is also checked for shape:** all fields of the verification result schema are present, including `head_index` and `head_hash`. A `FAIL` result lists every failure in `checks`, and `first_failure` is the failure with the lowest block index; within one block, the first check in the agreed order wins (section 12, decision 3). A `PASS` result has an empty `checks` list.

**Case scope:** `POST /verify/case/{id}` checks the chain links plus the blocks and file hashes of every evidence item in that case. Tested with T2 (altered file in the case → `FAIL`; altered file in another case → `PASS`).

**Exports:** every case report export (JSON and PDF) includes the head recorded at export time.

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
| False negatives | 0 | Verify every tampered fixture (T1, T2, T3b, T5, T5b); any `PASS` is a false negative |
| Verification time | reported | Median of 5 runs of `POST /verify/chain` at 100, 1,000 and 10,000 blocks |
| API latency | reported | Median and 95th percentile over 30 calls each for register, transfer and verify |

## 11. Done means

- Every row in sections 3 to 8 has a test, and every test is in the results table.
- Pass rate is at least 80%, with 0 false positives and 0 false negatives.
- T1-T6, T5b and T-final all pass.
- No test is skipped without a written reason.

## 12. Team decisions (Nov 10, 2026)

These answer the questions raised on the first draft of this plan and add to the shared formats doc.

1. **Upload rate limit:** 10 uploads per minute per user (`RATE_LIMIT_UPLOAD=10/minute`). Test: API-REG-05.
2. **Case verification:** new route `POST /verify/case/{id}`. It checks the chain links, plus the blocks and file hashes of every evidence item in that case.
3. **Check order:** per block, `PREV_HASH_LINK`, `INDEX_SEQUENTIAL`, `BLOCK_HASH_VALID`, `SIGNATURE_VALID`, `CUSTODY_CONTINUITY`. Then `FILE_HASH_MATCH` per evidence item, then `CHAIN_HEAD_CONSISTENT`. Every failure is listed in `checks`. `first_failure` is the failure with the lowest block index; within one block, the first check in this order wins.
4. **New check `CHAIN_HEAD_CONSISTENT`:** every verification records the chain head (`head_index`, `head_hash`) in its result, its audit event and every export. A later verification fails if the chain is shorter than the last recorded head, or if the block at that index has a different hash. `verification_results` also gets append-only triggers. Limitation: someone with full database access could wipe the blocks, the stored results and the audit events together, so an exported head kept off the machine is the real anchor. Test: T5b.
5. **Wrong password on transfer or accept:** `403 REAUTH_FAILED`. 401 always means the session ended. Test: API-XFER-03.
6. **Check order for access:** session (401), then role (403), then record lookup and membership (404). A 403 looks the same for a real case and a made-up one. Test: permission matrix.
7. **Accept by the wrong person:** a case member who isn't the receiver gets `409 NOT_RECEIVER`; a non-member gets 404; an already-accepted transfer gets `409 TRANSFER_NOT_PENDING`. Tests: API-XFER-06, API-XFER-07.
8. **Success codes:** 201 for anything that creates a record or adds a block (case, evidence, transfer, accept, user); 200 for everything else, including verification.
9. **CSRF token:** `csrf_token` in the login response body; `GET /auth/me` returns it too. Test: API-AUTH-01.
10. **Transfer target:** `to_user_id` must be an active analyst, a member of the case, and not the sender. Any failure returns `422 INVALID_RECIPIENT` with one generic message. Test: API-XFER-05.
11. **Test hooks:** A exposes `create_app(settings)` and publishes the trigger names as constants. There is no trigger-dropping code in the app; T1 drops the triggers itself in a copy of the database.

**New error codes** to add to the shared error table: `403 REAUTH_FAILED`, `409 NOT_RECEIVER`, `409 TRANSFER_NOT_PENDING`, `422 INVALID_RECIPIENT`.

### Still to confirm (B)

The test helpers assume these; tell D if any is wrong.

- `head_index` and `head_hash` are top-level fields of the verification result.
- A `CHAIN_HEAD_CONSISTENT` failure reports the recorded head's index as its `block_index`.
- `FILE_HASH_MATCH` failures have `block_index` set to null (they are per evidence item, not per block), so they sort after every per-block failure. If they report the REGISTER block's index instead, the first-failure rule still works, but T2's expected values change.
- The very first verification, with no head recorded yet, passes `CHAIN_HEAD_CONSISTENT`.
