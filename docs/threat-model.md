# ChainTrace Threat Model

Owner: D. Crypto threats reviewed by B, web threats reviewed by A.

Every threat is mapped to the agreed design that stops it and to the test that proves it. Test IDs refer to [test-plan.md](test-plan.md). Mitigations come from the team's shared formats doc; where the design doesn't cover a threat fully, the gap is listed under "Remaining risk" and goes in the report's limitations section.

## What we protect

| Asset | Why it matters |
|---|---|
| Ledger (`blocks` table) | The custody record; if it can be changed silently, the system proves nothing |
| Evidence files in `storage/` | Must be byte-for-byte what was registered |
| Users' private signing keys | Whoever holds one can sign custody events as that user |
| `CHAINTRACE_MASTER_KEY` | Decrypts every private key |
| Passwords and sessions | Give access to everything the user can do |
| Case details | File names, descriptions and reasons must not reach viewers or other cases |
| Audit log | Shows who did what, including failures and denials |

## Who might attack

| Attacker | Can do |
|---|---|
| Outsider | Send any HTTP request; guess passwords; trick a logged-in user's browser into sending requests |
| Viewer or analyst going beyond their role | Log in normally, then call routes or open records they shouldn't |
| Someone with access to the database or disk | Edit, insert or delete rows and files directly, bypassing the app |
| Fully compromised server | Everything above, plus run code with the master key |

## Trust boundaries

1. **Browser → API.** Nothing from the browser is trusted: role checks, validation and redaction all happen on the server. The frontend only hides buttons.
2. **API → database and storage.** The app trusts its own writes, but the verifier assumes stored data may have been changed since and re-checks everything.
3. **Server → master key.** The key comes from `.env`, outside the database, so a stolen database alone doesn't reveal private keys.

## Threats

| ID | Threat | Mitigation | Owner | Test | Remaining risk |
|---|---|---|---|---|---|
| TM-01 | **Edited block.** Someone changes a block's payload directly in the database. | `block_hash` covers all signing fields and the signature; the verifier recomputes it. Triggers reject `UPDATE`/`DELETE` through normal access. | B (A: triggers) | T1, API-LEDGER-01 | Detected, not prevented: anyone with file access can drop the triggers. |
| TM-02 | **Altered evidence file.** A stored file is changed on disk. | SHA-256 recorded at REGISTER; the verifier re-hashes the file. | B | T2 | Detected only when verification runs. |
| TM-03 | **Forged signature.** A transfer is signed with another user's key, or a signature is altered. | Ed25519 signature checked against the signer's stored public key on append and during verification. | B | T3 | None in the design. |
| TM-04 | **Duplicate or unauthorized transfer.** The same transfer is replayed, a second one is sent while one is pending, or a non-custodian transfers. | Signer must be `current_custodian_id`; no pending transfer allowed; `transfer_id` must be new; custody moves only on ACCEPT. | B (A: endpoints) | T4 | None in the design. |
| TM-05 | **Deleted, inserted or reordered block, or newest blocks removed (truncation).** | `prev_hash` linking and sequential `index` checks catch changes inside the chain. For truncation, every verification records the chain head (`head_index`, `head_hash`) in its result, audit event and exports; `CHAIN_HEAD_CONSISTENT` fails if the chain is shorter or the block at that index has changed. | B (A: triggers on `verification_results`) | T5, T5b | Someone with full database access can wipe the blocks, stored results and audit events together. An exported head kept off the machine is the real anchor. |
| TM-06 | **Two appends race for the same index.** Two requests at once produce a forked chain. | Appends run in one database transaction; `index` is the primary key. | A + B | API-LEDGER-02 | None in the design. |
| TM-07 | **Data leaks to viewers or exports.** File names, reasons or usernames reach a viewer; secrets end up in exports or logs. | Server-side redaction for viewers and reports; "never log" list in the audit format. | A (C: display) | T6, AUD-05 | None in the design. |
| TM-08 | **Access to another case by ID (IDOR), or probing whether a case exists.** A user changes the ID in the URL. | Checks run session (401) → role (403) → lookup and membership (404). A forbidden role gets the same 403 for real and made-up IDs; a non-member gets 404. | A | Permission matrix (test plan section 4) | None in the design. |
| TM-09 | **Password guessing.** | Argon2id hashes; 5 login attempts per minute per IP + username; same message for wrong username and wrong password. | A | API-AUTH-02, API-AUTH-03, API-AUTH-07 | Slow guessing spread across many IPs is only slowed down, not stopped. |
| TM-10 | **CSRF.** Another site makes the user's browser send a transfer. | `SameSite=Strict` cookie plus `X-CSRF-Token` header on every state-changing request. | A | API-CSRF-01, API-CSRF-02 | None in the design. |
| TM-11 | **Stolen or reused session.** | `HttpOnly` cookie, 30-minute idle expiry, session deleted on logout; transfer and accept also re-ask for the password. | A | API-AUTH-01, API-AUTH-04, API-AUTH-05, API-XFER-03 | `SESSION_COOKIE_SECURE=false` in development means cookies travel over plain HTTP; it must be `true` in any real deployment. |
| TM-12 | **Malicious upload.** A disguised file type, a huge file or a file name like `../../x` used to escape the storage folder. | Magic-byte type check; size limit; file names sanitized and never used in paths (files stored as `<id>.bin`); 26 MB request limit. | A | Validation boundaries (test plan section 6), API-REG-04, T-final | Allowed types such as `.pdf` and `.zip` can still carry malware; files are stored, never opened or run, by the server. |
| TM-13 | **Stolen private keys.** The database is copied and keys are read from it. | Private keys encrypted with Fernet using the master key from `.env`, which is not in the database. | B | Unit test: stored key isn't a raw Ed25519 key and only decrypts with the master key | If the database and `.env` are taken together, all keys are exposed. |
| TM-14 | **Compromised server signs for users.** | Admin is never a custodian; every signing action is in the audit log; re-authentication before signing. | B | Stated limitation | **Not prevented:** the server holds the encrypted keys and the master key. Browser-side signing (WebCrypto) is the stronger design. |
| TM-15 | **Audit log tampering or denial.** A user denies an action, or someone edits audit rows to hide it. | Every security action writes an audit event (including denials); triggers make `audit_events` append-only; TRANSFER and ACCEPT are also signed in the ledger. | A | AUD-01, API-LEDGER-01 | Audit events aren't hash-linked, so someone with database access can drop the triggers and edit them undetected. |
| TM-16 | **Error messages reveal internals.** Stack traces, SQL or file paths in responses help an attacker. | Fixed error envelope; unexpected errors return `500 INTERNAL_ERROR` with details only in the server log. | A | API-ERR-01, API-ERR-02, T-final | None in the design. |
| TM-17 | **Injection.** SQL injection through inputs, or script injection (XSS) through titles and reasons. | SQLAlchemy parameterized queries; descriptions and reasons stored as plain text and shown as text by the frontend. | A (C: display) | API-INJ-01, API-INJ-02, manual check (test plan section 9) | None in the design. |
| TM-18 | **Flooding or brute force.** Repeated transfers to guess a password, or mass uploads to fill the ledger and disk. | 10 transfers and 10 uploads per minute per user; password re-check before signing returns `403 REAUTH_FAILED`. | A | API-XFER-03, API-XFER-04, API-REG-05 | Many accounts working together can still upload 10 files each per minute. |
| TM-19 | **Finding out who exists through transfers.** Trying `to_user_id` values to learn which users exist, their roles or case membership. | Any invalid recipient returns `422 INVALID_RECIPIENT` with one generic message, whichever rule failed. | A | API-XFER-05 | None in the design. |

## Rows to confirm

- **B:** TM-01 to TM-06, TM-13, TM-14. Is anything missing on the crypto side (for example key rotation, or what happens when a user is deactivated)?
- **A:** TM-07 to TM-12 and TM-15 to TM-19.
- **Team:** keep exported heads somewhere off the server (for example, attached to the case file), since that is the anchor TM-05 relies on.
