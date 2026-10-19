# OpenAI Codex Token Import and Validation

Use this when a supplied JSON bundle contains OpenAI/ChatGPT Codex session JWTs, especially an `import_req.json` shape such as:

```json
{
  "contents": ["eyJ...", "eyJ..."],
  "update_existing": true,
  "concurrency": 10,
  "priority": 1,
  "rate_multiplier": 1
}
```

## Safe inspection

Decode only the JWT payload locally; never print complete tokens. Record:

- `exp`, `iat`, `jti`, `session_id`
- `sub`
- `https://api.openai.com/auth.chatgpt_account_id`
- `https://api.openai.com/auth.chatgpt_account_user_id` / `chatgpt_user_id`
- `https://api.openai.com/auth.chatgpt_plan_type`
- profile email only if operationally necessary

A future `exp` proves only that the JWT is structurally unexpired. OpenAI may revoke it early.

## Deduplication rule

**Do not deduplicate only by `chatgpt_account_id`.** Team, EDU, K-12, Enterprise, or shared workspaces can have many users and sessions under one account ID. Account-only dedupe silently discards valid credentials.

Preferred identity, in order:

1. Exact token hash for exact duplicates.
2. `(chatgpt_account_id, chatgpt_account_user_id or chatgpt_user_id, session_id)`.
3. `(chatgpt_account_id, sub, session_id)`.
4. `jti` as a final token-level identity.

Retain multiple sessions for one workspace unless the user explicitly requests one credential per account.

## Import into a running load balancer

Avoid editing the credential JSON from a separate CLI while the service keeps an in-memory copy. The running process may later persist its stale snapshot and erase the import.

Preferred approaches:

1. Authenticated admin import endpoint handled by the running service.
2. Transactional database/repository shared by CLI and service.
3. If neither exists: stop service, back up store, import atomically, then restart and verify.

When updating an existing record, do not erase a valid refresh token merely because the import bundle contains only an access token.

## Live validity probe

For the ChatGPT Codex backend, include both:

```http
Authorization: Bearer <access-token>
Chatgpt-Account-Id: <chatgpt_account_id>
```

Probe the actual Codex endpoint with a minimal request. Sanitize output to status and error code only.

Common authoritative failures:

- `token_invalidated`: access token was revoked despite future `exp`.
- `refresh_token_reused`: rotating refresh token was already consumed.
- `refresh_token_invalidated`: session ended or refresh token revoked.
- `invalid_refresh_token`: cannot recover without signing in again.

These are credential terminal states, not load-balancer/network failures. Mark the affected credential unavailable, but do not infer that other credentials sharing the same workspace account are invalid without probing them individually.

## Verification checklist

- Count input tokens, exact duplicates, unique users, unique sessions, and unique workspace accounts separately.
- Import all intended token identities.
- Read back the running service's credential count; do not trust only the importer output.
- Check readiness using unexpired and non-revoked credentials, not a persisted `is_alive` flag alone.
- Execute one real non-stream request and one stream request.
- Verify per-credential 401/429 isolation and that one failed token does not poison all users in the same workspace.
- Keep a timestamped pre-import backup until live calls succeed.
