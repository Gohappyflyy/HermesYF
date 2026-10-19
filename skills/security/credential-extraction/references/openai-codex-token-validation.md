# OpenAI Codex token validation and import

## Field classification

| Field | Use |
|---|---|
| `access_token` | Bearer for model requests |
| `id_token` | Identity only; do not import as access |
| `refresh_token` | Rotating OAuth credential |
| `account_id` / JWT `chatgpt_account_id` | Send as `Chatgpt-Account-Id` |

## Validity rules

- Future JWT `exp` is not proof of validity.
- Terminal upstream errors:
  - `token_invalidated`
  - `refresh_token_reused`
  - `refresh_token_invalidated`
  - `invalid_refresh_token`
- Concurrent or repeated refresh can invalidate/reuse refresh tokens.
- Report local-unexpired separately from upstream-valid.

## Internal Codex endpoint

`POST https://chatgpt.com/backend-api/codex/responses`

Required:

```http
Authorization: Bearer <access_token>
Chatgpt-Account-Id: <chatgpt_account_id>
Content-Type: application/json
```

Body constraints:

- `input` must be a list
- `stream` must be `true`
- `store` usually `false`

Non-stream adapters must:

1. Force upstream SSE
2. Collect `response.output_item.done`
3. On `response.completed` / `response.incomplete`, attach collected output if `response.output` is empty
4. Convert to Chat Completions JSON

## Model probe notes (ChatGPT OAuth)

Latest live probe:

| Model | Result |
|---|---|
| `gpt-5.6-sol` | accepted |
| `gpt-5.6-terra` | accepted |
| bare `gpt-5.6` | rejected with ChatGPT account |
| `gpt-5.6-sol-pro` | rejected |
| `gpt-5.6-luna` | not found / rejected |
| `gpt-5.5` / `gpt-5.4` | accepted |

Do not validate credentials only by decoding JWT claims. Make a minimal real request and require either model content or a clear terminal error.

## Import sequencing

1. Prefer live service import (`/admin/import`, `/admin/import-auth`) while proxy is running.
2. Deduplicate by `refresh_token` or `chatgpt_account_id`.
3. Keep source server/path metadata for fleet discoveries.
4. After import, hit readiness and a real chat completion.

## Hermes naming

Hermes commonly uses `gpt-5.6-sol`. That is a real 5.6 family ID on Codex OAuth and should not be rewritten to `gpt-5.5`.
