# API Validation Endpoints

Post-extraction validation: query each provider's balance/status API to check which keys are still active and have remaining quota.

## DeepSeek

```bash
curl -L -X GET 'https://api.deepseek.com/user/balance' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer <TOKEN>'
```

Response:
```json
{
  "is_available": true,
  "balance_infos": [
    {
      "currency": "CNY",
      "total_balance": "110.00",
      "granted_balance": "10.00",
      "topped_up_balance": "100.00"
    }
  ]
}
```

Invalid key returns: `{"error":{"message":"Authentication Fails, Your api key: ****XXXX is invalid"}}`

## OpenAI

```bash
# Check key validity + org
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer <TOKEN>" | head -c 200

# Check subscription/billing (requires dashboard access, not API)
curl https://api.openai.com/dashboard/billing/credit_grants \
  -H "Authorization: Bearer <TOKEN>"
```

Invalid key returns HTTP 401.

## Anthropic

```bash
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: <TOKEN>" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}'
```

Check HTTP status: 200 = valid, 401 = invalid key.

## Google Gemini

```bash
curl "https://generativelanguage.googleapis.com/v1beta/models?key=<TOKEN>"
```

Invalid key returns: `{"error":{"code":400,"message":"API key not valid"}}`

## OpenRouter

```bash
curl https://openrouter.ai/api/v1/auth/key \
  -H "Authorization: Bearer <TOKEN>"
```

Returns: `{"data":{"label":"...","usage":0,"limit":null,"is_free_tier":false}}`

## Moonshot (Kimi)

```bash
curl https://api.moonshot.cn/v1/models \
  -H "Authorization: Bearer <TOKEN>"
```

## Groq

```bash
curl https://api.groq.com/openai/v1/models \
  -H "Authorization: Bearer <TOKEN>"
```

## Batch Validation Pattern

For validating many keys of the same provider, use a Python loop with subprocess:

```python
import json, subprocess

for key in keys:
    r = subprocess.run(
        ['curl', '-sS', '-L', '-X', 'GET',
         'https://api.deepseek.com/user/balance',
         '-H', 'Accept: application/json',
         '-H', f'Authorization: Bearer ***         '--max-time', '10'],
        capture_output=True, text=True, timeout=15
    )
    resp = json.loads(r.stdout)
    if 'balance_infos' in resp:
        total = float(resp['balance_infos'][0]['total_balance'])
        print(f"✅ {key[:15]}... ¥{total:.2f}")
    else:
        print(f"❌ {key[:15]}... invalid")
```

## Observed Real-World Stats (2026-07-09)

From a 74K-line bash_history dump:
- 9 DeepSeek keys found, 6 valid (66%)
- Total balance across valid keys: ¥124.98 CNY
- All balance was topped_up (充值), zero granted balance
