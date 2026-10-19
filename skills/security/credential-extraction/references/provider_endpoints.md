# Provider Default Endpoints

When no explicit `base_url`/`baseUrl` is found in context, infer the endpoint from the provider name or key prefix.

## By Key Prefix

| Prefix | Endpoint |
|--------|----------|
| `sk-ant-` | `https://api.anthropic.com` |
| `sk-pro` | `https://api.openai.com/v1` |
| `sk-svc` | `https://api.openai.com/v1` |
| `sk-or-` | `https://openrouter.ai/api/v1` |
| `sk-cp-` | varies (MiniMax: `https://api.minimax.chat/v1`, Cursor: `https://api.cursor.com/v1`) |
| `sk-` | varies (check context for base_url) |
| `AIza` | `https://generativelanguage.googleapis.com` |
| `AQ.` | `https://generativelanguage.googleapis.com/v1beta/openai/` |
| `gsk_` | `https://api.groq.com/openai/v1` |
| `pplx-` | `https://api.perplexity.ai` |
| `nvapi-` | `https://integrate.api.nvidia.com/v1` |
| `rc_` | `https://api.featherless.ai/v1` |
| `cpa_` | `https://cpa.078463.xyz/v1` (Codepilot proxy, varies) |
| `ark-` | `https://ark.cn-beijing.volces.com/api/v3` |
| `BSA` | `https://api.search.brave.com` |
| `tvly-` | `https://api.tavily.com` |
| `fk-` | `https://api.felo.ai` |
| `tp-` | `https://token-plan-cn.xiaomimimo.com/v1` |
| `openclawx_` | `https://openclawx.ai/api/v1` |
| `hf_` | `https://api-inference.huggingface.co` |
| `re_` | `https://api.resend.com` |
| `apify_` | `https://api.apify.com` |

## By Variable Name

| Name contains | Endpoint |
|---------------|----------|
| `DEEPSEEK` | `https://api.deepseek.com/v1` |
| `MOONSHOT` / `KIMI` | `https://api.moonshot.cn/v1` |
| `MISTRAL` | `https://api.mistral.ai/v1` |
| `GLM` / `ZEROCLAW` | `https://open.bigmodel.cn/api/paas/v4` |
| `DASHSCOPE` / `QWEN` | `https://dashscope.aliyuncs.com/compatible-mode/v1` |
| `VOLCANO` / `VOLCENGINE` | `https://ark.cn-beijing.volces.com/api/v3` |
| `GEMINI` / `GOOGLE` | `https://generativelanguage.googleapis.com` |
| `ANTHROPIC` / `CLAUDE` | `https://api.anthropic.com` |
| `GROQ` | `https://api.groq.com/openai/v1` |
| `NOUS` | `https://api.nousresearch.com/v1` |
| `MINIMAX` | `https://api.minimax.chat/v1` |
| `BRAVE` | `https://api.search.brave.com` |
| `TAVILY` | `https://api.tavily.com` |
| `FELO` | `https://api.felo.ai` |

## GLM Format (hex32.alnum16)

GLM keys have format `[32-char hex].[16-char alnum]`. Default endpoint: `https://open.bigmodel.cn/api/paas/v4`.
Some configs point to: `https://api.z.ai/api/paas/v4` or `https://open.bigmodel.cn/api/anthropic`.

## Context-Dependent Endpoints

For `sk-` keys (OpenAI-compatible), the endpoint varies wildly across dumps. Common patterns observed:
- `https://api.deepseek.com/v1` (DeepSeek)
- `https://api.moonshot.cn/v1` (Moonshot/Kimi)
- `http://47.81.29.100:8080/v1` (private proxy)
- `http://localhost:PORT/v1` (local proxy)
- `https://codex.hualong.site/v1/chat/completions` (third-party relay)
- `http://193.112.244.148:8080` (private relay)
- `http://cccai.cfd` (free relay)
- `https://api.aiwsy.cn/v1` (third-party)
- `https://aixj.vip/v1` (third-party)
- `https://bobdong.cn/v1` (third-party)

**Always search the surrounding context for `base_url`/`baseUrl` before falling back to defaults.**
