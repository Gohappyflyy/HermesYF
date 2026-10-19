#!/usr/bin/env python3
"""
Credential Extraction Script (with endpoint association)
=========================================================
Scans any text file for API keys, tokens, and secrets across 25+ AI providers.
Outputs JSON grouped by provider with line numbers AND API endpoints.

Usage:
    python3 extract_credentials.py <filepath> [--output out.json] [--no-endpoints] [--summary-only]

Endpoint association:
  1. JSON "baseUrl" near "apiKey" (±20 lines)
  2. YAML base_url: near api_key: (±15 lines)
  3. curl URL on same line (for Bearer tokens)
  4. OPENAI_BASE_URL env var nearby (±5 lines)
  5. Fallback: infer from key name / value prefix (provider defaults)
"""

import re
import json
import sys
import argparse
from collections import defaultdict


def has_cjk(text):
    for c in text:
        if '\u4e00' <= c <= '\u9fff' or '\u3040' <= c <= '\u30ff' or '\uac00' <= c <= '\ud7af':
            return True
    return False


SKIP_SUBSTRINGS = [
    'your_', 'YOUR_', 'placeholder', 'example', 'DEIN_', 'DEINE_',
    'env:', 'TA_NOUVELLE', 'sk-xxx', 'sk-kimi-', 'not-ne', 'remov',
    '<remov', 'your-', 'YOUR-',
]


def is_placeholder(val):
    if val.startswith('<') or val.startswith('${') or val.startswith('$'):
        return True
    if len(val) < 15:
        return True
    if has_cjk(val):
        return True
    val_lower = val.lower()[:15]
    for s in SKIP_SUBSTRINGS:
        if s.lower() in val_lower:
            return True
    return False


def is_telegram_bot_token(val):
    return bool(re.match(r'^\d{8,12}:[A-Za-z0-9_-]{30,}$', val))


# ============================================================
# Provider identification
# ============================================================

def identify_provider(val, name=''):
    prefix_map = [
        ('sk-ant-',   'Anthropic (Claude)'),
        ('AIza',      'Google Gemini'),
        ('sk-or-',    'OpenRouter'),
        ('sk-pro',    'OpenAI'),
        ('sk-svc',    'OpenAI Service'),
        ('gsk_',      'Groq'),
        ('pplx-',     'Perplexity'),
        ('nvapi-',    'NVIDIA'),
        ('rc_',       'Featherless'),
        ('sk-cp-',    'Cerebras/Codepilot/MiniMax'),
        ('ark-',      'Volcano Engine'),
        ('BSA',       'Brave Search'),
        ('tvly-',     'Tavily'),
        ('fk-',       'FELO'),
        ('cpa_',      'Codepilot'),
        ('tp-',       'TurnPanel'),
        ('openclawx_','OpenClaw'),
        ('hf_',       'HuggingFace'),
        ('re_',       'Resend'),
        ('apify_',    'Apify'),
        ('ak_',       'Lovart'),
        ('sk_',       'Lovart/Custom'),
        ('cfut_',     'Cloudflare'),
        ('eyJ',       'JWT Token'),
        ('AQ.',       'Google Cloud'),
    ]
    for prefix, provider in prefix_map:
        if val.startswith(prefix):
            return provider

    name_upper = name.upper()
    name_map = [
        ('GEMINI', 'Google Gemini'), ('GOOGLE', 'Google Gemini'),
        ('GLM', 'GLM'), ('ZEROCLAW', 'GLM'),
        ('DASHSCOPE', 'Alibaba DashScope'),
        ('MISTRAL', 'Mistral'), ('NOUS', 'Nous Research'),
        ('MOONSHOT', 'Moonshot (Kimi)'), ('KIMI', 'Moonshot (Kimi)'),
        ('DEEPSEEK', 'DeepSeek'), ('MINIMAX', 'MiniMax'),
        ('FELO', 'FELO'), ('IMA', 'Tencent IMA'),
        ('VOLCANO', 'Volcano Engine'), ('VOLCENGINE', 'Volcano Engine'),
        ('N8N', 'N8N'), ('BRAVE', 'Brave Search'),
        ('TAVILY', 'Tavily'), ('RESEND', 'Resend'),
        ('APIFY', 'Apify'), ('LOVART', 'Lovart'),
        ('DIDI', 'DiDi MCP'), ('QWEN', 'Qwen'),
        ('CURSOR', 'Cursor'), ('EVOLINK', 'EVOLINK'),
    ]
    for keyword, provider in name_map:
        if keyword in name_upper:
            return provider

    if re.match(r'^[a-f0-9]{32}\.[A-Za-z0-9]{16}$', val):
        return 'GLM'
    if val.startswith('sk-'):
        return 'OpenAI Compatible'
    return 'Unknown'


# ============================================================
# Endpoint association
# ============================================================

PROVIDER_DEFAULT_ENDPOINTS = {
    'Anthropic (Claude)': 'https://api.anthropic.com',
    'OpenAI': 'https://api.openai.com/v1',
    'OpenAI Service': 'https://api.openai.com/v1',
    'Google Gemini': 'https://generativelanguage.googleapis.com',
    'Google Cloud': 'https://generativelanguage.googleapis.com/v1beta/openai/',
    'OpenRouter': 'https://openrouter.ai/api/v1',
    'Groq': 'https://api.groq.com/openai/v1',
    'Perplexity': 'https://api.perplexity.ai',
    'DeepSeek': 'https://api.deepseek.com/v1',
    'Moonshot (Kimi)': 'https://api.moonshot.cn/v1',
    'Mistral': 'https://api.mistral.ai/v1',
    'GLM': 'https://open.bigmodel.cn/api/paas/v4',
    'Qwen': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    'Alibaba DashScope': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    'Volcano Engine': 'https://ark.cn-beijing.volces.com/api/v3',
    'MiniMax': 'https://api.minimax.chat/v1',
    'Brave Search': 'https://api.search.brave.com',
    'Tavily': 'https://api.tavily.com',
    'Nous Research': 'https://api.nousresearch.com/v1',
    'FELO': 'https://api.felo.ai',
    'NVIDIA': 'https://integrate.api.nvidia.com/v1',
    'Featherless': 'https://api.featherless.ai/v1',
    'Codepilot': 'https://api.codepilot.ai/v1',
    'HuggingFace': 'https://api-inference.huggingface.co',
    'OpenClaw': 'https://openclawx.ai/api/v1',
    'Resend': 'https://api.resend.com',
    'Apify': 'https://api.apify.com',
}


def _block_bounds(lines, idx):
    """返回 idx 所在「段落」的 [start, end) —— 以空行为界。
    避免在密集 dump 里把隔壁块的 endpoint 错安到本块的 key 上。"""
    s = idx
    while s > 0 and lines[s - 1].strip():
        s -= 1
    e = idx
    while e < len(lines) and lines[e].strip():
        e += 1
    return s, e


def find_endpoint(lines, line_idx, name, val, provider, search_range=8):
    """Find the API endpoint for a key at line_idx (0-based).
    优先级: 同行 curl > 同段落显式 endpoint 字段 > provider 默认值。"""
    OPENAI_FAMILY = {
        'OpenAI', 'OpenAI Service', 'OpenAI Compatible', 'DeepSeek', 'Moonshot (Kimi)',
        'Groq', 'Mistral', 'Qwen', 'Alibaba DashScope', 'Volcano Engine', 'MiniMax',
        'GLM', 'Nous Research', 'FELO', 'NVIDIA', 'Featherless', 'Codepilot',
        'OpenRouter', 'OpenClaw', 'Cursor', 'EVOLINK', 'TurnPanel', 'Lovart',
        'Lovart/Custom', 'Tencent IMA', 'DiDi MCP', 'N8N', 'Unknown',
    }
    is_openai_family = provider in OPENAI_FAMILY or 'OPENAI' in name.upper()

    # 1. 同行 curl 的 URL 就是 endpoint
    if 'curl' in lines[line_idx]:
        for pat in (r'(https?://[^\s"\'<>]+)',):
            for m in re.finditer(pat, lines[line_idx]):
                return m.group(1).rstrip('.,;)')

    # 2. 只在本段落内找显式字段
    bs, be = _block_bounds(lines, line_idx)
    block = range(max(bs, line_idx - search_range), min(be, line_idx + search_range + 1))

    for idx in block:
        # JSON "baseUrl" / "url"
        for m in re.finditer(r'"baseUrl"\s*:\s*"(https?://[^"]+)"', lines[idx]):
            return m.group(1)
        for m in re.finditer(r'"url"\s*:\s*"(https?://[^"]+)"', lines[idx]):
            return m.group(1)
        # YAML / env base_url
        for m in re.finditer(r'\bbase_url\s*[:=]\s*["\']?(https?://[^\s"\'<>]+)', lines[idx], re.IGNORECASE):
            return m.group(1).rstrip('"\'')
        # OPENAI_BASE_URL —— 只对 OpenAI 兼容族生效
        if is_openai_family:
            for m in re.finditer(r'(?:OPENAI_BASE_URL|API_BASE)\s*[:=]\s*["\']?(https?://[^\s"\'<>]+)',
                                  lines[idx], re.IGNORECASE):
                return m.group(1).rstrip('"\'')

    # 3. Fallback: provider default
    return PROVIDER_DEFAULT_ENDPOINTS.get(provider, '')


# ============================================================
# Main extraction
# ============================================================

SKIP_NAMES = ('UPLOAD_TOKEN', 'ADMIN_TOKEN', 'OPENNEWS_TOKEN', 'TELEGRAM_TOKEN',
              'TWITTER_BEARER_TOKEN', 'TWITTER_AUTH_TOKEN', 'CF_API_TOKEN',
              'secret_token', 'botToken', 'appToken', 'HA_TOKEN')


def extract_from_file(filepath, with_endpoints=True):
    all_keys = []
    seen = set()

    with open(filepath, 'r', errors='replace') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        ls = line.strip()
        extractions = []

        # export VAR="value" / VAR=value（引号可有可无）
        for m in re.finditer(
            r'(?:export\s+)?([A-Z_][A-Z0-9_]*(?:API_KEY|APIKEY|AUTH_TOKEN|KEY)[A-Z0-9_]*)\s*=\s*["\']?([^"\'\s]{10,})["\']?',
            ls
        ):
            extractions.append(('env', m.group(1), m.group(2)))

        # JSON "apiKey": "value"
        for m in re.finditer(r'"apiKey"\s*:\s*"([^"]{15,})"', ls):
            extractions.append(('json', 'apiKey', m.group(1)))

        # JSON "SOME_API_KEY": "value"
        for m in re.finditer(r'"([A-Z_]*(?:API_KEY|KEY|TOKEN)[A-Z_]*)"\s*:\s*"([^"]{15,})"', ls):
            extractions.append(('json_named', m.group(1), m.group(2)))

        # YAML api_key: value
        for m in re.finditer(r'(?:^|\s)api_key:\s*["\']?([^"\'\s$>]{15,})', ls):
            v = m.group(1)
            if not v.startswith('env:'):
                extractions.append(('yaml', 'api_key', v))

        # openclaw secrets set
        for m in re.finditer(r'openclaw secrets set\s+(\S+)\s+(\S{15,})', ls):
            extractions.append(('openclaw', m.group(1), m.group(2)))

        # /config set
        for m in re.finditer(r'/config set\s+(\S+)\s+(\S{15,})', ls):
            extractions.append(('config', m.group(1), m.group(2)))

        # echo "KEY=value"
        for m in re.finditer(
            r'echo\s+["\']([^"\'=]*(?:API_KEY|TOKEN|SECRET)[^"\'=]*)=([^"\'\s>]{15,})',
            ls
        ):
            extractions.append(('echo', m.group(1), m.group(2)))

        # Bearer token in curl
        for m in re.finditer(r'-H\s+["\']Authorization:\s*(?:Bearer\s+)?([^"\']{15,})["\']', ls):
            v = m.group(1).strip()
            if not v.startswith('$'):
                extractions.append(('bearer', 'Authorization', v))

        for etype, name, val in extractions:
            if name in SKIP_NAMES:
                continue
            if is_placeholder(val):
                continue
            if is_telegram_bot_token(val):
                continue
            if val in seen:
                continue
            seen.add(val)

            provider = identify_provider(val, name)
            if provider == 'Unknown':
                continue

            entry = {
                'key_name': name,
                'value': val,
                'line': i + 1,
            }

            if with_endpoints:
                entry['endpoint'] = find_endpoint(lines, i, name, val, provider)

            all_keys.append({
                'provider': provider,
                **entry,
            })

    # Group by provider
    by_provider = defaultdict(list)
    for k in all_keys:
        prov = k.pop('provider')
        by_provider[prov].append(k)

    # Sort: known providers first
    provider_order = [
        'Anthropic (Claude)', 'OpenAI', 'OpenAI Service', 'OpenAI Compatible',
        'Google Gemini', 'Google Cloud', 'OpenRouter', 'Groq', 'Perplexity',
        'DeepSeek', 'Moonshot (Kimi)', 'Mistral', 'GLM', 'Qwen',
        'Volcano Engine', 'MiniMax',
        'Cerebras/Codepilot/MiniMax', 'Codepilot', 'NVIDIA', 'Featherless',
        'Brave Search', 'Tavily', 'Nous Research', 'FELO', 'Tencent IMA',
        'Alibaba DashScope', 'DiDi MCP', 'TurnPanel', 'Lovart', 'Lovart/Custom',
        'OpenClaw', 'HuggingFace', 'Resend', 'Apify', 'Cloudflare',
        'JWT Token', 'EVOLINK', 'Cursor', 'N8N',
    ]

    result = {}
    for p in provider_order:
        if p in by_provider:
            result[p] = by_provider[p]
    for p in sorted(by_provider.keys()):
        if p not in result:
            result[p] = by_provider[p]

    return result, len(lines)


def main():
    parser = argparse.ArgumentParser(description='Extract credentials from a text file')
    parser.add_argument('filepath', help='Path to the file to scan')
    parser.add_argument('--output', '-o', help='Output JSON file path (default: stdout)')
    parser.add_argument('--no-endpoints', action='store_true',
                        help='Skip endpoint association (faster, keys only)')
    parser.add_argument('--summary-only', '-s', action='store_true',
                        help='Print only a summary table, not full JSON')
    args = parser.parse_args()

    results, total_lines = extract_from_file(args.filepath, with_endpoints=not args.no_endpoints)
    total_keys = sum(len(v) for v in results.values())

    if args.summary_only:
        print(f"Scanned {total_lines} lines, found {total_keys} unique keys across {len(results)} providers:\n")
        print(f"{'Provider':<40} {'Count':>5}")
        print("-" * 50)
        for p, keys in results.items():
            print(f"  {p:<38} {len(keys):>5}")
        print("-" * 50)
        print(f"  {'TOTAL':<38} {total_keys:>5}")
    else:
        output = json.dumps(results, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Extracted {total_keys} keys across {len(results)} providers -> {args.output}")
        else:
            print(output)


if __name__ == '__main__':
    main()
