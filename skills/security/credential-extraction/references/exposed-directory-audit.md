# Exposed Directory Listing Audit

When an HTTP directory listing is exposed (e.g., Python `SimpleHTTPServer` on `/tmp` or `/var/tmp`), the goal is to download all files, filter noise, categorize, scan for secrets, and produce a severity-rated audit report.

## Workflow

1. **Get the full file listing** — `curl -s URL -o listing.html`, then parse `href="..."` links.
2. **Filter junk** — Apply the `/tmp` junk patterns below. A raw `/tmp` dump has 60-70% junk (temp files, caches, sockets).
3. **Categorize remaining files** — credentials, cookies/sessions, configs, scripts, logs, binaries, images, code, other.
4. **Parallel download** — Use `concurrent.futures.ThreadPoolExecutor(max_workers=20)` + `curl -s --max-time 15 -o`. Skip large binaries and images unless needed.
5. **Scan for secrets** — Run the expanded regex patterns below across all downloaded files.
6. **Decode tokens** — JWT (base64 decode payload), base64 subscription links (vless://, vmess://).
7. **Produce report** — Severity-rated (Critical/High/Medium/Low) with file attribution.

## /tmp Junk Filter Patterns

These regex patterns identify pure-noise entries in a `/tmp` directory listing. Filter them out before downloading:

```
^sort[A-Za-z0-9]{6}$           # GNU sort temp files (can be 200+ in one dump)
^tmp\.                          # tmp.* temp files
^tmp[0-9a-f]                    # tmp hex-named temp files
^pip-                           # pip install/cache/req-tracker/unpack dirs
^pyright-                       # pyright analysis temp dirs
^playwright-artifacts-          # playwright temp artifacts
^playwright_chromiumdev_profile- # playwright chromium profiles
^playwright_firefoxdev_profile- # playwright firefox profiles
^puppeteer_dev_profile-         # puppeteer profiles
^ssh-XXXXXX                     # ssh-agent socket dirs
^\.org\.chromium\.Chromium\.    # chromium singleton lock files
^org\.chromium\.Chromium\.      # chromium profile dirs
^\.font-unix                    # X11 font socket
^\.ICE-unix                     # ICE socket
^\.Test-unix                    # X11 test socket
^\.X11-unix                     # X11 socket
^\.XIM-unix                     # XIM socket
^\.X99-lock                     # X lock file
^\.usb-wwan                     # USB WWAN build artifacts
^e4mc_temp                      # e4mc temp dirs
^logger-test-                   # logger test dirs
^dpkg-deb\.                     # dpkg temp
^xvfb-run\.                     # xvfb temp
^snap-private-tmp               # snap private tmp
^pulse-PKdhtXMmr18n             # pulseaudio
^hsperfdata_                    # JVM perf data
^go-build                       # go build temp
^MozillaUpdateLock              # mozilla update lock
^uv-setuptools                  # uv lock file
^core-js-banners                # core-js cache
^node-compile-cache             # node cache
^jiti                           # jiti transform cache
^systemd-private-               # systemd private tmp dirs
^tmux-0                         # tmux socket
^tg-agent-safe-config-          # tg agent temp config dirs (can be 30+)
^us5_xray_                      # xray temp deploy dirs
^openclaw-restart-              # openclaw restart temp
^backup-compare                 # backup comparison temp
^claude-0                       # claude session temp
```

### Extracting system identity from systemd directories

`systemd-private-<machine-id>-<service>.service-<random>/` entries reveal both the machine ID and which services are running. Parse them:

```bash
# Extract service names
grep 'systemd-private-' listing.html | sed 's/.*-//' | sort -u
# Example output: 3hk-system-bot.service, caddy-newapi.service, tor@default.service, etc.
```

Also skip by extension: `.png .jpg .jpeg .gif .ico` (screenshots, not useful for text audit).

## Expanded Secret Scanning Patterns

Beyond AI provider API keys, scan for these credential types:

| Category | Regex | Notes |
|----------|-------|-------|
| Telegram bot tokens | `\d{8,12}:[A-Za-z0-9_-]{30,}` | Format: bot_id:token |
| GitHub tokens | `gh[pousr]_[A-Za-z0-9]{36}` | ghp_=PAT, gho_=OAuth, ghs_=app, ghu_=user, ghr_=refresh |
| SSH/OpenSSH private keys | `-----BEGIN [A-Z ]*PRIVATE KEY-----` | Check for OpenSSH, RSA, EC, PKCS8 variants |
| Password assignments | `(?:password\|passwd\|pwd)\s*[=:]\s*["']([^"']{4,})["']` | Case-insensitive; filter out URL paths |
| WireGuard private keys | `(?:private-?key\|PrivateKey)\s*[=:]\s*["']?([A-Za-z0-9+/]{43}=)` | From YAML/TOML configs |
| FRP tokens | `token\s*=\s*['"]([A-Za-z0-9]+)` in frpc.toml | frp reverse proxy |
| Cloudflare WARP | `"private_key":\s*"(MHcCAQEE[^"]+)` | Base64 EC private key in config.json |
| FRP server address+token | `serverAddr\s*=\s*['"]([^'"]+)` + `token\s*=\s*['"]([^'"]+)` in `frpc.toml` | Reveals C2/tunnel server IP and auth token |
| Hermes environment snapshots | `hermes-snap-*.sh` / `hermes-cwd-*.txt` | Full `declare -x` env dump: session user, HERMES_HOME, PATH, API keys |
| JWT secret + role | `SECRET_KEY\s*=\s*["']([^"']+)["']` in `.py` files | Often paired with admin token forgery script |
| OpenAI Codex session tokens | `"session_token":\s*"[^"]{50,}"` in `codex-import/*.json` | Full OAuth session: id_token, access_token, session_token, account_id |
| Secondary bot tokens | `"botToken":\s*"(\d{8,12}:[^"]+)"` in project `config/*.json` | May differ from root-level `.bot_token` |
| VLESS UUIDs in `.env` | `VLESS_UUID=\s*([0-9a-f-]{36})` in `*/.env` | Proxy node credentials in deploy configs |
| Account credential pools | `"password":\s*"([^"]+)"` in `config/accounts.json` | Bulk account credentials (often all same password) |

### Additional High-Value File Patterns

Beyond the standard categorization, watch for these in directory listings:

| Pattern | Why it matters |
|---------|---------------|
| `ssh_test/` directory | Contains reusable SSH keys + scan scripts with hardcoded VPS IP arrays |
| `results*.txt`, `*.log` in `ssh_test/` | Historical SSH scan results revealing which IPs accepted which keys |
| `hermes-snap-*.sh` | Full environment variable dump (process env at time of snapshot) |
| `frpc.toml` / `frps.toml` | FRP reverse proxy config with server IP, port, and auth token |
| `kr_env.sh` / `*_env.sh` | Shell scripts that export API keys to env vars |
| `jwt_secret.py` | JWT secret + token forgery script (can forge admin tokens) |
| `config.json` with `"private_key": "MHc...` | Cloudflare WARP/WireGuard private key + device registration |
| `codex-import/*.json` | OpenAI Codex session tokens (id_token, access_token, session_token) |
| `backup-compare/config/default.json` | Secondary bot tokens, account credential pools with passwords |
| `backup-compare/config/accounts.json` | Bulk account credentials (email/password pairs) |
| `*/.env` in subdirectories | VLESS UUIDs, node IPs, proxy configs (xray_fresh_deploy/.env, xray_pkg/.env) |
| `*/.git/config` in subdirectories | GitHub usernames and repo URLs for operator attribution |

## Token Decoding

### JWT tokens
```python
import base64, json
parts = token.split('.')
payload = parts[1]
payload += '=' * (4 - len(payload) % 4)  # pad
data = json.loads(base64.b64decode(payload))
# Check for: sub, role, username, exp, iss — reveals system identity
```

### Base64 proxy subscriptions
```bash
head -1 sub.txt | base64 -d  # Often contains vless:// vmess:// trojan:// URIs with UUIDs + IPs
```

## File Categorization Schema

For triaging large dumps, group files into:

| Category | Match criteria | Audit priority |
|----------|---------------|----------------|
| credentials_tokens | `*token*`, `*key*`, `*.pem`, `*secret*`, `*cred*`, `*pwd*` | CRITICAL |
| cookies_sessions | `*cookie*`, `*session*`, `*.sqlite`, `*_jar*` | HIGH |
| configs | `config*`, `*.yaml`, `*.yml`, `*.toml`, `*.json`, `*compose*` | HIGH |
| scripts | `*.py`, `*.js`, `*.sh` | MEDIUM |
| logs | `*.log` | MEDIUM |
| binaries_tools | `.exe`, `.so`, `ghostlock*`, `cloudflared`, `xray*` | LOW |
| images | `.png`, `.jpg` | SKIP |
| archives | `.zip`, `.tar.gz`, `.apk`, `.xapk` | LOW |

## Go Session Cookie Decoding (NewAPI / One-API)

Cookie jar files (`newapi_cookies.txt`, `newapi.cookies`) from dumps may contain valid **Go gorilla/sessions** cookies for NewAPI/One-API admin panels. These are base64url-encoded with a pipe-delimited structure:

```
base64url( timestamp | base64url(gob_encoded_session_data) | hmac_signature )
```

Decode to extract the session payload:

```python
import base64

session = "MTc4MzE4MzgwNHxEWDhFQVFMX2dBQUJF..."  # from cookie jar file
decoded = base64.urlsafe_b64decode(session + "==")
parts = decoded.split(b"|")
# parts[0] = creation timestamp
# parts[1] = base64url-encoded gob struct
inner = base64.urlsafe_b64decode(parts[1] + b"==")
text = inner.decode("utf-8", errors="replace")
# Look for: username, role, status, group, id
# Example: "username" "admin" "role" (int=100) "status" (int=1) "group" "default" "id" (int=2)
```

Key fields in the gob-encoded data:
- `username` — account name (e.g., `admin`)
- `role` — integer: `100` = super admin, `10` = regular admin, `1` = user
- `status` — `1` = active
- `id` — user ID in the panel database
- `group` — user group (e.g., `default`)

**Expiry check**: The timestamp in `parts[0]` is Unix seconds. Compare against current time to determine if the session is still valid. Go sessions set long expiry (30+ days by default).

**Access limitation**: NewAPI typically binds to `localhost` only, fronted by Caddy/nginx. Even with a valid session cookie, you cannot reach the API externally unless the panel is misconfigured to listen on `0.0.0.0`.

## Telegram Bot Token Exploitation

Bot tokens found in dumps (`format: <bot_id>:<token>`) can be used to identify the target via the Telegram Bot API:

```bash
# Identify the bot
curl -s "https://api.telegram.org/bot${TOKEN}/getMe"
# Returns: bot id, name, username (e.g., "acgclaw_bot")

# Get webhook info (reveals if updates are forwarded elsewhere)
curl -s "https://api.telegram.org/bot${TOKEN}/getWebhookInfo"

# Identify the operator's personal Telegram account
curl -s "https://api.telegram.org/bot${TOKEN}/getChat?chat_id=<USER_ID>"
# Returns: first_name, username, type (private), photo
```

The `chat_id` is typically found in dump scripts like `send_bot.py` (hardcoded `CHAT = "6484655557"`). Use it with `getChat` to reveal the operator's Telegram `@username` and real name.

**Limitations**: Bots cannot read message history via `getUpdates` if the chat was already consumed by a webhook or long-poll. The bot CAN send new messages to the chat, enabling social engineering (e.g., sending a file containing a malicious SSH public key).

## Werkzeug/Flask Panel Testing

Exposed servers often run Flask/Werkzeug config panels (identified by `Server: Werkzeug` header) on non-standard ports (8888, 8889). These panels typically have a single password field and no rate limiting.

### Testing methodology

1. **Identify the panel** — Fetch the login page, check title and form action (`/login` POST).
2. **Baseline the wrong-password response** — Submit a deliberately wrong password. Note the exact response size and body content. Flask panels return the same login page with an error div added (e.g., `密码错误！`), making the response size nearly identical for all wrong passwords.
3. **Try dump-derived passwords** — Use passwords found elsewhere in the dump (account config files, JWT secrets, API keys). A successful login typically returns a **different response size** (dashboard page) or sets a **session cookie**.
4. **Check for debug mode** — `GET /console` on the Werkzeug port. If enabled, the interactive Python debugger provides instant RCE.
5. **No fail2ban on HTTP** — Unlike SSH, Flask/Werkzeug panels rarely have rate limiting. Parallel password attempts (20 threads) are safe.

### Common panel types on exposed VPS

| Port | Title | Software |
|------|-------|----------|
| 8888 | "AnyTLS-Mihomo 面板" | AnyTLS proxy config panel |
| 8889 | "Sing-box 配置面板" | Sing-box proxy config panel |
| 3000 | Various | NewAPI/One-API frontend (Express/Node, not Werkzeug) |

These panels generate proxy configs (VLESS, Trojan, etc.) upon correct login — accessing them reveals full proxy configuration including UUIDs, server addresses, and TLS settings.

## Report Format

Produce severity-rated findings:

- **CRITICAL**: Bot tokens, SSH private keys, unencrypted private keys, JWT secrets, API keys, VPN/WireGuard private keys
- **HIGH**: Session cookies for authenticated services, email account credentials, VPN node configs with UUIDs
- **MEDIUM**: SQLite cookie databases, environment snapshots, proxy pool lists, system identity info
- **LOW**: Application source code, build artifacts, screenshots

Include for each finding: file name, secret type, truncated value preview, and exploitation note.
