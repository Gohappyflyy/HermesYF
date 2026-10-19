# Live-host secret audit and export

## Audit sequence

1. Enumerate likely stores before broad regex scanning: `.aws/credentials`, `.env*`, OAuth/service-account JSON, rclone configs, provider `*.key` files, SSH private keys, cloudflared/Hetzner tokens, and application token databases.
2. Report provider, path, owner/mode, prefix/type, and value length — never print the complete secret during audit.
3. Search source, Git objects/history, logs, web roots/aliases, backups, and world-readable files separately. A clean source scan does not cover `.env.bak*` or Git history.
4. For live services, fix permissions without deleting or rotating credentials unless explicitly requested. Typical targets: `600` for single-user secrets; preserve required group access only when justified.
5. Add secret filenames and backup patterns to `.gitignore`; verify whether any were already tracked.
6. Recommend rotation when a long-lived credential was world-readable, present in backups, or exposed in chat — permission repair does not undo historical exposure.

## SSH hardening verification

When changing to key-only root SSH:

```text
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
```

Run `sshd -t`, reload SSH, test key login through the user's actual jump path, then run a negative password-only test. Never disable password authentication until key login is proven.

## Exporting credentials for owner-led revocation

- Include a manifest and checksum.
- Include recovery SSH material only when needed and label it clearly.
- Do not assume the user wants encryption. If they ask to “打包发给我” without specifying format, prefer a normal `.tar.gz` on the existing private delivery channel, with a prominent warning. Offer encryption as an option rather than imposing it.
- If encryption is requested, verify decryption before delivery and provide the exact command.
- Exporting is not revocation: do not delete production credentials until the owner confirms the archive is usable and replacement credentials are deployed.
