# Live Host Secret Exposure Audit

Use this after authorized SSH access to a production Linux host when the goal is to find credentials without printing their values or disrupting services.

## Safe audit sequence

1. **Inventory credential stores and permissions first**
   - `~/.aws/credentials`, `.env*`, OAuth/service-account JSON, rclone configs, cloudflared tokens, application `config/*.key`, SSH private keys.
   - Report path, owner, mode, value type/prefix, and length—not the secret.
2. **Scan likely source/config roots before large data mounts**
   - Typical roots: `/srv/<app>`, `/home`, `/root`, `/etc`, `/var/www`.
   - Exclude virtualenvs, package caches, Git objects during the first pass, large scientific/media data, and files above a reasonable size.
3. **Use targeted prefix/content patterns**
   - AWS: `AKIA|ASIA` + 16 uppercase/digits.
   - Private keys: `BEGIN ... PRIVATE KEY`.
   - GitHub, Google, Stripe, Hugging Face, Telegram, JWT prefixes.
4. **Check logs and web exposure separately**
   - Search application/system logs for secret prefixes and variable assignments.
   - Inspect Nginx `root`/`alias`, symlinks, static directories, backup files, and accidental directory listings.
5. **Check Git current tree and raw repository objects**
   - Verify sensitive files are ignored and untracked.
   - Scan `.git` objects or history for credential signatures without emitting values.
6. **Fix permissions without rotating or deleting production credentials unless authorized**
   - AWS/root-only credentials: `0600 root:root`.
   - App credentials: usually `0600 <service-user>:<service-group>`.
   - Preserve intentional group-read access only where the service architecture requires it.
7. **Add `.gitignore` protections** for `.env*`, OAuth/service-account files, token stores, rclone configs, and `config/*.key`.
8. **Recommend rotation based on historical exposure**
   - A secret that was world-readable should be treated as potentially exposed even after permissions are fixed.

## Important pitfalls

- Filename-only scans produce huge false positives on scientific datasets containing words like `Secretome`; restrict filename patterns to basename-level credential conventions and exclude mounted data trees.
- Do not return full secret values in reports. Prefix, length, provider, file path, owner, and mode are enough.
- Broad Python filesystem scans can stall on large mounted data. Start with `find`/`grep` bounded by roots, size, and exclusions; run deep scans asynchronously only when needed.
- `.env.bak*` files are often more exposed than the active `.env` and may contain retired but still-valid credentials.
- Permission repair is not credential rotation. Clearly separate what was fixed locally from what must be revoked/reissued upstream.
