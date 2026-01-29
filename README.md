# Monstra CMS 3.0.4 – Security Write-up (Comprehensive Paths)

> Defensive documentation only.  
> No weaponized PoCs, no webshells, no password cracking instructions, no exploitation steps.

## Scope
- Product: Monstra CMS
- Version: 3.0.4
- Environment example: Windows/XAMPP (applies generally to similar stacks)
- Assumption: Some paths require authenticated admin access; others depend on misconfigurations.

---

## 1) Way – Backup Export Leakage (Admin Backup Feature Abuse)
### Preconditions
- Attacker has access to Admin panel (or backup feature is exposed/weakly protected).

### What can go wrong
- Downloaded backups may contain:
  - Database exports
  - `users.table.xml` or equivalent user data
  - Password hashes
  - Configuration files / secrets

### Impact
- Sensitive data disclosure
- Offline risk escalation (credential recovery attempts, secret discovery, lateral movement)

### Safe verification (non-exploit)
- Confirm **who** can access `System → Backups`
- Inspect backup contents **in a controlled environment**
- Check whether backups are stored in a web-accessible path

### Mitigations
- Restrict backup feature to least privilege / specific admin role
- Store backups outside web root + OS-level ACLs
- Encrypt backups at rest + rotate secrets after exposure

### Detection ideas
- Audit admin actions: backup create/download events
- Monitor filesystem for new backup archives and unusual download patterns

---

## 2) Way – Weak Credential Storage / Static Salt Risk (Post-Leak Escalation)
### Preconditions
- Password hashes are exposed (often via backups) AND hashing is weak/legacy OR salt is static/unchanged.

### What can go wrong
- If hashing is legacy + salt practices are weak, leaked hashes become significantly easier to attack offline.
- Admin credential reuse (same password used elsewhere) increases risk.

### Impact
- Account takeover (especially for admin)
- Credential stuffing risk on other services

### Safe verification (non-exploit)
- Review Monstra config/security code to identify hashing approach
- Validate whether salts are per-user vs global/static
- Check if any “default” salts/keys remained unchanged during install

### Mitigations
- Migrate to modern hashing (Argon2/bcrypt) with per-user salts
- Force password resets after disclosure
- Add MFA for admin accounts where possible
- Rotate secrets/keys/salts stored in config

### Detection ideas
- Spike in failed logins, new sessions from unusual IPs
- Admin login anomalies (time, location, user-agent)
- Password reset events and admin role changes

---

## 3) Way – Risky Admin Template/Theme Editing (Server-side Code Execution Risk)
### Preconditions
- Admin can edit templates/themes AND edited files are executed by the server runtime (PHP).
- Misconfiguration: writable + executable within web-accessible theme directory.

### What can go wrong
- Any “server-side executable content” inserted into editable templates can be executed by the web server runtime if stored under an executable path.

### Impact
- Remote code execution (RCE) under web server user
- Full server compromise depending on privileges and local weaknesses

### Safe verification (non-exploit)
- Confirm whether theme/template directories:
  - are writable by the web server user
  - are within web root
  - have server-side execution enabled (e.g., PHP execution)
- Review server config (Apache/Nginx + PHP handler) for execution rules in theme dirs

### Mitigations
- Disable server-side execution in editable/uploadable directories
- Make theme/template directories **read-only** for the web server runtime
- Separate “editable content” from executable templates
- Add strict allowlist for file types and enforce server-side sanitization

### Detection ideas
- Monitor file changes under theme/template directories
- Alert on unexpected creation/modification of executable server-side files
- Review admin edit logs for template changes

---

## 4) Way – File/Directory Permission Misconfiguration (Writable Web Roots)
### Preconditions
- Web server user has write permissions on web root or sensitive subdirectories.

### What can go wrong
- Any feature that writes files (cache, backups, theme editor, uploads) becomes a bigger risk
- In worst case, attacker can place executable content where it will run

### Impact
- Persistence, backdoors, config tampering, defacement

### Safe verification (non-exploit)
- Review OS ACLs (Windows: icacls; Linux: ls -la, getfacl)
- Identify directories writable by the web server process identity

### Mitigations
- Least privilege ACLs: web server write only where absolutely necessary
- Put configs outside web root
- Separate runtime writable dirs (cache/tmp/uploads) with no execution

### Detection ideas
- File integrity monitoring on web root and config paths
- Alerts for permission changes (ACL changes) and new executable files

---

## 5) Way – Exposed Config / Secrets in Backup or Web Root
### Preconditions
- Backups/configs include DB creds, salts, API keys, or admin session secrets.
- These are stored in accessible locations.

### What can go wrong
- Direct DB access or session hijacking (depending on what is leaked)
- Faster compromise chain after initial access

### Safe verification (non-exploit)
- Identify sensitive keys in config files
- Confirm file placement (outside/inside web root)
- Confirm file permissions and access restrictions

### Mitigations
- Move secrets to environment variables / secret manager where possible
- Rotate secrets after any suspected leak
- Ensure configs are not downloadable and not included in public backups

### Detection ideas
- Access logs for suspicious downloads of `.php`, `.ini`, `.xml`, `.bak`, `.zip`
- WAF rules to block common sensitive file patterns

---

## Recommended Hardening Checklist
- [ ] Lock down Admin panel (strong passwords + MFA + IP allowlist if possible)
- [ ] Restrict / harden backup feature (permissions + storage + encryption)
- [ ] Modern password hashing migration plan (Argon2/bcrypt)
- [ ] Disable server-side execution in writable directories
- [ ] Tighten filesystem permissions for web server user
- [ ] File integrity monitoring + admin action auditing
- [ ] Incident response: rotate secrets + force password resets after exposure

---

## Blacklist4 (Do NOT publish publicly)
1. Any webshell / executable payload content (even “simple”).
2. Exploit scripts or step-by-step exploitation instructions.
3. Password cracking commands/rules/wordlists or anything that reproduces cracking.
4. Real hashes, creds, tokens, internal IPs/paths, or unredacted screenshots containing them.
