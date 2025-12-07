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
