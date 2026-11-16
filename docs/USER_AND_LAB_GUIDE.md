# User & Lab Workflow Guide

This guide walks through local installation, setting up your isolated VirtualBox + Kali Linux lab, running live scans and automation scripts, and exporting your final 11-section VAPT PDF report.

---

## 1. Local Installation & Running the App

### Prerequisites
- **Node.js** `v20+` (or `v22+` / `v24+` recommended)
- **npm**

### Important Windows Path Note
Avoid placing the project inside any directory whose name contains an ampersand (`&`), such as `Phase-1 & 2`. Windows `cmd.exe` splits `.cmd` shims (`tsx.cmd`, `vite.cmd`) at `&`. Use a clean path like `D:\VAPT-Lab-Studio-main`.

### Installation Steps
1. Extract or clone the repository into a clean path without `&`:
   ```bash
   git clone https://github.com/<your-username>/vapt-lab-studio.git
   cd vapt-lab-studio
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
   *(If an older npm/lock environment raises an `ERESOLVE` peer warning or install-script prompt, run `npm install --legacy-peer-deps` and `npm install-scripts approve --all`.)*
3. Copy environment template (optional for local mode):
   ```bash
   cp .env.example .env
   ```
4. Start the development server:
   ```bash
   npm run dev
   ```
   *(On Node.js v22.18+/v24+, you can also run `node server.ts` directly.)*
5. Open your browser to **`http://localhost:3000`** *(do not type `0.0.0.0:3000` in Windows browsers)*.

---

## 2. Isolated VirtualBox Lab Setup

Before running any active exploitation commands from the Playbook:
1. Install **Oracle VirtualBox** and import:
   - **Attacker VM**: Kali Linux
   - **Target VM**: Metasploitable 2, Mr-Robot: 1, or Basic Pentesting: 1 (from VulnHub)
2. Set both VMs' network adapters to **Host-Only Adapter (`vboxnet0`)** or the same **NAT Network** so the vulnerable target is completely isolated from the public internet.
3. Verify connectivity inside Kali Linux:
   ```bash
   ip -4 addr show eth0
   sudo arp-scan -I eth0 --localnet
   ping -c 3 <TARGET_IP>
   ```
4. Enter your real Kali IP, Target VM IP, Interface, Assessor Name, and Tool/GitHub names inside the **Overview** tab.

---

## 3. Using the 5 Workspace Tabs

### Tab 1: Overview
- Configure studio branding, program name, assessor name, GitHub repository coordinates, and Kali/Target IPs.
- Track progress using the **Deliverable Checklist**.
- Sign in with Google in the sidebar to create, switch between, or delete multiple **Saved Lab Profiles**.

### Tab 2: Live VAPT Analyzer
- **Nmap XML & CVE Analyzer**: Upload (`scan.xml`) or paste Nmap XML/terminal output, correlate CVEs, save scan history, or push results directly into Section 5 of your VAPT Report.
- **Live TCP Port & Banner Probe**: Test reachability, round-trip latency, and service banners across up to 15 ports on public targets.
- **Live Web, DNS, TLS & CORS Audit**: Inspect HTTP security headers, `A`/`AAAA`/`MX`/`NS`/`SPF`/`DMARC` DNS records, TLS certificate validity, CORS reflection, cookie flags, and discovery paths.
- **Live CVE Search**: Look up CVSS scores, EPSS probabilities, CISA KEV flags, and advisory URLs for discovered banners or CVE IDs.
- **CIDR & Payloads**: Expand IPv4 subnets and generate parameterized reverse-shell / `msfvenom` snippets.

### Tab 3: Automation Toolkit (Option 1 + Option 2)
- Filter between **Full Suite**, **Option 1: NetRecon v2**, **Option 2: AutoVAPT**, and **Web & Payload Modules**.
- Preview expected Kali CLI output and GitHub deployment commands.
- Click **Download `<repoName>.zip`** to export the full Python 3 & Bash repository with 8 `unittest` test cases.
- Inside Kali Linux:
  ```bash
  unzip <repoName>.zip && cd <repoName>
  chmod +x auto_vapt.sh run_recon_upgrade.sh
  python3 -m unittest discover -s tests -v
  sudo ./auto_vapt.sh -t <TARGET_IP> -l <KALI_IP> -i eth0 --profile standard
  ```

### Tab 4: Lab Playbook
- Filter vectors by **All**, **Critical**, or **High** severity.
- Copy parameterized Kali Linux commands for each of the 8 attack vectors.
- Paste your real terminal proof (`id`, `uname -a`, shell output) and screenshot figure notes, then toggle **Verified in Lab** and **In PDF Report**.

### Tab 5: VAPT Report
- Update assessor, program, target name, and date in the top quick-edit strip.
- Switch to **Edit Sections** to customize narrative sections (`1, 2, 3, 4, 5, 8, 9, 11`).
- Switch to **Report Preview** and click:
  - **Export Markdown** to download `.md` documentation.
  - **Print / Save as PDF** to save a print-formatted A4 PDF (automatically styled with crisp white paper and dark ink regardless of Light/Dark screen theme).
