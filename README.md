# VAPT Lab Studio (`vapt-lab-studio`)

A full-stack **Vulnerability Assessment & Penetration Testing (VAPT) Workbench** designed for isolated virtual penetration-testing labs (Metasploitable 2, Mr-Robot: 1, Basic Pentesting: 1) and real-time network/web security auditing.

It combines **live backend security probes**, a **parameterized Python 3 & Bash automation suite generator**, an **8-vector Kali Linux exploitation playbook**, and a **print-to-PDF 11-section VAPT Report Studio** in a single dual-theme (Light Mode & **Obsidian Jade** Dark Mode) web application.

---

## Table of Contents
- [Key Capabilities](#key-capabilities)
- [1. Overview & Lab Configuration](#1-overview--lab-configuration)
- [2. Live VAPT Analyzer & Network Probe](#2-live-vapt-analyzer--network-probe)
- [3. Automation Toolkit Builder (Option 1 + Option 2)](#3-automation-toolkit-builder-option-1--option-2)
- [4. Kali Linux Exploitation & Evidence Playbook](#4-kali-linux-exploitation--evidence-playbook)
- [5. Professional 11-Section VAPT Report Studio](#5-professional-11-section-vapt-report-studio)
- [Dual-Theme UI & PWA Support](#dual-theme-ui--pwa-support)
- [Tech Stack](#tech-stack)
- [Backend API Reference](#backend-api-reference)
- [Project Structure](#project-structure)
- [Local Setup & Running](#local-setup--running)
- [Firebase Cloud Sync (Optional)](#firebase-cloud-sync-optional)
- [Authorized Use & Ethical Disclaimer](#authorized-use--ethical-disclaimer)

---

## Key Capabilities

### 1. Overview & Lab Configuration
- Dynamically customize **Studio/Brand Name**, **Program Name**, **Target Machine Name**, **Automation Tool CLI Name**, **Assessor Name**, **GitHub Username**, **Repository Name**, **Kali Attacker IP**, **Target VM IP**, **Network Interface**, and **VirtualBox Adapter Mode** (`Host-Only (vboxnet0)` or `NAT Network`).
- Changes propagate immediately across all Kali Linux playbook commands, generated Python/Bash automation scripts, `README.md`, `LICENSE`, GitHub push snippets, and VAPT PDF report sections.
- Includes a **Deliverable Milestone Checklist** and multi-profile **Saved Lab Profiles** switcher when signed in.

### 2. Live VAPT Analyzer & Network Probe
Powered by the Express backend (`server.ts`) with built-in SSRF safeguards on live internet targets:
- **Nmap XML & Terminal Output Analyzer (`POST /api/parse-nmap`)**: Parses `nmap -oX scan.xml` or standard Nmap terminal output, extracts OS guesses and open ports/banners, correlates known vulnerabilities/CVEs with CVSS scores, saves scan history to Firestore, and pushes results directly into Section 5 of the VAPT report.
- **Live TCP Port & Banner Probe (`POST /api/probe-port`)**: Performs real backend TCP socket connections (up to 15 ports per run) to measure `open` / `closed` / `filtered` state, round-trip latency (ms), and raw service banners.
- **Live Web, DNS, TLS & CORS Audit (`POST /api/inspect-url`)**:
  - Calculates an automated **Security Posture Score (0–100)**.
  - Queries live DNS records (`A`/`AAAA`, `NS`, `MX`, `SPF`, `DMARC`).
  - Inspects TLS/SSL protocol, certificate issuer, and days remaining until expiration.
  - Audits HTTP security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`), `Set-Cookie` hardening flags, CORS origin reflection, and common discovery paths.
- **Live CVE Intelligence Search (`GET /api/cve-search`)**: Queries live CVE databases (`cvedb.shodan.io` with `cveawg.mitre.org` fallback for exact CVE IDs) for CVSS scores, severity ratings, descriptions, and advisory references.
- **CIDR & Payload Workbench**: Expands IPv4 CIDR ranges (`/24`–`/32`) into usable host lists and generates parameterized reverse-shell & `msfvenom` lab commands.

### 3. Automation Toolkit Builder (Option 1 + Option 2)
Generates a complete, downloadable `.zip` repository (`<repo-name>.zip`) containing executable Python 3 & Bash scripts tailored to your configured lab settings:
- `auto_vapt.sh` — 5-stage orchestrated VAPT pipeline (connectivity check, profiled Nmap scan, Nikto/Enum4linux enumeration, web audit, and multi-format report + Metasploit `.rc` generation).
- `src/vapt_engine.py` — Nmap XML parser, CVE/vulnerability correlator, JSON/Markdown/standalone HTML report generator, and Metasploit resource script (`msf_lab_verify.rc`) builder.
- `src/netrecon_v2.py` — Multi-threaded TCP/UDP & CIDR subnet scanner with banner grabbing and TLS inspection (Option 1 upgrade).
- `run_recon_upgrade.sh` — Wrapper script for automated NetRecon v2 sweeps.
- `src/web_audit.py` — HTTP header, cookie, and directory surface auditor.
- `src/exploit_helper.py` — Authorized lab listener and payload reference helper.
- `tests/test_vapt_suite.py` — 8 Python `unittest` cases validating parsing, correlation, and output generation.
- `README.md`, `LICENSE` (MIT), `requirements.txt`, and `.gitignore`.

### 4. Kali Linux Exploitation & Evidence Playbook
Covers **8 structured attack vectors** with copy-ready Kali Linux execution steps, expected proof indicators, impact summaries, remediation guidance, **Verified in Lab** / **Include in PDF** toggles, and fields for real terminal evidence and figure notes:
1. **vsftpd 2.3.4 Backdoor Command Execution** (`21/tcp`, `CVE-2011-2523`)
2. **Samba `"username map script"` Remote Command Execution** (`139/445/tcp`, `CVE-2007-2447`)
3. **Unauthenticated Root Bindshell on Port 1524** (`1524/tcp`)
4. **UnrealIRCd 3.2.8.1 Trojaned Source Backdoor** (`6667/tcp`, `CVE-2010-2075`)
5. **Unencrypted Legacy r-Services Trust Misconfiguration** (`512–514/tcp`)
6. **Apache Tomcat Manager Default Credentials & WAR Upload RCE** (`8180/tcp`)
7. **Web Application SQL Injection & OS Command Injection (DVWA / Mutillidae)** (`80/tcp`)
8. **PostgreSQL Default Credentials & Server-Side Code Execution** (`5432/tcp`)

### 5. Professional 11-Section VAPT Report Studio
Generates a structured penetration testing report with both **Report Preview** and **Edit Sections** modes, **Markdown export (`.md`)**, and **Print / Save as PDF (`@media print` A4 formatting)**:
1. Project Overview and Objective
2. Lab Setup and Network Configuration (including VM topology table)
3. Target Machine Details
4. Scope and Methodology
5. Reconnaissance and Enumeration Results (auto-populated or synced from Live Analyzer)
6. Vulnerabilities Identified (CVSS & severity table)
7. Exploitation Methodology and Evidence (per-vector commands, notes, and terminal proof)
8. Proof of Successful Compromise
9. Risk Assessment and Impact
10. Remediation Recommendations
11. Conclusion and Lessons Learned

---

## Dual-Theme UI & PWA Support
- **Light Mode & Obsidian Jade Dark Mode**: Instant theme toggle in the sidebar/mobile drawer persisted in `localStorage` (`vapt_lab_studio` pre-paint script in `index.html` prevents theme flash). Print/PDF export automatically enforces crisp black-on-white A4 typography regardless of active UI theme.
- **PWA Ready**: Configured with `vite-plugin-pwa`, web app manifest, install prompt hook (`usePWAInstall`), and offline status indicator.

---

## Tech Stack
- **Frontend**: React 19, TypeScript, Vite 8, Tailwind CSS v4 (`@tailwindcss/vite`), Lucide Icons, Motion
- **Backend**: Node.js, Express 4 (`server.ts` serving API routes + Vite middleware in dev / `dist/` in production)
- **Database & Auth**: Firebase Authentication (Google Sign-In) + Cloud Firestore (`firebase` v13)
- **Utilities**: Client-side ZIP builder (`src/utils/zipBuilder.ts`) with zero external archive dependencies

---

## Backend API Reference

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Health check (`{ ok: true }`) |
| `POST` | `/api/parse-nmap` | Parses Nmap XML (`<nmaprun>`) or raw text output and returns ports + correlated findings |
| `POST` | `/api/probe-port` | Runs live backend TCP connect & banner grab across up to 15 ports (SSRF-guarded) |
| `POST` | `/api/inspect-url` | Runs live HTTP audit, DNS (`A/AAAA/NS/MX/SPF/DMARC`), TLS cert, CORS, cookie, and path checks |
| `GET` | `/api/cve-search?q=...` | Queries live CVE intelligence by software keyword or CVE ID |

---

## Project Structure

```text
├── index.html                        # Entry HTML + pre-paint Light/Dark theme bootstrap
├── metadata.json                     # App metadata & capabilities
├── package.json                      # Dependencies & npm scripts
├── server.ts                         # Express API server + Vite dev/static host (port 3000)
├── firebase-blueprint.json           # Firestore schema blueprint
├── firestore.rules                   # Firestore security rules
├── vite.config.ts                    # Vite + Tailwind v4 + PWA config
└── src/
    ├── App.tsx                       # Main workspace shell, sidebar/drawer, theme & state sync
    ├── index.css                     # Tailwind v4 theme tokens, hover transitions, A4 print CSS
    ├── components/
    │   ├── OverviewView.tsx          # Studio/GitHub/Lab config, saved profiles & milestone checklist
    │   ├── LiveAnalyzerView.tsx      # Nmap parser, TCP probe, Web/DNS/TLS audit, CVE search & CIDR tools
    │   ├── AutomationToolView.tsx    # Code browser, CLI dry-run preview & .zip bundle downloader
    │   ├── LabPlaybookView.tsx       # 8-vector Kali Linux exploitation playbook & evidence logger
    │   └── VaptReportView.tsx        # 11-section VAPT report editor, Markdown & PDF exporter
    ├── data/
    │   ├── automationTemplates.ts    # Dynamic Python 3, Bash, test, README & MIT License templates
    │   └── metasploitablePlaybook.ts # 8 target attack vectors & Kali command generators
    ├── hooks/
    │   └── usePWAInstall.tsx         # PWA install prompt & offline banner
    ├── lib/
    │   └── firebase.ts               # Firebase Auth & Firestore workspace/scan persistence
    ├── types/
    │   └── vapt.ts                   # TypeScript interfaces for configs, vectors, scans & reports
    └── utils/
        └── zipBuilder.ts             # Pure-TS ZIP archive generator for toolkit downloads
```

---

## Local Setup & Running

### Prerequisites
- **Node.js** `v20+` (or `v22+`)
- **npm** (or `bun`)

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` if needed (optional keys depending on your deployment):
```bash
cp .env.example .env
```

### 3. Run in Development Mode
Starts the Express server + Vite frontend on **http://localhost:3000**:
```bash
npm run dev
```

### 4. Type-Check & Build for Production
```bash
npm run lint
npm run build
npm start
```

---

## Firebase Cloud Sync (Optional)
- Without signing in, all lab configurations, playbook evidence, and report sections automatically persist in browser `localStorage`.
- Signing in with **Google Sign-In** from the sidebar enables multi-profile **Saved Lab Profiles** and **Saved Scan History** backed by Cloud Firestore (`firestore.rules`).

---

## Authorized Use & Ethical Disclaimer
All scanning utilities, Kali Linux commands, Metasploitable 2 playbooks, and payload builders in **VAPT Lab Studio** are strictly intended for **authorized penetration testing, cybersecurity education, and isolated virtual lab environments** (such as VirtualBox Host-Only or NAT Networks). Never run active exploitation or unauthorized scans against systems you do not own or lack explicit written permission to test.
