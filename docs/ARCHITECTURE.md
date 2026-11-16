# System Architecture

**VAPT Lab Studio** is a full-stack TypeScript single-page application paired with a lightweight Express backend that runs real network/web/CVE diagnostics and serves the Vite React frontend on port `3000`.

---

## 1. High-Level Architecture

```text
+-------------------------------------------------------------------+
|                        Browser (React 19 SPA)                     |
|                                                                   |
|  OverviewView | LiveAnalyzerView | AutomationToolView | Playbook  |
|  VaptReportView (Preview + Edit + Print-to-PDF / Markdown Export) |
|                                                                   |
|  Persistence Layer:                                               |
|   - Guest Mode: Browser localStorage (vapt_lab_studio_workspace_v2)
|   - Signed-In:  Firebase Auth (Google) + Cloud Firestore Sync     |
+------------------------------+------------------------------------+
                               | HTTP /api/* (same-origin port 3000)
                               v
+-------------------------------------------------------------------+
|                   Express Backend (server.ts)                     |
|                                                                   |
|  - GET  /api/health       -> Readiness probe                      |
|  - POST /api/parse-nmap   -> XML & CLI scan parser + CVE matcher  |
|  - POST /api/probe-port   -> Raw TCP socket + banner grabber      |
|  - POST /api/inspect-url  -> HTTP, DNS, TLS, CORS, cookie audit   |
|  - GET  /api/cve-search   -> Live CVEDB / MITRE CVE lookup        |
|                                                                   |
|  Static/Dev Serving:                                              |
|   - Dev:  Vite middlewareMode mounted via HTTP server             |
|   - Prod: Serves built assets from dist/                          |
+-------------------------------------------------------------------+
```

---

## 2. Core Design Decisions

### Single-Origin Express + Vite Host
- `server.ts` creates a single `http.Server` on `0.0.0.0:3000`.
- In development (`NODE_ENV !== 'production'`), Vite runs in `middlewareMode` attached to the Express app, eliminating CORS issues between frontend and `/api/*` endpoints.
- When `DISABLE_HMR=true` is active in preview sandboxes, the server neutralizes Vite's client WebSocket transport calls on `/@vite/client` so browsers do not log spurious WebSocket errors.

### Function Rehydration for Playbook Commands
- Each `PlaybookVector` in `src/data/metasploitablePlaybook.ts` stores dynamic command template generators (`cmd: (cfg: LabConfig) => string`).
- Because `JSON.stringify` strips functions when saving to `localStorage` or Firestore, `rehydrateVectors()` in `src/App.tsx` restores template command functions on workspace load, while UI views also guard calls with `typeof step.cmd === 'function'`.

### Dual-Theme System (Light Mode + Obsidian Jade Dark Mode)
- **Pre-paint script (`index.html`)**: Reads `localStorage.getItem('vapt_studio_theme')` (defaulting to `'dark'`) and applies the `.dark` class on `<html>` before first paint to avoid theme flicker.
- **Tailwind CSS v4 custom variant (`src/index.css`)**: `@custom-variant dark (&:where(.dark, .dark *));` enables deterministic class-based dark styling.
- **Dark Palette ("Obsidian Jade & Electric Mint")**:
  - Canvas: `#070B0E`
  - Elevated surfaces/cards: `#0D1418`
  - Inset inputs & table headers: `#131D23`
  - Borders & dividers: `#1D2C35` / `#273B47`
  - Primary electric mint CTAs: `#14B8A6` / `#2DD4BF` with `#042F2E` ink
  - Terminal blocks: `#05080A`
- **Print-to-PDF Protection (`@media print`)**: Inside `VaptReportView.tsx`, report pages carry `print:!bg-white print:!text-slate-900 print:!border-slate-200` overrides so exported A4 PDFs always print with crisp black text on white paper regardless of the active screen theme.

### Pure-TypeScript Client ZIP Builder
- `src/utils/zipBuilder.ts` constructs valid PKZIP archives (including POSIX executable file attributes for `.sh` and `.py` scripts) completely in the browser with zero third-party zip dependencies.

---

## 3. Backend SSRF & Safety Controls

The live probe endpoints (`/api/probe-port` and `/api/inspect-url`) run from the Node.js server and enforce strict validation before opening outbound connections:
- **Protocol enforcement**: Only `http:` and `https:` URLs are accepted by `/api/inspect-url`.
- **Private & metadata IP blocking**: DNS resolution is checked before socket/HTTP connection to block loopback (`127.0.0.0/8`, `::1`), RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), and carrier-grade NAT (`100.64.0.0/10`) targets from public server-side probing.
- **Resource bounds**:
  - `/api/probe-port` caps port lists at **15 unique ports** per request with per-socket timeouts.
  - JSON request bodies are capped at `2mb`.
  - Redirects on `/api/inspect-url` are handled safely with tight request timeouts.
