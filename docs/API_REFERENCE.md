# Backend REST API Reference

All API endpoints are served by `server.ts` under `/api/*` on port `3000`.

---

## 1. Health Check

### `GET /api/health`
Verifies that the Express server is online.

**Response (`200 OK`)**
```json
{
  "ok": true
}
```

---

## 2. Nmap XML & Terminal Output Analyzer

### `POST /api/parse-nmap`
Parses Nmap XML (`nmap -oX scan.xml`) or standard Nmap terminal output (`PORT STATE SERVICE VERSION`), extracts host IP, OS guess, open ports, and correlates matching vulnerability signatures/CVEs.

**Request Body**
```json
{
  "raw": "<nmaprun scanner=\"nmap\">...</nmaprun>"
}
```

**Response (`200 OK`)**
```json
{
  "format": "xml",
  "targetIp": "192.168.56.101",
  "osGuess": "Linux 2.6.9 - 2.6.33",
  "openPorts": [
    {
      "port": 21,
      "protocol": "tcp",
      "service": "ftp",
      "banner": "vsftpd 2.3.4",
      "nseNotes": []
    }
  ],
  "findings": [
    {
      "port": 21,
      "protocol": "tcp",
      "serviceBanner": "vsftpd 2.3.4",
      "title": "vsftpd 2.3.4 Backdoor Command Execution",
      "cve": "CVE-2011-2523",
      "cvss": 10.0,
      "severity": "Critical",
      "remediation": "Remove compromised vsftpd 2.3.4, deploy verified upstream packages, and prefer SFTP."
    }
  ]
}
```

**Error (`400 Bad Request`)**
- Returned when `raw` is empty or cannot be parsed.

---

## 3. Live TCP Port & Service Banner Probe

### `POST /api/probe-port`
Opens real TCP socket connections from the backend to a public target host/IP, measures round-trip latency, sends lightweight protocol probes where appropriate, and captures service banners.

**Constraints**
- Accepts up to **15 comma-separated TCP ports** per request (`1–65535`).
- Blocks private, loopback, link-local, and cloud metadata IP ranges (SSRF protection).

**Request Body**
```json
{
  "host": "scanme.nmap.org",
  "ports": "21,22,80,443,8080"
}
```

**Response (`200 OK`)**
```json
{
  "host": "scanme.nmap.org",
  "resolvedIp": "45.33.32.156",
  "probedAt": "2026-11-16T12:00:00.000Z",
  "results": [
    {
      "port": 22,
      "status": "open",
      "latencyMs": 118,
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
    },
    {
      "port": 80,
      "status": "open",
      "latencyMs": 115,
      "service": "http",
      "banner": "HTTP/1.1 200 OK | Apache/2.4.7 (Ubuntu)"
    }
  ]
}
```

**Errors**
- `400 Bad Request`: Missing host or invalid port list.
- `422 Unprocessable Entity`: DNS resolution failure or blocked private/loopback IP.

---

## 4. Live Web, DNS, TLS & CORS Security Audit

### `POST /api/inspect-url`
Performs a multi-layer HTTP, DNS, TLS, CORS, cookie, and sensitive-path audit on a target URL and computes a `securityScore` (`0–100`).

**Request Body**
```json
{
  "url": "https://example.com"
}
```

**Response (`200 OK`)**
```json
{
  "url": "https://example.com/",
  "hostname": "example.com",
  "responseTimeMs": 210,
  "securityScore": 72,
  "dnsRecords": ["93.184.216.34"],
  "mxRecords": ["0 ."],
  "nsRecords": ["a.iana-servers.net"],
  "spfRecord": "v=spf1 -all",
  "dmarcRecord": "v=DMARC1; p=reject;",
  "statusCode": 200,
  "statusMessage": "OK",
  "serverBanner": "ECS (dcb/7F3B)",
  "poweredBy": "Not disclosed",
  "corsIssue": "No permissive wildcard or reflected origin observed",
  "cookieIssues": [],
  "pathChecks": [
    { "path": "/robots.txt", "statusCode": 404, "note": "Not found" },
    { "path": "/.env", "statusCode": 404, "note": "Not exposed" }
  ],
  "securityHeadersChecklist": [
    { "header": "strict-transport-security", "present": true, "value": "max-age=31536000" },
    { "header": "content-security-policy", "present": false, "value": "Missing" }
  ],
  "tlsSummary": {
    "protocol": "TLSv1.3",
    "subject": "example.com",
    "issuer": "DigiCert Inc",
    "validTo": "Jan 15 23:59:59 2027 GMT",
    "daysRemaining": 60
  }
}
```

**Errors**
- `400 Bad Request`: Missing URL.
- `422 Unprocessable Entity`: Invalid URL scheme, SSRF-blocked target, or unreachable host.

---

## 5. Live CVE Intelligence Search

### `GET /api/cve-search?q=<query>`
Queries live CVE intelligence for either a specific CVE ID (e.g., `CVE-2011-2523`) or a software/product keyword (e.g., `vsftpd 2.3.4`, `OpenSSH`, `Apache`). Uses `cvedb.shodan.io` with automatic fallback to `cveawg.mitre.org` for exact CVE IDs.

**Example Request**
```http
GET /api/cve-search?q=vsftpd%202.3.4
```

**Response (`200 OK`)**
```json
{
  "query": "vsftpd 2.3.4",
  "count": 1,
  "items": [
    {
      "id": "CVE-2011-2523",
      "published": "2011-07-04",
      "severity": "CRITICAL",
      "cvssScore": 10.0,
      "description": "[EPSS 94.3%] vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor...",
      "referenceUrl": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"
    }
  ]
}
```

**Errors**
- `400 Bad Request`: Query `q` shorter than 2 characters.
- `502 Bad Gateway`: Upstream CVE API unreachable.
