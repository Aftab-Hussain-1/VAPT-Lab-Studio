import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface ParsedPort {
  port: number;
  protocol: string;
  service: string;
  banner: string;
  nseNotes: string[];
}

interface CorrelatedFinding {
  port: number;
  protocol: string;
  serviceBanner: string;
  title: string;
  cve: string;
  cvss: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  remediation: string;
}

const SIGNATURES: Array<{
  port: number;
  pattern: RegExp;
  title: string;
  cve: string;
  cvss: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  remediation: string;
}> = [
  {
    port: 21,
    pattern: /vsftpd\s*2\.3\.4/i,
    title: 'vsftpd 2.3.4 Backdoor Command Execution',
    cve: 'CVE-2011-2523',
    cvss: 10.0,
    severity: 'Critical',
    remediation: 'Remove compromised vsftpd 2.3.4, deploy verified upstream packages, and prefer SFTP.',
  },
  {
    port: 1524,
    pattern: /ingreslock|bindshell|root/i,
    title: 'Unauthenticated Root Bindshell on Port 1524',
    cve: 'CWE-284',
    cvss: 9.8,
    severity: 'Critical',
    remediation: 'Terminate the bindshell process and audit /etc/inetd.conf for unauthorized listeners.',
  },
  {
    port: 6667,
    pattern: /UnrealIRCd/i,
    title: 'UnrealIRCd 3.2.8.1 Trojaned Source Backdoor',
    cve: 'CVE-2010-2075',
    cvss: 9.8,
    severity: 'Critical',
    remediation: 'Remove trojaned UnrealIRCd builds and verify cryptographic checksums before deployment.',
  },
  {
    port: 139,
    pattern: /Samba\s*3\.0\.20|Samba\s*smbd/i,
    title: 'Samba smbd 3.0.20 Username Map Script RCE',
    cve: 'CVE-2007-2447',
    cvss: 9.3,
    severity: 'Critical',
    remediation: 'Upgrade Samba (>= 3.0.25) and disable unsafe username map script rules.',
  },
  {
    port: 445,
    pattern: /Samba\s*3\.0\.20|Samba\s*smbd/i,
    title: 'Samba smbd 3.0.20 Username Map Script RCE (SMB)',
    cve: 'CVE-2007-2447',
    cvss: 9.3,
    severity: 'Critical',
    remediation: 'Upgrade Samba and firewall TCP/445 from untrusted network zones.',
  },
  {
    port: 3632,
    pattern: /distccd/i,
    title: 'DistCC Daemon Remote Command Execution',
    cve: 'CVE-2004-2687',
    cvss: 9.3,
    severity: 'Critical',
    remediation: 'Restrict distccd to trusted build subnets via --allow or disable the service.',
  },
  {
    port: 1099,
    pattern: /rmiregistry|java-rmi/i,
    title: 'Java RMI Registry Remote Code Execution Exposure',
    cve: 'CWE-94',
    cvss: 9.1,
    severity: 'Critical',
    remediation: 'Disable remote class loading and bind RMI registries to localhost.',
  },
  {
    port: 513,
    pattern: /login|rlogind/i,
    title: 'Passwordless rlogin Host-Trust Exposure',
    cve: 'CWE-287',
    cvss: 9.1,
    severity: 'Critical',
    remediation: 'Disable rlogind and delete /etc/hosts.equiv and ~/.rhosts wildcard trust entries.',
  },
  {
    port: 512,
    pattern: /exec|rexec/i,
    title: 'Legacy Cleartext rexec Daemon Enabled',
    cve: 'CWE-287',
    cvss: 8.8,
    severity: 'High',
    remediation: 'Disable rexecd in /etc/inetd.conf and enforce SSHv2 key authentication.',
  },
  {
    port: 8180,
    pattern: /Tomcat|Coyote/i,
    title: 'Apache Tomcat Manager Default Credentials & WAR Upload',
    cve: 'CWE-798',
    cvss: 8.8,
    severity: 'High',
    remediation: 'Rotate manager passwords, IP-restrict /manager/html, and upgrade EOL Tomcat 5.5.',
  },
  {
    port: 5432,
    pattern: /PostgreSQL\s*8\.3/i,
    title: 'PostgreSQL 8.3 EOL & Default Superuser Risk',
    cve: 'CVE-2009-3229',
    cvss: 8.1,
    severity: 'High',
    remediation: 'Bind PostgreSQL to localhost, enforce SCRAM-SHA-256 passwords, and upgrade.',
  },
  {
    port: 3306,
    pattern: /MySQL\s*5\.0/i,
    title: 'MySQL 5.0 EOL & Weak/Empty Root Access Surface',
    cve: 'CWE-521',
    cvss: 7.8,
    severity: 'High',
    remediation: 'Bind MySQL to 127.0.0.1, set strong root credentials, and upgrade to a supported release.',
  },
  {
    port: 23,
    pattern: /telnet/i,
    title: 'Cleartext Telnet Administration Service',
    cve: 'CWE-319',
    cvss: 7.5,
    severity: 'High',
    remediation: 'Disable Telnet daemon and migrate remote administration to SSHv2.',
  },
  {
    port: 5900,
    pattern: /VNC/i,
    title: 'VNC Remote Desktop Weak Password Surface',
    cve: 'CWE-521',
    cvss: 7.5,
    severity: 'High',
    remediation: 'Tunnel VNC over SSH, enforce strong authentication, or restrict to management VLANs.',
  },
  {
    port: 80,
    pattern: /Apache.*2\.2\.8|PHP\/5\.2/i,
    title: 'End-of-Life Apache 2.2.8 / PHP 5.2 Web Stack',
    cve: 'CWE-1104',
    cvss: 7.5,
    severity: 'High',
    remediation: 'Upgrade Apache & PHP to maintained releases and remove intentionally vulnerable demo apps.',
  },
];

function extractAttr(tag: string, name: string): string {
  const match = tag.match(new RegExp(`${name}="([^"]*)"`, 'i'));
  return match ? match[1] : '';
}

function parseNmapInput(raw: string): {
  format: 'xml' | 'text';
  targetIp: string;
  osGuess: string;
  openPorts: ParsedPort[];
  findings: CorrelatedFinding[];
} {
  const trimmed = raw.trim();
  const openPorts: ParsedPort[] = [];
  let targetIp = 'unknown';
  let osGuess = 'Not identified';
  let format: 'xml' | 'text' = 'text';

  if (trimmed.startsWith('<')) {
    format = 'xml';
    const addrMatch = trimmed.match(/<address\s+[^>]*addrtype="ipv4"[^>]*>/i);
    if (addrMatch) {
      targetIp = extractAttr(addrMatch[0], 'addr') || 'unknown';
    }
    const osMatch = trimmed.match(/<osmatch\s+[^>]*name="([^"]+)"/i);
    if (osMatch) {
      osGuess = osMatch[1];
    }

    const portRegex = /<port\s+([^>]*)>([\s\S]*?)<\/port>/gi;
    let m: RegExpExecArray | null;
    while ((m = portRegex.exec(trimmed)) !== null) {
      const attrs = m[1];
      const body = m[2];
      const stateMatch = body.match(/<state\s+[^>]*state="([^"]+)"/i);
      if (!stateMatch || stateMatch[1].toLowerCase() !== 'open') continue;

      const port = Number.parseInt(extractAttr(attrs, 'portid'), 10);
      const protocol = extractAttr(attrs, 'protocol') || 'tcp';
      const svcTag = body.match(/<service\s+[^>]*>/i)?.[0] || '';
      const service = extractAttr(svcTag, 'name') || 'unknown';
      const product = extractAttr(svcTag, 'product');
      const version = extractAttr(svcTag, 'version');
      const extrainfo = extractAttr(svcTag, 'extrainfo');
      const banner = [product, version, extrainfo].filter(Boolean).join(' ') || service;

      const nseNotes: string[] = [];
      const scriptRegex = /<script\s+([^>]*?)\/?>/gi;
      let sm: RegExpExecArray | null;
      while ((sm = scriptRegex.exec(body)) !== null) {
        const sid = extractAttr(sm[1], 'id');
        const sout = extractAttr(sm[1], 'output');
        if (sid && sout) nseNotes.push(`${sid}: ${sout.slice(0, 140)}`);
      }

      if (!Number.isNaN(port)) {
        openPorts.push({ port, protocol, service, banner, nseNotes });
      }
    }
  } else {
    const ipMatch = trimmed.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    if (ipMatch) targetIp = ipMatch[1];

    const osLine = trimmed.match(/OS details:\s*(.+)/i) || trimmed.match(/Running:\s*(.+)/i);
    if (osLine) osGuess = osLine[1].trim();

    for (const line of trimmed.split(/\r?\n/)) {
      const pm = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)$/i);
      if (pm) {
        openPorts.push({
          port: Number.parseInt(pm[1], 10),
          protocol: pm[2].toLowerCase(),
          service: pm[3],
          banner: pm[4].trim() || pm[3],
          nseNotes: [],
        });
      }
    }
  }

  openPorts.sort((a, b) => a.port - b.port);

  const findings: CorrelatedFinding[] = [];
  for (const svc of openPorts) {
    const searchable = `${svc.service} ${svc.banner}`;
    for (const sig of SIGNATURES) {
      if (svc.port === sig.port && sig.pattern.test(searchable)) {
        findings.push({
          port: svc.port,
          protocol: svc.protocol,
          serviceBanner: svc.banner,
          title: sig.title,
          cve: sig.cve,
          cvss: sig.cvss,
          severity: sig.severity,
          remediation: sig.remediation,
        });
      }
    }
  }
  findings.sort((a, b) => b.cvss - a.cvss);

  return { format, targetIp, osGuess, openPorts, findings };
}

function isBlockedMetadataHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return (
    lower === '169.254.169.254' ||
    lower.startsWith('169.254.') ||
    lower === 'metadata.google.internal' ||
    lower.endsWith('.internal') ||
    lower === 'localhost' ||
    lower === '127.0.0.1' ||
    lower === '::1'
  );
}

async function fetchSingleHttpHeader(
  target: URL,
  extraHeaders: Record<string, string> = {},
  method: 'GET' | 'HEAD' = 'GET'
): Promise<{
  statusCode: number;
  statusMessage: string;
  headers: Record<string, string>;
  setCookies: string[];
}> {
  return new Promise((resolve, reject) => {
    const client = target.protocol === 'https:' ? https : http;
    const req = client.request(
      target,
      {
        method,
        timeout: 5500,
        headers: {
          'User-Agent': 'VAPTLabStudio-Auditor/2.1',
          ...extraHeaders,
        },
        rejectUnauthorized: false,
      },
      (res) => {
        const normalized: Record<string, string> = {};
        const setCookies: string[] = [];
        for (const [k, v] of Object.entries(res.headers)) {
          const lk = k.toLowerCase();
          if (lk === 'set-cookie') {
            if (Array.isArray(v)) setCookies.push(...v);
            else if (typeof v === 'string') setCookies.push(v);
          }
          if (typeof v === 'string') normalized[lk] = v;
          else if (Array.isArray(v)) normalized[lk] = v.join(', ');
        }
        res.resume();
        resolve({
          statusCode: res.statusCode || 0,
          statusMessage: res.statusMessage || '',
          headers: normalized,
          setCookies,
        });
      }
    );
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out after 5.5 seconds.'));
    });
    req.on('error', (err) => reject(err));
    req.end();
  });
}

async function inspectUrlSecurity(targetUrl: string) {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
  } catch {
    throw new Error('Invalid URL format. Include a valid domain or http(s):// URL.');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only HTTP and HTTPS URLs are supported.');
  }
  if (isBlockedMetadataHost(parsed.hostname)) {
    throw new Error('Metadata and loopback host inspection is blocked.');
  }

  const dnsRecords: string[] = [];
  const mxRecords: string[] = [];
  const nsRecords: string[] = [];
  let spfRecord: string | null = null;
  let dmarcRecord: string | null = null;

  await Promise.all([
    dns
      .lookup(parsed.hostname, { all: true })
      .then((addrs) => {
        for (const a of addrs) dnsRecords.push(`${a.address} (IPv${a.family})`);
      })
      .catch(() => {}),
    dns
      .resolveMx(parsed.hostname)
      .then((mxs) => {
        for (const m of mxs.slice(0, 4)) mxRecords.push(`${m.exchange} (prio ${m.priority})`);
      })
      .catch(() => {}),
    dns
      .resolveNs(parsed.hostname)
      .then((nss) => {
        for (const n of nss.slice(0, 4)) nsRecords.push(n);
      })
      .catch(() => {}),
    dns
      .resolveTxt(parsed.hostname)
      .then((txts) => {
        const joined = txts.map((t) => t.join('')).find((s) => s.toLowerCase().includes('v=spf1'));
        if (joined) spfRecord = joined;
      })
      .catch(() => {}),
    dns
      .resolveTxt(`_dmarc.${parsed.hostname}`)
      .then((txts) => {
        const joined = txts.map((t) => t.join('')).find((s) => s.toLowerCase().includes('v=dmarc1'));
        if (joined) dmarcRecord = joined;
      })
      .catch(() => {}),
  ]);

  const startedAt = Date.now();
  const httpResponse = await fetchSingleHttpHeader(parsed, {
    Origin: 'https://untrusted-probe.example',
  });
  const responseTimeMs = Date.now() - startedAt;

  let tlsSummary: {
    protocol: string;
    subject: string;
    issuer: string;
    validTo: string;
    daysRemaining: number | null;
  } | null = null;

  if (parsed.protocol === 'https:') {
    const port = parsed.port ? Number.parseInt(parsed.port, 10) : 443;
    tlsSummary = await new Promise((resolve) => {
      const socket = tls.connect(
        {
          host: parsed.hostname,
          port,
          servername: parsed.hostname,
          rejectUnauthorized: false,
          timeout: 4500,
        },
        () => {
          const cert = socket.getPeerCertificate();
          const proto = socket.getProtocol() || 'TLS';
          socket.end();
          const rawSubject = cert?.subject?.CN;
          const rawIssuer = cert?.issuer?.O || cert?.issuer?.CN;
          const subjectStr = Array.isArray(rawSubject) ? rawSubject.join(', ') : (rawSubject || parsed.hostname);
          const issuerStr = Array.isArray(rawIssuer) ? rawIssuer.join(', ') : (rawIssuer || 'Unknown Issuer');
          const validTo = cert?.valid_to || 'Unknown';
          let daysRemaining: number | null = null;
          if (cert?.valid_to) {
            const expMs = Date.parse(cert.valid_to);
            if (!Number.isNaN(expMs)) {
              daysRemaining = Math.floor((expMs - Date.now()) / (1000 * 60 * 60 * 24));
            }
          }
          resolve({
            protocol: proto,
            subject: subjectStr,
            issuer: issuerStr,
            validTo,
            daysRemaining,
          });
        }
      );
      socket.on('error', () => resolve(null));
      socket.on('timeout', () => {
        socket.destroy();
        resolve(null);
      });
    });
  }

  const securityHeadersChecklist = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
  ].map((name) => ({
    header: name,
    present: Boolean(httpResponse.headers[name]),
    value: httpResponse.headers[name] || 'Missing',
  }));

  const acao = httpResponse.headers['access-control-allow-origin'] || '';
  const acac = httpResponse.headers['access-control-allow-credentials'] || '';
  const corsIssue =
    acao === 'https://untrusted-probe.example'
      ? `Reflected arbitrary Origin (${acao})${acac === 'true' ? ' with Allow-Credentials: true' : ''}`
      : acao === '*'
        ? 'Wildcard Access-Control-Allow-Origin (*)'
        : 'No arbitrary Origin reflection detected';

  const cookieIssues = httpResponse.setCookies.map((rawCookie) => {
    const cookieName = rawCookie.split('=')[0]?.trim() || 'cookie';
    const lower = rawCookie.toLowerCase();
    const missing: string[] = [];
    if (!lower.includes('httponly')) missing.push('HttpOnly');
    if (!lower.includes('secure')) missing.push('Secure');
    if (!lower.includes('samesite')) missing.push('SameSite');
    return {
      name: cookieName,
      missingFlags: missing,
      ok: missing.length === 0,
    };
  });

  const probePaths = ['/.well-known/security.txt', '/robots.txt', '/.env', '/.git/HEAD'];
  const pathChecks = await Promise.all(
    probePaths.map(async (probePath) => {
      try {
        const probeUrl = new URL(probePath, parsed.origin);
        const r = await fetchSingleHttpHeader(probeUrl, {}, 'HEAD');
        const sensitiveExposed =
          (probePath === '/.env' || probePath === '/.git/HEAD') && r.statusCode >= 200 && r.statusCode < 300;
        return {
          path: probePath,
          statusCode: r.statusCode,
          note: sensitiveExposed
            ? 'Potential sensitive file exposure (HTTP 2xx)'
            : r.statusCode >= 200 && r.statusCode < 400
              ? 'Accessible'
              : 'Restricted / Not found',
        };
      } catch {
        return { path: probePath, statusCode: 0, note: 'Request failed' };
      }
    })
  );

  const presentHeadersCount = securityHeadersChecklist.filter((h) => h.present).length;
  let score = Math.round((presentHeadersCount / securityHeadersChecklist.length) * 55);
  if (tlsSummary) score += 20;
  if (spfRecord) score += 8;
  if (dmarcRecord) score += 7;
  if (!acao || (acao !== 'https://untrusted-probe.example' && !(acao === '*' && acac === 'true'))) {
    score += 10;
  }
  const exposedSensitive = pathChecks.some(
    (p) => (p.path === '/.env' || p.path === '/.git/HEAD') && p.statusCode >= 200 && p.statusCode < 300
  );
  if (exposedSensitive) score = Math.max(0, score - 25);

  return {
    url: parsed.toString(),
    hostname: parsed.hostname,
    responseTimeMs,
    securityScore: Math.min(100, score),
    dnsRecords,
    mxRecords,
    nsRecords,
    spfRecord,
    dmarcRecord,
    statusCode: httpResponse.statusCode,
    statusMessage: httpResponse.statusMessage,
    serverBanner: httpResponse.headers['server'] || 'Not disclosed',
    poweredBy: httpResponse.headers['x-powered-by'] || 'Not disclosed',
    corsIssue,
    cookieIssues,
    pathChecks,
    securityHeadersChecklist,
    tlsSummary,
  };
}

const WELL_KNOWN_PORT_SERVICES: Record<number, string> = {
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'domain',
  80: 'http',
  110: 'pop3',
  139: 'netbios-ssn',
  143: 'imap',
  443: 'https',
  445: 'microsoft-ds',
  587: 'submission',
  1524: 'ingreslock',
  3306: 'mysql',
  3389: 'ms-wbt-server',
  5432: 'postgresql',
  5900: 'vnc',
  6379: 'redis',
  6667: 'irc',
  8080: 'http-proxy',
  8180: 'http-alt',
  8443: 'https-alt',
};

function probeSingleTcpPort(
  host: string,
  port: number
): Promise<{
  port: number;
  status: 'open' | 'closed' | 'filtered';
  latencyMs: number;
  service: string;
  banner: string;
}> {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let settled = false;
    let banner = '';

    const finish = (status: 'open' | 'closed' | 'filtered') => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        port,
        status,
        latencyMs: Date.now() - start,
        service: WELL_KNOWN_PORT_SERVICES[port] || 'tcp',
        banner: banner.replace(/[\r\n]+/g, ' ').trim().slice(0, 180) || (status === 'open' ? 'Connected (no immediate banner)' : '-'),
      });
    };

    socket.setTimeout(2200);

    socket.on('connect', () => {
      if (port === 80 || port === 8080 || port === 8000 || port === 8180) {
        socket.write(`HEAD / HTTP/1.0\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
      }
      setTimeout(() => finish('open'), 650);
    });

    socket.on('data', (chunk) => {
      banner += chunk.toString('utf8');
      if (banner.length >= 160) {
        finish('open');
      }
    });

    socket.on('timeout', () => {
      finish(banner ? 'open' : 'filtered');
    });

    socket.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ECONNREFUSED') finish('closed');
      else finish('filtered');
    });

    socket.connect(port, host);
  });
}

async function probeTcpTarget(rawHost: string, rawPorts: string) {
  let hostname = rawHost.trim();
  if (hostname.startsWith('http://') || hostname.startsWith('https://')) {
    hostname = new URL(hostname).hostname;
  } else {
    hostname = hostname.split('/')[0].split(':')[0];
  }

  if (!hostname || isBlockedMetadataHost(hostname)) {
    throw new Error('Enter a valid non-loopback target hostname or public IPv4 address.');
  }

  const parsedPorts = Array.from(
    new Set(
      rawPorts
        .split(/[\s,]+/)
        .map((p) => Number.parseInt(p.trim(), 10))
        .filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535)
    )
  ).slice(0, 15);

  if (parsedPorts.length === 0) {
    throw new Error('Specify at least one valid TCP port (1–65535).');
  }

  let resolvedIp = hostname;
  try {
    const looked = await dns.lookup(hostname);
    resolvedIp = looked.address;
    if (isBlockedMetadataHost(resolvedIp)) {
      throw new Error('Resolved host points to a blocked internal/loopback IP.');
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes('blocked')) throw err;
  }

  const results = await Promise.all(parsedPorts.map((p) => probeSingleTcpPort(resolvedIp, p)));
  results.sort((a, b) => a.port - b.port);

  return {
    host: hostname,
    resolvedIp,
    probedAt: new Date().toISOString(),
    results,
  };
}

interface LiveCveItem {
  id: string;
  published: string;
  severity: string;
  cvssScore: number | null;
  description: string;
  referenceUrl: string;
}

function fetchHttpsJson<T>(url: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        timeout: 6000,
        headers: {
          'User-Agent': 'VAPTLabStudio-CVEIntel/2.1',
          Accept: 'application/json',
        },
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => {
          if ((res.statusCode || 500) >= 400) {
            reject(new Error(`CVE API responded with HTTP ${res.statusCode}`));
            return;
          }
          try {
            resolve(JSON.parse(body) as T);
          } catch {
            reject(new Error('Invalid JSON returned by CVE database.'));
          }
        });
      }
    );
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Live CVE lookup timed out after 6 seconds.'));
    });
    req.on('error', (err) => reject(err));
  });
}

function scoreToSeverity(score: number | null): string {
  if (score === null) return 'UNRATED';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

interface ShodanCveRaw {
  cve_id?: string;
  summary?: string;
  cvss?: number | null;
  cvss_v3?: number | null;
  cvss_v2?: number | null;
  epss?: number | null;
  kev?: boolean;
  published_time?: string;
  references?: string[];
}

function normalizeShodanCve(item: ShodanCveRaw): LiveCveItem {
  const score = item.cvss_v3 ?? item.cvss ?? item.cvss_v2 ?? null;
  const id = item.cve_id || 'UNKNOWN';
  const tags: string[] = [];
  if (item.kev) tags.push('[CISA KEV]');
  if (typeof item.epss === 'number') tags.push(`[EPSS ${(item.epss * 100).toFixed(1)}%]`);
  const prefix = tags.length > 0 ? `${tags.join(' ')} ` : '';
  const summary = (item.summary || 'No summary available.').trim();
  const fullDesc = `${prefix}${summary}`;
  return {
    id,
    published: item.published_time ? item.published_time.slice(0, 10) : 'Unknown',
    severity: scoreToSeverity(score),
    cvssScore: score,
    description: fullDesc.slice(0, 280) + (fullDesc.length > 280 ? '…' : ''),
    referenceUrl: item.references?.[0] || `https://nvd.nist.gov/vuln/detail/${id}`,
  };
}

async function searchLiveNvdCves(keyword: string): Promise<LiveCveItem[]> {
  const cleaned = keyword.trim();
  const cveMatch = cleaned.match(/\b(CVE-\d{4}-\d{4,7})\b/i);

  if (cveMatch) {
    const cveId = cveMatch[1].toUpperCase();
    try {
      const single = await fetchHttpsJson<ShodanCveRaw>(
        `https://cvedb.shodan.io/cve/${encodeURIComponent(cveId)}`
      );
      if (single?.cve_id) return [normalizeShodanCve(single)];
    } catch {
      // Fallback to official MITRE CVE Services API
    }

    const mitre = await fetchHttpsJson<{
      cveMetadata?: { cveId?: string; datePublished?: string };
      containers?: {
        cna?: {
          descriptions?: Array<{ lang?: string; value?: string }>;
          references?: Array<{ url?: string }>;
        };
      };
    }>(`https://cveawg.mitre.org/api/cve/${encodeURIComponent(cveId)}`);

    const desc =
      mitre.containers?.cna?.descriptions?.find((d) => d.lang === 'en')?.value ||
      mitre.containers?.cna?.descriptions?.[0]?.value ||
      'No English description available.';
    return [
      {
        id: mitre.cveMetadata?.cveId || cveId,
        published: mitre.cveMetadata?.datePublished?.slice(0, 10) || 'Unknown',
        severity: 'UNRATED',
        cvssScore: null,
        description: desc.slice(0, 280) + (desc.length > 280 ? '…' : ''),
        referenceUrl:
          mitre.containers?.cna?.references?.[0]?.url ||
          `https://nvd.nist.gov/vuln/detail/${cveId}`,
      },
    ];
  }

  // Extract primary software/product keyword (e.g. "vsftpd 2.3.4" -> "vsftpd", "Apache httpd 2.2.8" -> "apache")
  const tokens = cleaned
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, ' ')
    .split(/\s+/)
    .filter((t) => t.length >= 2 && !/^\d+(\.\d+)*$/.test(t) && t !== 'httpd' && t !== 'smbd');
  const product = tokens[0] || cleaned.toLowerCase().split(/\s+/)[0];

  const data = await fetchHttpsJson<{ cves?: ShodanCveRaw[] }>(
    `https://cvedb.shodan.io/cves?product=${encodeURIComponent(product)}&limit=8`
  );
  return (data.cves || []).map(normalizeShodanCve);
}

async function startServer() {
  const app = express();
  const port = 3000;

  app.use(express.json({ limit: '2mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.post('/api/parse-nmap', (req, res) => {
    const raw = typeof req.body?.raw === 'string' ? req.body.raw : '';
    if (!raw.trim()) {
      return res.status(400).json({ error: 'Paste Nmap XML or Nmap scan text to analyze.' });
    }
    try {
      const result = parseNmapInput(raw);
      return res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unable to parse scan output.';
      return res.status(400).json({ error: message });
    }
  });

  app.post('/api/inspect-url', async (req, res) => {
    const url = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
    if (!url) {
      return res.status(400).json({ error: 'Enter a target URL (e.g., https://example.com).' });
    }
    try {
      const report = await inspectUrlSecurity(url);
      return res.json(report);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Target inspection failed.';
      return res.status(422).json({ error: message });
    }
  });

  app.post('/api/probe-port', async (req, res) => {
    const host = typeof req.body?.host === 'string' ? req.body.host.trim() : '';
    const ports = typeof req.body?.ports === 'string' ? req.body.ports.trim() : '21,22,80,443,8080';
    if (!host) {
      return res.status(400).json({ error: 'Enter a target hostname or public IPv4 address.' });
    }
    try {
      const report = await probeTcpTarget(host, ports);
      return res.json(report);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Live port probe failed.';
      return res.status(422).json({ error: message });
    }
  });

  app.get('/api/cve-search', async (req, res) => {
    const q = typeof req.query?.q === 'string' ? req.query.q.trim() : '';
    if (q.length < 2) {
      return res.status(400).json({ error: 'Provide a service, software, or CVE query (min 2 chars).' });
    }
    try {
      const items = await searchLiveNvdCves(q);
      return res.json({ query: q, count: items.length, items });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Live NVD lookup failed.';
      return res.status(502).json({ error: message });
    }
  });

  const httpServer = http.createServer(app);
  const hmrDisabled = process.env.DISABLE_HMR === 'true';

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: hmrDisabled ? false : { server: httpServer },
        watch: hmrDisabled ? null : {},
      },
      appType: 'spa',
    });

    if (hmrDisabled) {
      app.get('/@vite/client', async (req, res, next) => {
        try {
          const result = await vite.transformRequest(req.url);
          if (result?.code) {
            const safeCode = result.code
              .replace(/await wsTransport\.connect\(handlers\);/g, 'return;')
              .replace(/await wsTransport\.disconnect\(\);/g, 'return;')
              .replace(/wsTransport\.send\(data\);/g, 'return;');
            res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
            return res.status(200).send(safeCode);
          }
        } catch {
          // Fall through to Vite middlewares if transformRequest fails
        }
        return next();
      });
    }

    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  httpServer.listen(port, '0.0.0.0', () => {
    console.log(`Server listening on http://0.0.0.0:${port}`);
    console.log(`Open in browser: http://localhost:${port} (or http://127.0.0.1:${port})`);
  });
}

void startServer();
