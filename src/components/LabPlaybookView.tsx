import React, { useState } from 'react';
import {
  Check,
  CheckCircle2,
  Copy,
  FileText,
  Network,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import { LabConfig, PlaybookVector, Severity } from '../types/vapt';

interface LabPlaybookViewProps {
  config: LabConfig;
  vectors: PlaybookVector[];
  onUpdateVector: (id: string, patch: Partial<PlaybookVector>) => void;
  onGoToReport: () => void;
}

export const LabPlaybookView: React.FC<LabPlaybookViewProps> = ({
  config,
  vectors,
  onUpdateVector,
  onGoToReport,
}) => {
  const [severityFilter, setSeverityFilter] = useState<'All' | Severity>('All');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredVectors =
    severityFilter === 'All'
      ? vectors
      : vectors.filter((v) => v.severity === severityFilter);

  const handleCopy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 1600);
    } catch {
      // Clipboard fallback ignored
    }
  };

  const targetIp = config.targetIp || '192.168.56.101';
  const iface = config.networkInterface || 'eth0';

  const networkCheckCommands = `# 1. Confirm VirtualBox ${config.networkMode} isolation (no bridged public exposure)
ip -4 addr show ${iface}

# 2. Discover Metasploitable 2 IP on the local lab subnet
sudo arp-scan -I ${iface} --localnet

# 3. Verify bidirectional connectivity and baseline Nmap enumeration
ping -c 4 ${targetIp}
nmap -sS -sV -sC -O -Pn -oN metasploitable2_nmap.txt ${targetIp}`;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-[#1D2C35]">
        <div className="space-y-1">
          <p className="text-xs font-medium text-teal-700 dark:text-[#2DD4BF]">
            Practical Penetration Testing · {config.academyOrProgramName || 'Authorized Virtual Lab'}
          </p>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-[#F0F6FA]">
            {config.labName || 'Metasploitable 2'} Exploitation &amp; Evidence Playbook
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-300 max-w-2xl">
            Run these commands inside your Kali Linux VM against{' '}
            <code className="font-mono text-slate-900 dark:text-[#2DD4BF]">{targetIp}</code>, verify each compromise,
            and paste your real terminal output below to populate your VAPT PDF report.
          </p>
        </div>

        <button
          type="button"
          onClick={onGoToReport}
          className="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-semibold text-white bg-teal-700 hover:bg-teal-600 hover:shadow-[0_6px_18px_-4px_rgba(13,148,136,0.42)] dark:bg-[#14B8A6] dark:text-[#042F2E] dark:hover:bg-[#2DD4BF] dark:hover:shadow-[0_6px_22px_-4px_rgba(45,212,191,0.42)] rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
        >
          <FileText className="w-4 h-4" />
          <span>Review VAPT Report</span>
        </button>
      </div>

      {/* Step 1: Network & Isolation Pre-Flight */}
      <section className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <Network className="w-5 h-5 text-teal-700 dark:text-[#2DD4BF] shrink-0" />
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F0F6FA]">
                Lab Isolation &amp; Reconnaissance Baseline ({config.networkMode})
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Ensure both Kali Linux and Metasploitable 2 share the same isolated VirtualBox subnet before testing.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => handleCopy(networkCheckCommands, 'net-check')}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-[#131D23] dark:border dark:border-[#273B47] hover:bg-slate-200 dark:hover:bg-[#19262E] dark:hover:border-[#2DD4BF]/50 dark:hover:text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
          >
            {copiedId === 'net-check' ? (
              <>
                <Check className="w-3.5 h-3.5 text-teal-700 dark:text-[#2DD4BF]" />
                <span>Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Recon Commands</span>
              </>
            )}
          </button>
        </div>

        <pre className="p-4 bg-[#05080A] border border-[#1D2C35] text-teal-300 rounded-lg text-xs font-mono leading-relaxed overflow-x-auto">
          <code>{networkCheckCommands}</code>
        </pre>
      </section>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="inline-flex items-center gap-1 p-1 bg-slate-200/70 dark:bg-[#131D23] dark:border dark:border-[#1D2C35] rounded-lg">
          {(['All', 'Critical', 'High'] as const).map((level) => (
            <button
              key={level}
              type="button"
              onClick={() => setSeverityFilter(level)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
                severityFilter === level
                  ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {level === 'All' ? `All Vectors (${vectors.length})` : `${level} Severity`}
            </button>
          ))}
        </div>

        <span className="text-xs text-slate-500 dark:text-slate-400 tabular-nums">
          {vectors.filter((v) => v.verified).length} verified ·{' '}
          {vectors.filter((v) => v.includeInReport).length} included in PDF report
        </span>
      </div>

      {/* Attack Vector Cards */}
      <div className="space-y-5">
        {filteredVectors.map((vec) => (
          <article
            key={vec.id}
            className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-6 space-y-5"
          >
            {/* Card Title & Unboxed Metadata */}
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4 pb-4 border-b border-slate-100 dark:border-[#1D2C35]">
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                  <span
                    className={`font-semibold ${
                      vec.severity === 'Critical'
                        ? 'text-red-700 dark:text-rose-400'
                        : 'text-amber-700 dark:text-amber-400'
                    }`}
                  >
                    {vec.severity} (CVSS {vec.cvss})
                  </span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono tabular-nums">
                    Port {vec.port}/{vec.protocol}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span>{vec.service}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">{vec.cve}</span>
                </div>
                <h3 className="text-base font-semibold text-slate-900 dark:text-[#F0F6FA]">{vec.title}</h3>
                <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">{vec.summary}</p>
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => onUpdateVector(vec.id, { verified: !vec.verified })}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border whitespace-nowrap shrink-0 cursor-pointer ${
                    vec.verified
                      ? 'bg-emerald-50 border-emerald-300 text-emerald-800 hover:bg-emerald-100 dark:bg-emerald-500/15 dark:border-emerald-400/40 dark:text-emerald-300 dark:hover:bg-emerald-500/25'
                      : 'bg-white border-slate-300 text-slate-700 hover:bg-slate-50 dark:bg-[#131D23] dark:border-[#273B47] dark:text-slate-200 dark:hover:bg-[#19262E] dark:hover:border-[#2DD4BF]/50'
                  }`}
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>{vec.verified ? 'Verified in Lab' : 'Mark Verified'}</span>
                </button>

                <button
                  type="button"
                  onClick={() =>
                    onUpdateVector(vec.id, { includeInReport: !vec.includeInReport })
                  }
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border whitespace-nowrap shrink-0 cursor-pointer ${
                    vec.includeInReport
                      ? 'bg-teal-50 border-teal-300 text-teal-800 hover:bg-teal-100 dark:bg-[#14B8A6]/15 dark:border-[#2DD4BF]/40 dark:text-[#2DD4BF] dark:hover:bg-[#14B8A6]/25'
                      : 'bg-white border-slate-300 text-slate-600 hover:bg-slate-50 dark:bg-[#131D23] dark:border-[#273B47] dark:text-slate-300 dark:hover:bg-[#19262E] dark:hover:border-[#2DD4BF]/50'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>{vec.includeInReport ? 'In PDF Report' : 'Exclude from PDF'}</span>
                </button>
              </div>
            </div>

            {/* Kali Commands */}
            <div className="space-y-3">
              <div className="text-xs font-semibold text-slate-700 dark:text-slate-200 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-slate-500 dark:text-[#2DD4BF]" />
                <span>Execution Steps in Kali Linux</span>
              </div>
              <div className="space-y-2.5">
                {vec.commands.map((step, idx) => {
                  const cmdText = typeof step.cmd === 'function' ? step.cmd(config) : '';
                  const copyKey = `${vec.id}-${idx}`;
                  return (
                    <div key={copyKey} className="bg-[#05080A] border border-[#1D2C35] rounded-lg p-3 space-y-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[11px] font-medium text-slate-400">
                          {step.label}
                        </span>
                        <button
                          type="button"
                          onClick={() => handleCopy(cmdText, copyKey)}
                          className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] text-slate-300 hover:text-[#2DD4BF] rounded cursor-pointer"
                        >
                          {copiedId === copyKey ? (
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
                      <pre className="text-xs font-mono text-teal-300 overflow-x-auto">
                        <code>{cmdText}</code>
                      </pre>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Expected Proof + Impact + Remediation */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="bg-slate-50 dark:bg-[#131D23] border border-slate-200 dark:border-[#1D2C35] rounded-lg p-3.5 space-y-1">
                <div className="font-semibold text-slate-800 dark:text-[#F0F6FA]">Expected Proof &amp; Impact</div>
                <p className="font-mono text-slate-700 dark:text-[#2DD4BF] bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#273B47] rounded px-2 py-1 mt-1">
                  {vec.expectedProof}
                </p>
                <p className="text-slate-600 dark:text-slate-300 leading-relaxed pt-1">{vec.impact}</p>
              </div>
              <div className="bg-slate-50 dark:bg-[#131D23] border border-slate-200 dark:border-[#1D2C35] rounded-lg p-3.5 space-y-1">
                <div className="font-semibold text-slate-800 dark:text-[#F0F6FA] flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-teal-700 dark:text-[#2DD4BF]" />
                  <span>Remediation Recommendation</span>
                </div>
                <p className="text-slate-600 dark:text-slate-300 leading-relaxed pt-1">{vec.remediation}</p>
              </div>
            </div>

            {/* Personal Lab Evidence Inputs */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-slate-100 dark:border-[#1D2C35]">
              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
                  Paste Real Terminal Evidence Output (included in VAPT PDF)
                </span>
                <textarea
                  rows={3}
                  value={vec.evidenceOutput}
                  onChange={(e) =>
                    onUpdateVector(vec.id, { evidenceOutput: e.target.value })
                  }
                  placeholder={`Paste your actual Kali output here (e.g., uid=0(root) gid=0(root) from ${targetIp})...`}
                  className="w-full px-3 py-2 text-xs font-mono bg-slate-50 dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
                  Your Testing Observations &amp; Screenshot Figure Note
                </span>
                <textarea
                  rows={3}
                  value={vec.labNotes}
                  onChange={(e) => onUpdateVector(vec.id, { labNotes: e.target.value })}
                  placeholder="Describe how you verified this vulnerability and reference any screenshot figure (e.g., Figure 3: Root shell via vsftpd)..."
                  className="w-full px-3 py-2 text-xs bg-slate-50 dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
};
