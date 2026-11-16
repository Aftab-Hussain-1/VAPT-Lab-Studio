import React, { useState } from 'react';
import { Download, Edit3, Eye, Printer } from 'lucide-react';
import { LabConfig, PlaybookVector, ReportTextSections } from '../types/vapt';

interface VaptReportViewProps {
  config: LabConfig;
  onUpdateConfig: (patch: Partial<LabConfig>) => void;
  vectors: PlaybookVector[];
  sections: ReportTextSections;
  onUpdateSections: (patch: Partial<ReportTextSections>) => void;
}

export const VaptReportView: React.FC<VaptReportViewProps> = ({
  config,
  onUpdateConfig,
  vectors,
  sections,
  onUpdateSections,
}) => {
  const [mode, setMode] = useState<'preview' | 'edit'>('preview');

  const includedFindings = vectors.filter((v) => v.includeInReport);
  const criticalCount = includedFindings.filter((v) => v.severity === 'Critical').length;
  const highCount = includedFindings.filter((v) => v.severity === 'High').length;

  const targetIp = config.targetIp || '192.168.56.101';
  const kaliIp = config.kaliIp || '192.168.56.102';
  const assessor = config.internName || 'Alex Rivera';
  const programName = config.academyOrProgramName || 'Practical VAPT Engagement';
  const labName = config.labName || 'Metasploitable 2 Virtual Lab';
  const toolName = config.toolName || 'AutoReconVAPT';

  const handleExportMarkdown = () => {
    const safeSlug = labName.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'target';
    const md = [
      `# Vulnerability Assessment & Penetration Testing (VAPT) Report`,
      `**Program:** ${programName}`,
      `**Target System:** ${labName} (\`${targetIp}\`)`,
      `**Attacker System:** Kali Linux (\`${kaliIp}\`)`,
      `**Automation Toolkit:** ${toolName} (\`${config.githubUsername}/${config.repoName}\`)`,
      `**Assessor:** ${assessor}`,
      `**Assessment Date:** ${config.assessmentDate}`,
      ``,
      `## 1. Project Overview and Objective`,
      sections.projectOverview,
      ``,
      `## 2. Lab Setup and Network Configuration`,
      sections.labSetupNotes,
      ``,
      `## 3. Target Machine Details`,
      sections.targetDetails,
      ``,
      `## 4. Scope and Methodology`,
      sections.scopeAndMethodology,
      ``,
      `## 5. Reconnaissance and Enumeration Results`,
      `\`\`\`text`,
      sections.reconRawOutput,
      `\`\`\``,
      ``,
      `## 6. Vulnerabilities Identified`,
      `| ID | Severity | CVSS | Port/Service | Vulnerability | Reference |`,
      `| --- | --- | ---: | --- | --- | --- |`,
      ...includedFindings.map(
        (v, idx) =>
          `| VAPT-${String(idx + 1).padStart(2, '0')} | ${v.severity} | ${v.cvss} | ${v.port}/${v.protocol} (${v.service}) | ${v.title} | ${v.cve} |`
      ),
      ``,
      `## 7. Exploitation Methodology and Evidence`,
      ...includedFindings.flatMap((v, idx) => [
        `### 7.${idx + 1} ${v.title} (${v.cve})`,
        `- **Vector:** Port ${v.port}/${v.protocol} (${v.service})`,
        `- **Command Executed:** \`${typeof v.commands?.[0]?.cmd === 'function' ? v.commands[0].cmd(config) : ''}\``,
        `- **Tester Notes:** ${v.labNotes || 'Executed inside isolated VirtualBox lab environment.'}`,
        `- **Terminal Evidence:**`,
        `\`\`\`text`,
        v.evidenceOutput || `[Paste your real Kali terminal output for ${v.service}]`,
        `\`\`\``,
        ``,
      ]),
      `## 8. Proof of Successful Compromise`,
      sections.proofOfCompromiseSummary,
      ``,
      `## 9. Risk Assessment and Impact`,
      sections.riskAssessmentNotes,
      ``,
      `## 10. Remediation Recommendations`,
      ...includedFindings.map((v, idx) => `${idx + 1}. **${v.title}:** ${v.remediation}`),
      ``,
      `## 11. Conclusion and Lessons Learned`,
      sections.conclusionAndLessons,
      ``,
    ].join('\n');

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VAPT_Report_${safeSlug}_${targetIp}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Screen-only Toolbar */}
      <div className="print:hidden flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-[#1D2C35]">
        <div className="space-y-1">
          <p className="text-xs font-medium text-teal-700 dark:text-[#2DD4BF]">
            {programName} · 11 Required Report Sections · Print-to-PDF Ready
          </p>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-[#F0F6FA]">
            Professional VAPT Report Studio
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Review or customize all 11 sections below, verify your pasted terminal evidence, then
            click <strong>Print / Save as PDF</strong>.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <div className="inline-flex items-center gap-1 p-1 bg-slate-200/70 dark:bg-[#131D23] dark:border dark:border-[#1D2C35] rounded-lg">
            <button
              type="button"
              onClick={() => setMode('preview')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
                mode === 'preview'
                  ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>Report Preview</span>
            </button>
            <button
              type="button"
              onClick={() => setMode('edit')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
                mode === 'edit'
                  ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              <Edit3 className="w-3.5 h-3.5" />
              <span>Edit Sections</span>
            </button>
          </div>

          <button
            type="button"
            onClick={handleExportMarkdown}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] hover:bg-slate-50 hover:border-teal-500/40 dark:hover:bg-[#19262E] dark:hover:border-[#2DD4BF]/50 dark:hover:text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Markdown</span>
          </button>

          <button
            type="button"
            onClick={() => window.print()}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-teal-700 hover:bg-teal-600 hover:shadow-[0_6px_18px_-4px_rgba(13,148,136,0.42)] dark:bg-[#14B8A6] dark:text-[#042F2E] dark:hover:bg-[#2DD4BF] dark:hover:shadow-[0_6px_22px_-4px_rgba(45,212,191,0.42)] rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / Save as PDF</span>
          </button>
        </div>
      </div>

      {/* Quick Assessor & Report Header Editor (Screen-only) */}
      <div className="print:hidden bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <label className="block space-y-1">
          <span className="text-[11px] font-semibold text-slate-600 dark:text-slate-300">Assessor Name (Report Author)</span>
          <input
            type="text"
            value={config.internName}
            onChange={(e) => onUpdateConfig({ internName: e.target.value })}
            placeholder="Alex Rivera"
            className="w-full px-3 py-1.5 text-xs bg-slate-50 dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
          />
        </label>
        <label className="block space-y-1">
          <span className="text-[11px] font-semibold text-slate-600 dark:text-slate-300">Program / Organization</span>
          <input
            type="text"
            value={config.academyOrProgramName}
            onChange={(e) => onUpdateConfig({ academyOrProgramName: e.target.value })}
            placeholder="Cybersecurity Internship — Phase 2"
            className="w-full px-3 py-1.5 text-xs bg-slate-50 dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
          />
        </label>
        <label className="block space-y-1">
          <span className="text-[11px] font-semibold text-slate-600 dark:text-slate-300">Target Machine Name</span>
          <input
            type="text"
            value={config.labName}
            onChange={(e) => onUpdateConfig({ labName: e.target.value })}
            placeholder="Metasploitable 2 Virtual Lab"
            className="w-full px-3 py-1.5 text-xs bg-slate-50 dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
          />
        </label>
        <label className="block space-y-1">
          <span className="text-[11px] font-semibold text-slate-600 dark:text-slate-300">Assessment Date</span>
          <input
            type="date"
            value={config.assessmentDate}
            onChange={(e) => onUpdateConfig({ assessmentDate: e.target.value })}
            className="w-full px-3 py-1.5 text-xs font-mono tabular-nums bg-slate-50 dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
          />
        </label>
      </div>

      {/* Edit Mode Form */}
      {mode === 'edit' && (
        <div className="print:hidden bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-6 space-y-5">
          <div className="pb-3 border-b border-slate-100 dark:border-[#1D2C35]">
            <h2 className="text-base font-semibold text-slate-900 dark:text-[#F0F6FA]">
              Customize Narrative &amp; Paste Your Real Nmap Reconnaissance Output
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Personalize every section with observations from your Kali Linux + {labName} session.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-5">
            <label className="block space-y-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">1. Project Overview and Objective</span>
              <textarea
                rows={3}
                value={sections.projectOverview}
                onChange={(e) => onUpdateSections({ projectOverview: e.target.value })}
                className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
              />
            </label>

            <label className="block space-y-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">2. Lab Setup and Network Configuration</span>
              <textarea
                rows={3}
                value={sections.labSetupNotes}
                onChange={(e) => onUpdateSections({ labSetupNotes: e.target.value })}
                className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
              />
            </label>

            <label className="block space-y-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">3. Target Machine Details</span>
              <textarea
                rows={3}
                value={sections.targetDetails}
                onChange={(e) => onUpdateSections({ targetDetails: e.target.value })}
                className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
              />
            </label>

            <label className="block space-y-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">4. Scope and Methodology</span>
              <textarea
                rows={3}
                value={sections.scopeAndMethodology}
                onChange={(e) => onUpdateSections({ scopeAndMethodology: e.target.value })}
                className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
              />
            </label>

            <label className="block space-y-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                5. Reconnaissance and Enumeration Results (Paste Nmap / {toolName} Output)
              </span>
              <textarea
                rows={8}
                value={sections.reconRawOutput}
                onChange={(e) => onUpdateSections({ reconRawOutput: e.target.value })}
                className="w-full px-3 py-2 text-xs font-mono bg-slate-50 dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
              />
            </label>

            <label className="block space-y-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">8. Proof of Successful Compromise</span>
              <textarea
                rows={3}
                value={sections.proofOfCompromiseSummary}
                onChange={(e) => onUpdateSections({ proofOfCompromiseSummary: e.target.value })}
                className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
              />
            </label>

            <label className="block space-y-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">9. Risk Assessment and Impact</span>
              <textarea
                rows={3}
                value={sections.riskAssessmentNotes}
                onChange={(e) => onUpdateSections({ riskAssessmentNotes: e.target.value })}
                className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
              />
            </label>

            <label className="block space-y-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">11. Conclusion and Lessons Learned</span>
              <textarea
                rows={3}
                value={sections.conclusionAndLessons}
                onChange={(e) => onUpdateSections({ conclusionAndLessons: e.target.value })}
                className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
              />
            </label>
          </div>
        </div>
      )}

      {/* Printable Report Document Canvas */}
      <article
        className={`${
          mode === 'edit' ? 'hidden print:block' : 'block'
        } bg-white dark:bg-[#0D1418] print:!bg-white border border-slate-200 dark:border-[#1D2C35] print:!border-0 rounded-xl p-8 sm:p-10 print:p-0 max-w-4xl mx-auto space-y-8 text-slate-900 dark:text-[#E6EDF3] print:!text-slate-900`}
      >
        {/* Document Cover Header */}
        <header className="pb-6 border-b border-slate-300 dark:border-[#1D2C35] print:!border-slate-300 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-[#2DD4BF] print:!text-slate-500">
            <span>{programName}</span>
            <span className="font-mono tabular-nums">Date: {config.assessmentDate}</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">
            Vulnerability Assessment &amp; Penetration Testing Report
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-300 print:!text-slate-600">
            Authorized Isolated Virtual Lab Assessment — Target: {labName} ({targetIp})
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-3 text-xs">
            <div>
              <div className="text-slate-500 dark:text-slate-400 print:!text-slate-500">Assessor</div>
              <div className="font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900 mt-0.5">{assessor}</div>
            </div>
            <div>
              <div className="text-slate-500 dark:text-slate-400 print:!text-slate-500">Attacking Host</div>
              <div className="font-mono text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900 mt-0.5">{kaliIp}</div>
            </div>
            <div>
              <div className="text-slate-500 dark:text-slate-400 print:!text-slate-500">Target Host</div>
              <div className="font-mono text-slate-900 dark:text-[#2DD4BF] print:!text-slate-900 mt-0.5">{targetIp}</div>
            </div>
            <div>
              <div className="text-slate-500 dark:text-slate-400 print:!text-slate-500">Findings Summary</div>
              <div className="font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900 mt-0.5 tabular-nums">
                {criticalCount} Critical · {highCount} High
              </div>
            </div>
          </div>
        </header>

        {/* 1. Project Overview */}
        <section className="space-y-2 print-avoid-break">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">
            1. Project Overview and Objective
          </h2>
          <p className="text-sm text-slate-700 dark:text-slate-300 print:!text-slate-700 leading-relaxed whitespace-pre-line">
            {sections.projectOverview}
          </p>
        </section>

        {/* 2. Lab Setup */}
        <section className="space-y-2 print-avoid-break">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">
            2. Lab Setup and Network Configuration
          </h2>
          <p className="text-sm text-slate-700 dark:text-slate-300 print:!text-slate-700 leading-relaxed whitespace-pre-line">
            {sections.labSetupNotes}
          </p>
          <div className="overflow-x-auto pt-2">
            <table className="w-full text-xs border border-slate-200 dark:border-[#1D2C35] print:!border-slate-200">
              <thead className="bg-slate-50 dark:bg-[#131D23] print:!bg-slate-50 text-slate-700 dark:text-slate-200 print:!text-slate-700">
                <tr>
                  <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35] print:!border-slate-200 font-semibold">Virtual Machine</th>
                  <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35] print:!border-slate-200 font-semibold">Role</th>
                  <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35] print:!border-slate-200 font-semibold">Adapter Mode</th>
                  <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35] print:!border-slate-200 font-semibold">IPv4 Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-[#1D2C35] print:!divide-slate-200">
                <tr>
                  <td className="px-3 py-2 font-medium">Kali Linux</td>
                  <td className="px-3 py-2">Attacking Workstation</td>
                  <td className="px-3 py-2">{config.networkMode}</td>
                  <td className="px-3 py-2 font-mono tabular-nums">{kaliIp}</td>
                </tr>
                <tr>
                  <td className="px-3 py-2 font-medium">{labName}</td>
                  <td className="px-3 py-2">Authorized Target</td>
                  <td className="px-3 py-2">{config.networkMode}</td>
                  <td className="px-3 py-2 font-mono tabular-nums">{targetIp}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        {/* 3. Target Details */}
        <section className="space-y-2 print-avoid-break">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">3. Target Machine Details</h2>
          <p className="text-sm text-slate-700 dark:text-slate-300 print:!text-slate-700 leading-relaxed whitespace-pre-line">
            {sections.targetDetails}
          </p>
        </section>

        {/* 4. Scope and Methodology */}
        <section className="space-y-2 print-avoid-break">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">4. Scope and Methodology</h2>
          <p className="text-sm text-slate-700 dark:text-slate-300 print:!text-slate-700 leading-relaxed whitespace-pre-line">
            {sections.scopeAndMethodology}
          </p>
        </section>

        {/* 5. Reconnaissance Results */}
        <section className="space-y-2">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">
            5. Reconnaissance and Enumeration Results
          </h2>
          <pre className="p-4 bg-[#05080A] border border-[#1D2C35] text-teal-300 print:!bg-slate-950 print:!text-slate-100 rounded-lg text-xs font-mono leading-relaxed overflow-x-auto whitespace-pre-wrap">
            {sections.reconRawOutput}
          </pre>
        </section>

        {/* 6. Vulnerabilities Identified */}
        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">
            6. Vulnerabilities Identified
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-xs border border-slate-200 dark:border-[#1D2C35] print:!border-slate-200">
              <thead className="bg-slate-50 dark:bg-[#131D23] print:!bg-slate-50 text-slate-700 dark:text-slate-200 print:!text-slate-700">
                <tr>
                  <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35] print:!border-slate-200 font-semibold">ID</th>
                  <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35] print:!border-slate-200 font-semibold">Severity</th>
                  <th className="text-right px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35] print:!border-slate-200 font-semibold">CVSS</th>
                  <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35] print:!border-slate-200 font-semibold">Port / Service</th>
                  <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35] print:!border-slate-200 font-semibold">Finding</th>
                  <th className="text-left px-3 py-2 border-b border-slate-200 dark:border-[#1D2C35] print:!border-slate-200 font-semibold">Reference</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-[#1D2C35] print:!divide-slate-200">
                {includedFindings.map((v, idx) => (
                  <tr key={v.id}>
                    <td className="px-3 py-2 font-mono tabular-nums">
                      VAPT-{String(idx + 1).padStart(2, '0')}
                    </td>
                    <td
                      className={`px-3 py-2 font-semibold ${
                        v.severity === 'Critical'
                          ? 'text-red-700 dark:text-rose-400 print:!text-red-700'
                          : 'text-amber-700 dark:text-amber-400 print:!text-amber-700'
                      }`}
                    >
                      {v.severity}
                    </td>
                    <td className="px-3 py-2 text-right font-mono tabular-nums">{v.cvss}</td>
                    <td className="px-3 py-2 font-mono">
                      {v.port}/{v.protocol} · {v.service}
                    </td>
                    <td className="px-3 py-2 font-medium text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">{v.title}</td>
                    <td className="px-3 py-2 font-mono">{v.cve}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* 7. Exploitation Methodology and Evidence */}
        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">
            7. Exploitation Methodology and Evidence
          </h2>
          <div className="space-y-5">
            {includedFindings.map((v, idx) => (
              <div
                key={v.id}
                className="border border-slate-200 dark:border-[#1D2C35] print:!border-slate-200 rounded-lg p-4 space-y-2.5 print-avoid-break"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">
                    7.{idx + 1} {v.title}
                  </h3>
                  <span className="text-xs font-mono text-slate-500 dark:text-[#2DD4BF] print:!text-slate-500">
                    {v.cve} · Port {v.port}/{v.protocol}
                  </span>
                </div>
                <p className="text-xs text-slate-700 dark:text-slate-300 print:!text-slate-700 leading-relaxed">{v.summary}</p>
                <div className="text-xs text-slate-600 dark:text-slate-300 print:!text-slate-600">
                  <span className="font-semibold text-slate-800 dark:text-[#F0F6FA] print:!text-slate-800">Primary Command: </span>
                  <code className="font-mono bg-slate-100 dark:bg-[#131D23] dark:text-[#2DD4BF] print:!bg-slate-100 print:!text-slate-800 px-1.5 py-0.5 rounded">
                    {typeof v.commands?.[0]?.cmd === 'function' ? v.commands[0].cmd(config) : ''}
                  </code>
                </div>
                {v.labNotes && (
                  <p className="text-xs text-slate-700 dark:text-slate-300 print:!text-slate-700">
                    <span className="font-semibold text-slate-800 dark:text-[#F0F6FA] print:!text-slate-800">Assessor Notes: </span>
                    {v.labNotes}
                  </p>
                )}
                <pre className="p-3 bg-[#05080A] border border-[#1D2C35] text-teal-300 print:!bg-slate-950 print:!text-slate-100 rounded text-[11px] font-mono overflow-x-auto whitespace-pre-wrap">
                  {v.evidenceOutput.trim() ||
                    `[Evidence placeholder — paste your actual Kali terminal output confirming: ${v.expectedProof}]`}
                </pre>
              </div>
            ))}
          </div>
        </section>

        {/* 8. Proof of Successful Compromise */}
        <section className="space-y-2 print-avoid-break">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">
            8. Proof of Successful Compromise
          </h2>
          <p className="text-sm text-slate-700 dark:text-slate-300 print:!text-slate-700 leading-relaxed whitespace-pre-line">
            {sections.proofOfCompromiseSummary}
          </p>
        </section>

        {/* 9. Risk Assessment and Impact */}
        <section className="space-y-2 print-avoid-break">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">9. Risk Assessment and Impact</h2>
          <p className="text-sm text-slate-700 dark:text-slate-300 print:!text-slate-700 leading-relaxed whitespace-pre-line">
            {sections.riskAssessmentNotes}
          </p>
        </section>

        {/* 10. Remediation Recommendations */}
        <section className="space-y-2 print-avoid-break">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">
            10. Remediation Recommendations
          </h2>
          <ol className="list-decimal pl-5 space-y-2 text-sm text-slate-700 dark:text-slate-300 print:!text-slate-700">
            {includedFindings.map((v) => (
              <li key={v.id} className="leading-relaxed">
                <span className="font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">
                  {v.title} (Port {v.port}):{' '}
                </span>
                {v.remediation}
              </li>
            ))}
          </ol>
        </section>

        {/* 11. Conclusion and Lessons Learned */}
        <section className="space-y-2 print-avoid-break">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] print:!text-slate-900">
            11. Conclusion and Lessons Learned
          </h2>
          <p className="text-sm text-slate-700 dark:text-slate-300 print:!text-slate-700 leading-relaxed whitespace-pre-line">
            {sections.conclusionAndLessons}
          </p>
        </section>
      </article>
    </div>
  );
};
