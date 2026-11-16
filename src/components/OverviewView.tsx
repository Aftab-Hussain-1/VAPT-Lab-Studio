import React, { useState } from 'react';
import {
  ArrowRight,
  CheckSquare,
  FileCode2,
  FileText,
  FolderPlus,
  Network,
  Square,
  Terminal,
  Trash2,
} from 'lucide-react';
import {
  LabConfig,
  MilestoneItem,
  PlaybookVector,
  SavedWorkspaceSummary,
  WorkspaceTab,
} from '../types/vapt';

interface OverviewViewProps {
  config: LabConfig;
  onUpdateConfig: (patch: Partial<LabConfig>) => void;
  milestones: MilestoneItem[];
  onToggleMilestone: (id: string) => void;
  vectors: PlaybookVector[];
  onNavigate: (tab: WorkspaceTab) => void;
  isSignedIn: boolean;
  savedWorkspaces: SavedWorkspaceSummary[];
  activeWorkspaceId: string;
  onSelectWorkspace: (id: string) => void;
  onCreateWorkspace: (name: string) => void;
  onDeleteWorkspace: (id: string) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  config,
  onUpdateConfig,
  milestones,
  onToggleMilestone,
  vectors,
  onNavigate,
  isSignedIn,
  savedWorkspaces,
  activeWorkspaceId,
  onSelectWorkspace,
  onCreateWorkspace,
  onDeleteWorkspace,
}) => {
  const [newWorkspaceName, setNewWorkspaceName] = useState('');

  const completedCount = milestones.filter((m) => m.completed).length;
  const verifiedVectors = vectors.filter((v) => v.verified).length;
  const includedVectors = vectors.filter((v) => v.includeInReport).length;

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newWorkspaceName.trim();
    if (!trimmed) return;
    onCreateWorkspace(trimmed);
    setNewWorkspaceName('');
  };

  return (
    <div className="space-y-8">
      {/* Header Summary */}
      <section className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-200 dark:border-[#1D2C35]">
        <div className="max-w-2xl space-y-2">
          <p className="text-xs font-medium text-teal-700 dark:text-[#2DD4BF] tracking-wide">
            {config.academyOrProgramName || 'Security Assessment Program'} · Deadline{' '}
            {config.submissionDeadline || '18 Nov 2026'}
          </p>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-[#F0F6FA] [text-wrap:balance]">
            {config.brandTitle || 'VAPT Lab Studio'}
          </h1>
          <p className="text-sm sm:text-base text-slate-600 dark:text-slate-300 leading-relaxed">
            Customize your brand, lab, tool, and GitHub repository names below. Every Python/Bash
            script, README, MIT License, Kali command, and VAPT PDF section updates dynamically.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => onNavigate('automation')}
            className="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-semibold text-white bg-teal-700 hover:bg-teal-600 hover:shadow-[0_6px_18px_-4px_rgba(13,148,136,0.42)] dark:bg-[#14B8A6] dark:text-[#042F2E] dark:hover:bg-[#2DD4BF] dark:hover:shadow-[0_6px_22px_-4px_rgba(45,212,191,0.42)] rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
          >
            <FileCode2 className="w-4 h-4" />
            <span>Open Automation Tool</span>
          </button>
          <button
            type="button"
            onClick={() => onNavigate('report')}
            className="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] hover:bg-slate-50 hover:border-teal-500/40 dark:hover:bg-[#19262E] dark:hover:border-[#2DD4BF]/50 dark:hover:text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
          >
            <FileText className="w-4 h-4" />
            <span>Open VAPT Report</span>
          </button>
        </div>
      </section>

      {/* 4-Column Quantitative Summary Strip */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Target Machine</div>
          <div className="mt-2 text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] font-mono tabular-nums truncate">
            {config.targetIp || '192.168.56.101'}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400 truncate">
            {config.labName || 'Virtual Lab'} · {config.networkMode}
          </div>
        </div>

        <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">GitHub &amp; Tool Identity</div>
          <div className="mt-2 text-lg font-semibold text-slate-900 dark:text-[#F0F6FA] truncate">
            {config.toolName || 'AutoReconVAPT'}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400 font-mono truncate">
            {config.githubUsername || 'user'}/{config.repoName || 'repo'}
          </div>
        </div>

        <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Lab Vectors Verified</div>
          <div className="mt-2 text-lg font-semibold text-slate-900 dark:text-[#2DD4BF] tabular-nums">
            {verifiedVectors} / {vectors.length} Tested
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">{includedVectors} selected for PDF report</div>
        </div>

        <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Project Milestones</div>
          <div className="mt-2 text-lg font-semibold text-slate-900 dark:text-amber-400 tabular-nums">
            {completedCount} / {milestones.length} Done
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {isSignedIn ? 'Synced to your account' : 'Saved in browser'}
          </div>
        </div>
      </section>

      {/* Lab Configuration Form + Quick Workflow */}
      <section className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        <div className="xl:col-span-7 bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-[#1D2C35] pb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-[#F0F6FA]">
                Branding, GitHub &amp; Lab Configuration
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Rename your studio, program, lab, automation CLI, and GitHub repository at any time.
              </p>
            </div>
            <Network className="w-5 h-5 text-slate-400 dark:text-[#2DD4BF] shrink-0" />
          </div>

          {/* Group 1: Project, Tool & GitHub Naming */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-slate-500 dark:text-[#2DD4BF]">
              01. Project, Brand &amp; GitHub Repository Names
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Workspace / Studio Name</span>
                <input
                  type="text"
                  value={config.brandTitle}
                  onChange={(e) => onUpdateConfig({ brandTitle: e.target.value })}
                  placeholder="VAPT Lab Studio"
                  className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Program / Academy Name</span>
                <input
                  type="text"
                  value={config.academyOrProgramName}
                  onChange={(e) => onUpdateConfig({ academyOrProgramName: e.target.value })}
                  placeholder="Cybersecurity Internship — Phase 2"
                  className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Lab Target Name</span>
                <input
                  type="text"
                  value={config.labName}
                  onChange={(e) => onUpdateConfig({ labName: e.target.value })}
                  placeholder="Metasploitable 2 Virtual Lab"
                  className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Automation Tool CLI Name</span>
                <input
                  type="text"
                  value={config.toolName}
                  onChange={(e) => onUpdateConfig({ toolName: e.target.value })}
                  placeholder="AutoReconVAPT"
                  className="w-full px-3 py-2 text-sm font-mono bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Author / Assessor Name</span>
                <input
                  type="text"
                  value={config.internName}
                  onChange={(e) => onUpdateConfig({ internName: e.target.value })}
                  placeholder="Your Name"
                  className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">GitHub Username</span>
                <input
                  type="text"
                  value={config.githubUsername}
                  onChange={(e) => onUpdateConfig({ githubUsername: e.target.value })}
                  placeholder="your-username"
                  className="w-full px-3 py-2 text-sm font-mono bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">GitHub Repository Name</span>
                <input
                  type="text"
                  value={config.repoName}
                  onChange={(e) => onUpdateConfig({ repoName: e.target.value })}
                  placeholder="autorecon-vapt-suite"
                  className="w-full px-3 py-2 text-sm font-mono bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Submission Deadline</span>
                <input
                  type="text"
                  value={config.submissionDeadline}
                  onChange={(e) => onUpdateConfig({ submissionDeadline: e.target.value })}
                  placeholder="18 Nov 2026"
                  className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>
            </div>
          </div>

          {/* Group 2: Kali & Target Network */}
          <div className="space-y-3 pt-4 border-t border-slate-100 dark:border-[#1D2C35]">
            <h3 className="text-xs font-semibold text-slate-500 dark:text-[#2DD4BF]">
              02. Kali Linux &amp; VirtualBox Network Configuration
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Kali Linux IP (Attacker)</span>
                <input
                  type="text"
                  value={config.kaliIp}
                  onChange={(e) => onUpdateConfig({ kaliIp: e.target.value })}
                  placeholder="192.168.56.102"
                  className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Target VM IP</span>
                <input
                  type="text"
                  value={config.targetIp}
                  onChange={(e) => onUpdateConfig({ targetIp: e.target.value })}
                  placeholder="192.168.56.101"
                  className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Kali Interface</span>
                <input
                  type="text"
                  value={config.networkInterface}
                  onChange={(e) => onUpdateConfig({ networkInterface: e.target.value })}
                  placeholder="eth0"
                  className="w-full px-3 py-2 text-sm font-mono bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">VirtualBox Adapter Mode</span>
                <select
                  value={config.networkMode}
                  onChange={(e) =>
                    onUpdateConfig({
                      networkMode: e.target.value as LabConfig['networkMode'],
                    })
                  }
                  className="w-full px-3 py-2 text-sm bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                >
                  <option value="Host-Only (vboxnet0)">Host-Only (vboxnet0)</option>
                  <option value="NAT Network">NAT Network</option>
                </select>
              </label>

              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Assessment Date</span>
                <input
                  type="date"
                  value={config.assessmentDate}
                  onChange={(e) => onUpdateConfig({ assessmentDate: e.target.value })}
                  className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                />
              </label>
            </div>
          </div>
        </div>

        {/* Right Column: Saved Lab Profiles + Workflow */}
        <div className="xl:col-span-5 space-y-4">
          {/* Cloud Lab Profiles Switcher */}
          <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-slate-900 dark:text-[#F0F6FA]">Saved Lab Profiles</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  {isSignedIn
                    ? 'Save and switch between multiple target labs across devices.'
                    : 'Sign in with Google from the sidebar to store multiple labs in your account.'}
                </p>
              </div>
            </div>

            {isSignedIn && (
              <>
                <form onSubmit={handleCreate} className="flex items-center gap-2">
                  <input
                    type="text"
                    value={newWorkspaceName}
                    onChange={(e) => setNewWorkspaceName(e.target.value)}
                    placeholder="New lab profile (e.g. Mr-Robot 1)"
                    className="flex-1 min-w-0 px-3 py-2 text-xs bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] text-slate-900 dark:text-[#E6EDF3] dark:placeholder:text-slate-500 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-600/20 dark:focus:ring-[#2DD4BF]/25 focus:border-teal-700 dark:focus:border-[#2DD4BF]"
                  />
                  <button
                    type="submit"
                    className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-white bg-teal-700 hover:bg-teal-600 hover:shadow-[0_4px_14px_-3px_rgba(13,148,136,0.4)] dark:bg-[#14B8A6] dark:text-[#042F2E] dark:hover:bg-[#2DD4BF] dark:hover:shadow-[0_4px_16px_-3px_rgba(45,212,191,0.4)] rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <FolderPlus className="w-3.5 h-3.5" />
                    <span>Save As New</span>
                  </button>
                </form>

                {savedWorkspaces.length === 0 ? (
                  <p className="text-xs text-slate-500 dark:text-slate-400 py-2">
                    Your active workspace will appear here once saved.
                  </p>
                ) : (
                  <div className="divide-y divide-slate-100 dark:divide-[#1D2C35] border border-slate-200 dark:border-[#1D2C35] rounded-lg overflow-hidden">
                    {savedWorkspaces.map((ws) => {
                      const active = ws.id === activeWorkspaceId;
                      return (
                        <div
                          key={ws.id}
                          className={`flex items-center justify-between gap-2 px-3 py-2.5 text-xs ${
                            active
                              ? 'bg-teal-50/70 dark:bg-[#14B8A6]/12'
                              : 'bg-white dark:bg-[#0D1418]'
                          }`}
                        >
                          <button
                            type="button"
                            onClick={() => onSelectWorkspace(ws.id)}
                            className="flex-1 text-left min-w-0 cursor-pointer"
                          >
                            <div
                              className={`font-medium truncate ${
                                active ? 'text-teal-800 dark:text-[#2DD4BF]' : 'text-slate-900 dark:text-[#F0F6FA]'
                              }`}
                            >
                              {ws.title}
                            </div>
                            <div className="text-[11px] text-slate-500 dark:text-slate-400">{ws.updatedAtLabel}</div>
                          </button>
                          {savedWorkspaces.length > 1 && (
                            <button
                              type="button"
                              onClick={() => onDeleteWorkspace(ws.id)}
                              className="p-1.5 text-slate-400 hover:text-red-600 dark:hover:text-rose-400 rounded cursor-pointer"
                              aria-label={`Delete ${ws.title}`}
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </>
            )}
          </div>

          <div className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-6 space-y-4">
            <h2 className="text-base font-semibold text-slate-900 dark:text-[#F0F6FA]">
              Deliverables Included in Your Suite
            </h2>
            <div className="space-y-4 text-sm text-slate-600 dark:text-slate-300">
              <div className="pb-3 border-b border-slate-100 dark:border-[#1D2C35]">
                <div className="font-medium text-slate-900 dark:text-[#F0F6FA]">
                  1. Advanced Scripting &amp; Automation (Option 1 &amp; Option 2)
                </div>
                <p className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-300">
                  Includes CIDR subnet sweeps, TCP/UDP probing, TLS inspection, HTTP header &amp;
                  directory auditing, SearchSploit + Nmap XML correlation, standalone HTML + Markdown
                  + JSON reports, and Metasploit verification scripts.
                </p>
                <button
                  type="button"
                  onClick={() => onNavigate('automation')}
                  className="mt-2 inline-flex items-center gap-1.5 text-xs font-medium text-teal-700 hover:text-teal-800 dark:text-[#2DD4BF] dark:hover:text-[#5EEAD4] cursor-pointer"
                >
                  <span>Inspect &amp; download repository ZIP</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="pb-3 border-b border-slate-100 dark:border-[#1D2C35]">
                <div className="font-medium text-slate-900 dark:text-[#F0F6FA]">
                  2. Hands-On Exploitation Playbook
                </div>
                <p className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-300">
                  Log real terminal proof (<code className="text-slate-800 dark:text-[#2DD4BF]">id</code>,{' '}
                  <code className="text-slate-800 dark:text-[#2DD4BF]">uname -a</code>) across 8 target attack vectors.
                </p>
                <button
                  type="button"
                  onClick={() => onNavigate('playbook')}
                  className="mt-2 inline-flex items-center gap-1.5 text-xs font-medium text-teal-700 hover:text-teal-800 dark:text-[#2DD4BF] dark:hover:text-[#5EEAD4] cursor-pointer"
                >
                  <span>Open lab playbook</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>

              <div>
                <div className="font-medium text-slate-900 dark:text-[#F0F6FA]">
                  3. Structured VAPT PDF Submission
                </div>
                <p className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-300">
                  Export all 11 required sections directly to PDF or Markdown using your chosen
                  brand, lab, and assessor names.
                </p>
                <button
                  type="button"
                  onClick={() => onNavigate('report')}
                  className="mt-2 inline-flex items-center gap-1.5 text-xs font-medium text-teal-700 hover:text-teal-800 dark:text-[#2DD4BF] dark:hover:text-[#5EEAD4] cursor-pointer"
                >
                  <span>Prepare &amp; export VAPT PDF</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>

          <div className="bg-[#05080A] border border-[#1D2C35] text-slate-100 rounded-xl p-5 space-y-2">
            <div className="flex items-center gap-2 text-xs font-medium text-slate-300">
              <Terminal className="w-4 h-4 text-[#2DD4BF]" />
              <span>Quick Kali Connectivity Check</span>
            </div>
            <pre className="text-xs font-mono text-teal-300 overflow-x-auto leading-relaxed">
{`ip -4 addr show ${config.networkInterface || 'eth0'}
ping -c 3 ${config.targetIp || '192.168.56.101'}
sudo ./auto_vapt.sh -t ${config.targetIp || '192.168.56.101'} --profile standard`}
            </pre>
          </div>
        </div>
      </section>

      {/* Completion Checklist */}
      <section className="bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-[#1D2C35] pb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-[#F0F6FA]">Deliverable Checklist</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Track completion across lab setup, automation testing, GitHub publishing, and PDF export.
            </p>
          </div>
          <span className="text-xs font-mono tabular-nums text-slate-600 dark:text-[#2DD4BF]">
            {completedCount} of {milestones.length} completed
          </span>
        </div>

        <div className="divide-y divide-slate-100 dark:divide-[#1D2C35]">
          {milestones.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => onToggleMilestone(item.id)}
              className="w-full py-3.5 flex items-start gap-3.5 text-left hover:bg-slate-50/70 dark:hover:bg-[#131D23] px-2 rounded-lg cursor-pointer"
            >
              {item.completed ? (
                <CheckSquare className="w-5 h-5 text-teal-700 dark:text-[#2DD4BF] shrink-0 mt-0.5" />
              ) : (
                <Square className="w-5 h-5 text-slate-400 dark:text-slate-500 shrink-0 mt-0.5" />
              )}
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`text-sm font-medium ${
                      item.completed
                        ? 'line-through text-slate-400 dark:text-slate-500'
                        : 'text-slate-900 dark:text-[#F0F6FA]'
                    }`}
                  >
                    {item.title}
                  </span>
                  <span className="text-xs text-slate-400 dark:text-slate-600" aria-hidden="true">
                    ·
                  </span>
                  <span className="text-xs text-slate-500 dark:text-slate-400">{item.category}</span>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">{item.description}</p>
              </div>
            </button>
          ))}
        </div>
      </section>
    </div>
  );
};
