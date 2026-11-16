import React, { useMemo, useState } from 'react';
import {
  Check,
  Copy,
  Download,
  FileCode2,
  FolderArchive,
  GitBranch,
  Play,
  Terminal,
} from 'lucide-react';
import { buildRepoFiles } from '../data/automationTemplates';
import { AutomationOption, LabConfig, RepoFile } from '../types/vapt';
import { buildZipBlob } from '../utils/zipBuilder';

interface AutomationToolViewProps {
  config: LabConfig;
}

export const AutomationToolView: React.FC<AutomationToolViewProps> = ({ config }) => {
  const [selectedOption, setSelectedOption] = useState<'all' | AutomationOption>('all');
  const [activeFilePath, setActiveFilePath] = useState<string>('auto_vapt.sh');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [rightPanelMode, setRightPanelMode] = useState<'code' | 'dryrun' | 'github'>('code');

  const files = useMemo(() => buildRepoFiles(config), [config]);

  const filteredFiles = useMemo(() => {
    if (selectedOption === 'all') return files;
    return files.filter((f) => f.optionGroup === selectedOption || f.optionGroup === 'shared');
  }, [files, selectedOption]);

  const activeFile: RepoFile =
    files.find((f) => f.path === activeFilePath) || filteredFiles[0] || files[0];

  const handleCopy = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      // Clipboard fallback ignored if blocked
    }
  };

  const handleDownloadSingleFile = (file: RepoFile) => {
    const blob = new Blob([file.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.path.split('/').pop() || 'script.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadRepoZip = () => {
    const repoRoot = (config.repoName || 'autorecon-vapt-suite').trim();
    const entries = [
      ...files.map((f) => ({
        path: `${repoRoot}/${f.path}`,
        content: f.content,
        executable: f.path.endsWith('.sh') || f.path.endsWith('.py'),
      })),
      {
        path: `${repoRoot}/src/__init__.py`,
        content: `"""${config.toolName || 'AutoReconVAPT'} Python package."""\n`,
        executable: false,
      },
      {
        path: `${repoRoot}/tests/__init__.py`,
        content: '',
        executable: false,
      },
    ];
    const zipBlob = buildZipBlob(entries);
    const url = URL.createObjectURL(zipBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${repoRoot}.zip`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const targetIp = config.targetIp || '192.168.56.101';
  const kaliIp = config.kaliIp || '192.168.56.102';
  const iface = config.networkInterface || 'eth0';
  const repoName = config.repoName || 'autorecon-vapt-suite';
  const toolName = config.toolName || 'AutoReconVAPT';
  const ghUser = config.githubUsername || 'your-github-username';

  const dryRunSample =
    selectedOption === 'option1'
      ? `$ python3 src/netrecon_v2.py -t ${targetIp} --udp --tls
[INFO] Starting ${toolName} NetRecon v2 against 1 host(s) (23 TCP ports)
[INFO] OPEN ${targetIp.padEnd(15)} 21/tcp    ftp            220 (vsFTPd 2.3.4)
[INFO] OPEN ${targetIp.padEnd(15)} 22/tcp    ssh            SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
[INFO] OPEN ${targetIp.padEnd(15)} 80/tcp    http           HTTP/1.1 200 OK | Server: Apache/2.2.8 (Ubuntu)
[INFO] OPEN ${targetIp.padEnd(15)} 445/tcp   microsoft-ds   No immediate banner
[INFO] OPEN ${targetIp.padEnd(15)} 1524/tcp  ingreslock     root@metasploitable:/#
[INFO] OPEN ${targetIp.padEnd(15)} 3632/tcp  distccd        No immediate banner
[INFO] OPEN ${targetIp.padEnd(15)} 6667/tcp  irc            :irc.Metasploitable.LAN NOTICE AUTH
[INFO] OPEN ${targetIp.padEnd(15)} 8180/tcp  http-tomcat    HTTP/1.1 200 OK | Server: Apache-Coyote/1.1
[INFO] OPEN ${targetIp.padEnd(15)} 111/udp   rpcbind        UDP response (28 bytes)
[INFO] Completed in 1.64s. Open services discovered: 9
[INFO] Exports: output/netrecon_${targetIp}.json | output/netrecon_${targetIp}.md | output/netrecon_${targetIp}.csv`
      : `$ sudo ./auto_vapt.sh -t ${targetIp} -l ${kaliIp} -i ${iface} --profile standard
====================================================================
 ${toolName} | Target: ${targetIp} | Profile: standard
 Program: ${config.academyOrProgramName || 'Security Lab Phase 2'}
====================================================================

[1/5] Verifying reachability to ${targetIp}...
  [+] ICMP echo reply received.

[2/5] Running Nmap (standard profile)...
  -> nmap -sS -sV -sC -O -Pn -T4 --open -e ${iface}

[3/5] Running secondary enumeration & exploit correlation...
  [+] Probing HTTP surface with Nikto (60s cap)...
  [+] Probing SMB shares/users with Enum4linux (45s cap)...

[4/5] Running Python Web Surface Audit...
[OK] Web audit saved to ./output/vapt_${targetIp}_standard/web_audit.json

[5/5] Generating JSON, Markdown, HTML, and Metasploit artifacts...
[OK] Parsed 23 open services and matched 13 vulnerabilities for ${targetIp}.

[COMPLETE] Assessment artifacts ready:
  - findings.json
  - vapt_report.md
  - vapt_report.html
  - msf_lab_verify.rc
  - web_audit.json

$ python3 -m unittest discover -s tests -v
----------------------------------------------------------------------
Ran 8 tests in 0.018s — OK`;

  const gitCommands = `# 1. Unzip downloaded bundle inside Kali Linux
unzip ${repoName}.zip
cd ${repoName}

# 2. Make Bash scripts executable and run unit tests
chmod +x auto_vapt.sh run_recon_upgrade.sh
python3 -m unittest discover -s tests -v

# 3. Run Option 1 (Upgraded Multi-threaded TCP/UDP + TLS/Header Recon)
python3 src/netrecon_v2.py -t ${targetIp} --udp --tls

# 4. Run Option 2 (Full Profiled VAPT Pipeline + HTML/MD/JSON + MSF .rc)
sudo ./auto_vapt.sh -t ${targetIp} -l ${kaliIp} -i ${iface} --profile standard

# 5. Run Web Audit & Authorized Lab Payload Helper
python3 src/web_audit.py -t ${targetIp} -p 80,8180
python3 src/exploit_helper.py --lhost ${kaliIp} --lport 4444

# 6. Push to your GitHub repository (${ghUser}/${repoName})
git init
git add .
git commit -m "feat: initialize ${toolName} advanced VAPT automation suite"
git branch -M main
git remote add origin https://github.com/${ghUser}/${repoName}.git
git push -u origin main`;

  return (
    <div className="space-y-6">
      {/* Section Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-[#1D2C35]">
        <div className="space-y-1">
          <p className="text-xs font-medium text-teal-700 dark:text-[#2DD4BF]">
            {toolName} · Python 3 &amp; Bash Suite · {ghUser}/{repoName}
          </p>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-[#F0F6FA]">
            Advanced Automation Toolkit (Option 1 + Option 2)
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-300 max-w-2xl">
            Multi-threaded TCP/UDP &amp; CIDR scanner, TLS/HTTP security auditor, profiled Nmap +
            SearchSploit pipeline, HTML/Markdown/JSON reporting, Metasploit{' '}
            <code className="text-slate-800 dark:text-[#2DD4BF]">.rc</code> builder, and 8 unit tests.
          </p>
        </div>

        <button
          type="button"
          onClick={handleDownloadRepoZip}
          className="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-semibold text-white bg-teal-700 hover:bg-teal-600 hover:shadow-[0_6px_18px_-4px_rgba(13,148,136,0.42)] dark:bg-[#14B8A6] dark:text-[#042F2E] dark:hover:bg-[#2DD4BF] dark:hover:shadow-[0_6px_22px_-4px_rgba(45,212,191,0.42)] rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
        >
          <FolderArchive className="w-4 h-4" />
          <span>Download {repoName}.zip</span>
        </button>
      </div>

      {/* Filter & View Mode Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="inline-flex flex-wrap items-center gap-1 p-1 bg-slate-200/70 dark:bg-[#131D23] dark:border dark:border-[#1D2C35] rounded-lg self-start">
          <button
            type="button"
            onClick={() => setSelectedOption('all')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
              selectedOption === 'all'
                ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
            }`}
          >
            Full Suite
          </button>
          <button
            type="button"
            onClick={() => {
              setSelectedOption('option1');
              setActiveFilePath('src/netrecon_v2.py');
            }}
            className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
              selectedOption === 'option1'
                ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
            }`}
          >
            Option 1: NetRecon v2
          </button>
          <button
            type="button"
            onClick={() => {
              setSelectedOption('option2');
              setActiveFilePath('auto_vapt.sh');
            }}
            className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
              selectedOption === 'option2'
                ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
            }`}
          >
            Option 2: AutoVAPT
          </button>
          <button
            type="button"
            onClick={() => {
              setSelectedOption('modules');
              setActiveFilePath('src/web_audit.py');
            }}
            className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
              selectedOption === 'modules'
                ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
            }`}
          >
            Web &amp; Payload Modules
          </button>
        </div>

        <div className="inline-flex items-center gap-1 p-1 bg-slate-200/70 dark:bg-[#131D23] dark:border dark:border-[#1D2C35] rounded-lg self-start">
          <button
            type="button"
            onClick={() => setRightPanelMode('code')}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
              rightPanelMode === 'code'
                ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
            }`}
          >
            <FileCode2 className="w-3.5 h-3.5" />
            <span>Source Code</span>
          </button>
          <button
            type="button"
            onClick={() => setRightPanelMode('dryrun')}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
              rightPanelMode === 'dryrun'
                ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
            }`}
          >
            <Play className="w-3.5 h-3.5" />
            <span>Expected CLI Output</span>
          </button>
          <button
            type="button"
            onClick={() => setRightPanelMode('github')}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 cursor-pointer ${
              rightPanelMode === 'github'
                ? 'bg-white text-slate-900 shadow-sm dark:bg-[#0D1418] dark:text-[#2DD4BF] dark:border dark:border-[#2DD4BF]/35'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
            }`}
          >
            <GitBranch className="w-3.5 h-3.5" />
            <span>Kali &amp; GitHub Setup</span>
          </button>
        </div>
      </div>

      {/* Main Two-Column Code Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        <aside className="lg:col-span-4 bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-200 dark:border-[#1D2C35] flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-700 dark:text-slate-200">Repository Files</span>
            <span className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
              {filteredFiles.length} files
            </span>
          </div>
          <div className="divide-y divide-slate-100 dark:divide-[#1D2C35]">
            {filteredFiles.map((file) => {
              const isActive = activeFile.path === file.path && rightPanelMode === 'code';
              const tagLabel =
                file.optionGroup === 'option1'
                  ? 'Option 1'
                  : file.optionGroup === 'option2'
                    ? 'Option 2'
                    : file.optionGroup === 'modules'
                      ? 'Module'
                      : 'Shared';
              return (
                <button
                  key={file.path}
                  type="button"
                  onClick={() => {
                    setActiveFilePath(file.path);
                    setRightPanelMode('code');
                  }}
                  className={`w-full text-left px-4 py-3 cursor-pointer ${
                    isActive
                      ? 'bg-teal-50/70 dark:bg-[#14B8A6]/12'
                      : 'hover:bg-slate-50 dark:hover:bg-[#131D23]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span
                      className={`text-xs font-mono font-medium truncate ${
                        isActive ? 'text-teal-800 dark:text-[#2DD4BF]' : 'text-slate-900 dark:text-[#F0F6FA]'
                      }`}
                    >
                      {file.path}
                    </span>
                    <span className="text-[11px] text-slate-500 dark:text-slate-400 shrink-0">{tagLabel}</span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                    {file.description}
                  </p>
                </button>
              );
            })}
          </div>
        </aside>

        {/* Viewer Panel */}
        <div className="lg:col-span-8 bg-[#05080A] border border-[#1D2C35] rounded-xl overflow-hidden text-slate-100">
          {rightPanelMode === 'code' && (
            <>
              <div className="px-4 py-3 bg-[#0D1418] border-b border-[#1D2C35] flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-xs font-mono font-medium text-[#F0F6FA] truncate">
                    {activeFile.path}
                  </div>
                  <div className="text-xs text-slate-400 truncate mt-0.5">
                    {activeFile.description}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => handleCopy(activeFile.content, activeFile.path)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#131D23] border border-[#273B47] hover:bg-[#19262E] hover:border-[#2DD4BF]/50 hover:text-white rounded-md whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    {copiedKey === activeFile.path ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy File</span>
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDownloadSingleFile(activeFile)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-[#042F2E] bg-[#14B8A6] hover:bg-[#2DD4BF] hover:shadow-[0_4px_16px_-3px_rgba(45,212,191,0.42)] rounded-md whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download</span>
                  </button>
                </div>
              </div>
              <pre className="p-4 text-xs font-mono leading-relaxed text-slate-200 overflow-x-auto max-h-[640px] overflow-y-auto">
                <code>{activeFile.content}</code>
              </pre>
            </>
          )}

          {rightPanelMode === 'dryrun' && (
            <>
              <div className="px-4 py-3 bg-[#0D1418] border-b border-[#1D2C35] flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-[#2DD4BF]" />
                  <span className="text-xs font-medium text-[#F0F6FA]">
                    Expected Kali Linux Terminal Session ({targetIp})
                  </span>
                </div>
                <span className="text-xs text-slate-400">Sample reference run</span>
              </div>
              <pre className="p-4 text-xs font-mono leading-relaxed text-emerald-300/95 overflow-x-auto max-h-[640px] overflow-y-auto">
                <code>{dryRunSample}</code>
              </pre>
            </>
          )}

          {rightPanelMode === 'github' && (
            <>
              <div className="px-4 py-3 bg-[#0D1418] border-b border-[#1D2C35] flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-[#2DD4BF]" />
                  <span className="text-xs font-medium text-[#F0F6FA]">
                    Deploy in Kali Linux &amp; Push to {ghUser}/{repoName}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => handleCopy(gitCommands, 'git-setup')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#131D23] border border-[#273B47] hover:bg-[#19262E] hover:border-[#2DD4BF]/50 hover:text-white rounded-md whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {copiedKey === 'git-setup' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Commands</span>
                    </>
                  )}
                </button>
              </div>
              <div className="p-4 space-y-4">
                <p className="text-xs text-slate-300 leading-relaxed">
                  Click <strong>Download {repoName}.zip</strong> above, extract it inside Kali Linux,
                  verify all 8 unit tests pass, and push to GitHub:
                </p>
                <pre className="p-4 bg-[#0D1418] rounded-lg border border-[#1D2C35] text-xs font-mono leading-relaxed text-teal-300 overflow-x-auto">
                  <code>{gitCommands}</code>
                </pre>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
