/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import { onAuthStateChanged, type User } from 'firebase/auth';
import {
  Activity,
  FileCode2,
  FileText,
  LayoutDashboard,
  LogIn,
  LogOut,
  Menu,
  Moon,
  Printer,
  RotateCcw,
  ShieldCheck,
  Sun,
  TerminalSquare,
  X,
} from 'lucide-react';
import { AutomationToolView } from './components/AutomationToolView';
import { LabPlaybookView } from './components/LabPlaybookView';
import { LiveAnalyzerView } from './components/LiveAnalyzerView';
import { OverviewView } from './components/OverviewView';
import { VaptReportView } from './components/VaptReportView';
import { INITIAL_PLAYBOOK_VECTORS } from './data/metasploitablePlaybook';
import { OfflineIndicator, PWAInstallButton } from './hooks/usePWAInstall';
import {
  auth,
  deleteUserScan,
  deleteUserWorkspace,
  listUserScans,
  listUserWorkspaces,
  loadUserWorkspace,
  saveUserScan,
  saveUserWorkspace,
  signInWithGoogle,
  signOutAccount,
} from './lib/firebase';
import {
  CorrelatedFindingItem,
  LabConfig,
  MilestoneItem,
  ParsedPortItem,
  PlaybookVector,
  ReportTextSections,
  SavedScanRecord,
  SavedWorkspaceSummary,
  WorkspaceTab,
} from './types/vapt';

const STORAGE_KEY = 'vapt_lab_studio_workspace_v2';

const DEFAULT_CONFIG: LabConfig = {
  brandTitle: 'VAPT Lab Studio',
  academyOrProgramName: 'Cybersecurity Internship — Phase 2',
  labName: 'Metasploitable 2 Virtual Lab',
  toolName: 'AutoReconVAPT',
  internName: 'Alex Rivera',
  githubUsername: 'alexrivera-sec',
  repoName: 'autorecon-vapt-suite',
  kaliIp: '192.168.56.102',
  targetIp: '192.168.56.101',
  networkInterface: 'eth0',
  networkMode: 'Host-Only (vboxnet0)',
  assessmentDate: '2026-11-16',
  submissionDeadline: '18 Nov 2026',
  phase1ToolFocus: 'Python Port Scanner',
};

function normalizeLegacyAssessor(cfg: LabConfig): LabConfig {
  const internLower = (cfg.internName || '').trim().toLowerCase();
  const githubLower = (cfg.githubUsername || '').trim().toLowerCase();
  return {
    ...cfg,
    internName:
      internLower === 'syed badshah' || internLower === 'syedbadshah'
        ? DEFAULT_CONFIG.internName
        : cfg.internName,
    githubUsername:
      githubLower === 'syedbadshah' || githubLower === 'syed-badshah'
        ? DEFAULT_CONFIG.githubUsername
        : cfg.githubUsername,
  };
}

function rehydrateVectors(loadedVectors: PlaybookVector[]): PlaybookVector[] {
  const templateById = new Map(INITIAL_PLAYBOOK_VECTORS.map((v) => [v.id, v]));
  return loadedVectors.map((vec) => {
    const template = templateById.get(vec.id);
    const commands = template
      ? template.commands
      : (vec.commands || []).map((step) => ({
          label: step.label,
          cmd: typeof step.cmd === 'function' ? step.cmd : () => '',
        }));
    return {
      ...(template || {}),
      ...vec,
      commands,
    };
  });
}

const DEFAULT_MILESTONES: MilestoneItem[] = [
  {
    id: 'm1',
    category: 'Lab Setup',
    title: 'Kali Linux & target VM isolated in VirtualBox',
    description: 'Both VMs attached to Host-Only (vboxnet0) or NAT Network with verified ping/ARP connectivity.',
    completed: true,
  },
  {
    id: 'm2',
    category: 'Scripting & GitHub',
    title: 'Test Option 1 (NetRecon v2) & Option 2 (AutoVAPT) in Kali',
    description: 'Download the GitHub ZIP bundle, run the 8 unit tests, and execute scans against your lab target.',
    completed: false,
  },
  {
    id: 'm3',
    category: 'VAPT Execution',
    title: 'Complete reconnaissance, enumeration & exploitation in lab',
    description: 'Verify open services, exploit key target vulnerabilities, and record terminal evidence.',
    completed: false,
  },
  {
    id: 'm4',
    category: 'Scripting & GitHub',
    title: 'Push repository with README & MIT License to public GitHub',
    description: 'Verify tests pass, exclude raw scan outputs via .gitignore, and publish your repository link.',
    completed: false,
  },
  {
    id: 'm5',
    category: 'Final Submission',
    title: 'Export 11-section VAPT PDF Report before submission deadline',
    description: 'Confirm real lab screenshots/outputs are embedded and print cleanly to PDF.',
    completed: false,
  },
];

function createDefaultSections(cfg: LabConfig): ReportTextSections {
  return {
    projectOverview: `This Vulnerability Assessment and Penetration Testing (VAPT) engagement was conducted for ${cfg.academyOrProgramName}. The objective was to deploy an intentionally vulnerable virtual machine (${cfg.labName}) inside an isolated VirtualBox lab, perform structured reconnaissance, service enumeration, and controlled exploitation from Kali Linux, and document actionable remediation guidance alongside custom Python and Bash automation (${cfg.toolName}).`,
    labSetupNotes: `All testing was performed strictly inside an offline/isolated Oracle VirtualBox ${cfg.networkMode} segment with zero exposure to public networks. Kali Linux (${cfg.kaliIp}) acted as the attacking workstation on interface ${cfg.networkInterface}, targeting ${cfg.labName} (${cfg.targetIp}).`,
    targetDetails: `Target System: ${cfg.labName} (Ubuntu 8.04 / Linux kernel 2.6.24-16-server).\nPrimary Attack Surface: Legacy network daemons (vsftpd 2.3.4, Samba 3.0.20, UnrealIRCd 3.2.8.1, r-services, ingreslock bindshell, distccd), database engines (MySQL 5.0, PostgreSQL 8.3), and vulnerable web stacks (Apache 2.2.8 / DVWA / Mutillidae / Tomcat 5.5).`,
    scopeAndMethodology: `Testing followed the Penetration Testing Execution Standard (PTES): (1) Pre-engagement lab isolation verification, (2) Active host discovery & Nmap service/NSE enumeration automated via ${cfg.toolName}, (3) Vulnerability correlation & manual verification, (4) Controlled exploitation to confirm impact, and (5) CVSS risk rating & remediation reporting.`,
    reconRawOutput: `# Paste your real Nmap / ${cfg.toolName} output from Kali Linux here:
$ nmap -sS -sV -sC -O -Pn ${cfg.targetIp}
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login       OpenBSD or Solaris rlogind
1524/tcp open  ingreslock  Metasploitable root shell
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
6667/tcp open  irc         UnrealIRCd
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1`,
    proofOfCompromiseSummary: `Multiple independent attack paths yielded full administrative (uid=0(root)) access on ${cfg.targetIp} without prior credentials, including the vsftpd 2.3.4 backdoor, Samba usermap_script RCE, unauthenticated ingreslock bindshell on port 1524, and passwordless rlogin root trust.`,
    riskAssessmentNotes: `The overall risk posture of the assessed host is Critical. High-impact vulnerabilities require zero authentication, have publicly available Metasploit modules, and expose both operating system control and underlying databases. In a production environment, an equivalent configuration would result in immediate full-host takeover and lateral movement.`,
    conclusionAndLessons: `This assessment reinforced practical virtual lab networking, Nmap XML automation with Python and Bash, vulnerability validation without blind scanner reliance, and clear technical reporting. Using ${cfg.toolName} reduced manual enumeration overhead and standardized evidence collection.`,
  };
}

interface StoredState {
  config: LabConfig;
  milestones: MilestoneItem[];
  vectors: PlaybookVector[];
  sections: ReportTextSections;
}

function loadInitialState(): StoredState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<StoredState>;
      if (parsed.config && parsed.vectors && parsed.milestones && parsed.sections) {
        return {
          config: normalizeLegacyAssessor({ ...DEFAULT_CONFIG, ...parsed.config }),
          milestones: parsed.milestones,
          vectors: rehydrateVectors(parsed.vectors),
          sections: parsed.sections,
        };
      }
    }
  } catch {
    // Fallback to defaults
  }
  return {
    config: DEFAULT_CONFIG,
    milestones: DEFAULT_MILESTONES,
    vectors: INITIAL_PLAYBOOK_VECTORS,
    sections: createDefaultSections(DEFAULT_CONFIG),
  };
}

export default function App() {
  const [initial] = useState<StoredState>(() => loadInitialState());
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    try {
      return localStorage.getItem('vapt_studio_theme') === 'light' ? 'light' : 'dark';
    } catch {
      return 'dark';
    }
  });

  const [config, setConfig] = useState<LabConfig>(initial.config);
  const [milestones, setMilestones] = useState<MilestoneItem[]>(initial.milestones);
  const [vectors, setVectors] = useState<PlaybookVector[]>(initial.vectors);
  const [sections, setSections] = useState<ReportTextSections>(initial.sections);

  const [user, setUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [activeWorkspaceId, setActiveWorkspaceId] = useState<string>('default-lab');
  const [savedWorkspaces, setSavedWorkspaces] = useState<SavedWorkspaceSummary[]>([]);
  const [savedScans, setSavedScans] = useState<SavedScanRecord[]>([]);
  const [authNotice, setAuthNotice] = useState<string | null>(null);

  const skipNextCloudSave = useRef(false);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    try {
      localStorage.setItem('vapt_studio_theme', theme);
    } catch {
      // Ignore storage errors
    }
    const metaTheme = document.querySelector('meta[name="theme-color"]');
    if (metaTheme) {
      metaTheme.setAttribute('content', theme === 'dark' ? '#070B0E' : '#0f766e');
    }
  }, [theme]);

  useEffect(() => {
    document.title = `${config.brandTitle || 'VAPT Lab Studio'} — VAPT & Automation Workbench`;
  }, [config.brandTitle]);

  useEffect(() => {
    try {
      const payload: StoredState = { config, milestones, vectors, sections };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    } catch {
      // Ignore storage quota errors
    }
  }, [config, milestones, vectors, sections]);

  useEffect(() => {
    const unsub = onAuthStateChanged(auth, async (currentUser) => {
      setUser(currentUser);
      setAuthReady(true);
      if (!currentUser) {
        setSavedWorkspaces([]);
        setSavedScans([]);
        return;
      }

      try {
        const [list, scans] = await Promise.all([
          listUserWorkspaces(currentUser.uid),
          listUserScans(currentUser.uid),
        ]);
        setSavedScans(scans);

        if (list.length > 0) {
          setSavedWorkspaces(list);
          const firstId = list[0].id;
          setActiveWorkspaceId(firstId);
          const loaded = await loadUserWorkspace(currentUser.uid, firstId);
          if (loaded) {
            skipNextCloudSave.current = true;
            setConfig(normalizeLegacyAssessor({ ...DEFAULT_CONFIG, ...loaded.config }));
            setMilestones(loaded.milestones);
            setVectors(rehydrateVectors(loaded.vectors));
            setSections(loaded.sections);
          }
        } else {
          await saveUserWorkspace(currentUser.uid, 'default-lab', {
            config,
            milestones,
            vectors,
            sections,
          });
          const refreshed = await listUserWorkspaces(currentUser.uid);
          setSavedWorkspaces(refreshed);
        }
      } catch {
        setAuthNotice('Unable to sync saved workspaces right now.');
      }
    });
    return () => unsub();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!authReady || !user) return;
    if (skipNextCloudSave.current) {
      skipNextCloudSave.current = false;
      return;
    }

    const timer = setTimeout(async () => {
      try {
        await saveUserWorkspace(user.uid, activeWorkspaceId, {
          config,
          milestones,
          vectors,
          sections,
        });
        const list = await listUserWorkspaces(user.uid);
        setSavedWorkspaces(list);
      } catch {
        // Silently avoid crashing UI on transient save errors
      }
    }, 900);

    return () => clearTimeout(timer);
  }, [authReady, user, activeWorkspaceId, config, milestones, vectors, sections]);

  const handleSignIn = async () => {
    setAuthNotice(null);
    try {
      await signInWithGoogle();
    } catch {
      setAuthNotice('Sign-in popup was cancelled or blocked.');
    }
  };

  const handleSignOut = async () => {
    await signOutAccount();
  };

  const handleSelectWorkspace = async (workspaceId: string) => {
    if (!user) return;
    try {
      const loaded = await loadUserWorkspace(user.uid, workspaceId);
      if (loaded) {
        skipNextCloudSave.current = true;
        setActiveWorkspaceId(workspaceId);
        setConfig(normalizeLegacyAssessor({ ...DEFAULT_CONFIG, ...loaded.config }));
        setMilestones(loaded.milestones);
        setVectors(rehydrateVectors(loaded.vectors));
        setSections(loaded.sections);
      }
    } catch {
      setAuthNotice('Could not load selected workspace.');
    }
  };

  const handleCreateWorkspace = async (name: string) => {
    if (!user) return;
    const newId =
      name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 60) || `lab-${Date.now()}`;
    const nextConfig: LabConfig = { ...config, labName: name };
    const nextSections = createDefaultSections(nextConfig);
    try {
      skipNextCloudSave.current = true;
      setActiveWorkspaceId(newId);
      setConfig(nextConfig);
      setSections(nextSections);
      await saveUserWorkspace(user.uid, newId, {
        config: nextConfig,
        milestones,
        vectors,
        sections: nextSections,
      });
      const list = await listUserWorkspaces(user.uid);
      setSavedWorkspaces(list);
    } catch {
      setAuthNotice('Could not create new lab profile.');
    }
  };

  const handleDeleteWorkspace = async (workspaceId: string) => {
    if (!user) return;
    try {
      await deleteUserWorkspace(user.uid, workspaceId);
      const list = await listUserWorkspaces(user.uid);
      setSavedWorkspaces(list);
      if (workspaceId === activeWorkspaceId && list.length > 0) {
        await handleSelectWorkspace(list[0].id);
      }
    } catch {
      setAuthNotice('Could not remove workspace.');
    }
  };

  const handleSaveScan = async (scan: {
    targetIp: string;
    osGuess: string;
    openPorts: ParsedPortItem[];
    findings: CorrelatedFindingItem[];
  }) => {
    if (!user) return;
    await saveUserScan(user.uid, scan);
    const updated = await listUserScans(user.uid);
    setSavedScans(updated);
  };

  const handleDeleteScan = async (scanId: string) => {
    if (!user) return;
    await deleteUserScan(user.uid, scanId);
    const updated = await listUserScans(user.uid);
    setSavedScans(updated);
  };

  const handleSendScanToReport = (rawSummary: string, scannedTargetIp: string) => {
    setSections((prev) => ({ ...prev, reconRawOutput: rawSummary }));
    if (scannedTargetIp && scannedTargetIp !== 'unknown') {
      setConfig((prev) => ({ ...prev, targetIp: scannedTargetIp }));
    }
    setActiveTab('report');
  };

  const handleUpdateConfig = (patch: Partial<LabConfig>) => {
    setConfig((prev) => ({ ...prev, ...patch }));
  };

  const handleToggleMilestone = (id: string) => {
    setMilestones((prev) =>
      prev.map((m) => (m.id === id ? { ...m, completed: !m.completed } : m))
    );
  };

  const handleUpdateVector = (id: string, patch: Partial<PlaybookVector>) => {
    setVectors((prev) => prev.map((v) => (v.id === id ? { ...v, ...patch } : v)));
  };

  const handleUpdateSections = (patch: Partial<ReportTextSections>) => {
    setSections((prev) => ({ ...prev, ...patch }));
  };

  const handleResetWorkspace = () => {
    setConfig(DEFAULT_CONFIG);
    setMilestones(DEFAULT_MILESTONES);
    setVectors(INITIAL_PLAYBOOK_VECTORS);
    setSections(createDefaultSections(DEFAULT_CONFIG));
    localStorage.removeItem(STORAGE_KEY);
  };

  const navItems: { id: WorkspaceTab; label: string; icon: React.ReactNode }[] = [
    {
      id: 'overview',
      label: 'Workspace Overview',
      icon: <LayoutDashboard className="w-4 h-4 shrink-0" />,
    },
    {
      id: 'analyzer',
      label: 'Live Analyzer',
      icon: <Activity className="w-4 h-4 shrink-0" />,
    },
    {
      id: 'automation',
      label: 'CLI & Repo Builder',
      icon: <FileCode2 className="w-4 h-4 shrink-0" />,
    },
    {
      id: 'playbook',
      label: 'VAPT Lab Playbook',
      icon: <TerminalSquare className="w-4 h-4 shrink-0" />,
    },
    {
      id: 'report',
      label: 'VAPT PDF Report',
      icon: <FileText className="w-4 h-4 shrink-0" />,
    },
  ];

  const activeLabel = navItems.find((n) => n.id === activeTab)?.label || 'Overview';
  const displayBrand = config.brandTitle || 'VAPT Lab Studio';

  return (
    <div className="min-h-screen flex bg-[#F4F6F9] dark:bg-[#070B0E] text-slate-900 dark:text-[#E6EDF3] print:bg-white print:text-slate-900 transition-colors duration-200">
      {/* Desktop Sidebar */}
      <aside className="hidden md:flex md:w-64 md:flex-col md:fixed md:inset-y-0 bg-white dark:bg-[#0D1418] border-r border-[#DDE3EC] dark:border-[#1D2C35] print:hidden transition-colors duration-200">
        <div className="h-16 px-5 flex items-center gap-2.5 border-b border-[#DDE3EC] dark:border-[#1D2C35]">
          <ShieldCheck className="w-5 h-5 text-teal-700 dark:text-[#2DD4BF] shrink-0" />
          <span className="text-base font-bold tracking-tight text-slate-900 dark:text-[#F0F6FA] whitespace-nowrap truncate">
            {displayBrand}
          </span>
        </div>

        <nav className="flex-1 px-3 py-5 space-y-1">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-lg border whitespace-nowrap cursor-pointer ${
                  isActive
                    ? 'bg-teal-50 border-teal-200/80 text-teal-800 dark:bg-[#13282B] dark:border-[#2DD4BF]/35 dark:text-[#2DD4BF] dark:shadow-[0_0_20px_-6px_rgba(45,212,191,0.35)]'
                    : 'border-transparent text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-[#131D23] hover:text-slate-900 dark:hover:text-[#F0F6FA] dark:hover:border-[#273B47]'
                }`}
              >
                {item.icon}
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-[#DDE3EC] dark:border-[#1D2C35] space-y-2.5">
          <div className="text-xs text-slate-500 dark:text-slate-400 space-y-1">
            <div className="font-medium text-slate-800 dark:text-[#E6EDF3] truncate">
              {config.internName || 'Alex Rivera'}
            </div>
            <div className="font-mono tabular-nums truncate text-slate-500 dark:text-slate-400">
              {config.githubUsername}/{config.repoName}
            </div>
          </div>

          {/* Theme Mode Segmented Control */}
          <div className="grid grid-cols-2 gap-1 p-1 rounded-lg bg-slate-100 dark:bg-[#131D23] border border-[#DDE3EC] dark:border-[#1D2C35]">
            <button
              type="button"
              onClick={() => setTheme('light')}
              className={`inline-flex items-center justify-center gap-1.5 py-1.5 text-xs font-medium rounded-md whitespace-nowrap cursor-pointer ${
                theme === 'light'
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              <Sun className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
              <span>Light</span>
            </button>
            <button
              type="button"
              onClick={() => setTheme('dark')}
              className={`inline-flex items-center justify-center gap-1.5 py-1.5 text-xs font-medium rounded-md whitespace-nowrap cursor-pointer ${
                theme === 'dark'
                  ? 'bg-[#0D1418] text-[#2DD4BF] border border-[#2DD4BF]/30 shadow-sm'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              <Moon className="w-3.5 h-3.5" />
              <span>Dark</span>
            </button>
          </div>

          {authNotice && (
            <p className="text-[11px] text-amber-700 dark:text-amber-400 leading-snug">{authNotice}</p>
          )}

          <PWAInstallButton />

          {user ? (
            <button
              type="button"
              onClick={handleSignOut}
              className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:text-slate-900 dark:hover:text-white bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] hover:bg-slate-50 dark:hover:bg-[#19262E] hover:border-teal-600/40 dark:hover:border-[#2DD4BF]/50 rounded-lg whitespace-nowrap cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign Out</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={handleSignIn}
              className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white dark:text-[#042F2E] bg-teal-700 hover:bg-teal-600 dark:bg-[#14B8A6] dark:hover:bg-[#2DD4BF] hover:shadow-[0_6px_18px_-4px_rgba(13,148,136,0.45)] dark:hover:shadow-[0_6px_22px_-4px_rgba(45,212,191,0.4)] rounded-lg whitespace-nowrap cursor-pointer"
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>Sign In with Google</span>
            </button>
          )}

          <button
            type="button"
            onClick={handleResetWorkspace}
            className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white bg-slate-100 dark:bg-[#131D23] hover:bg-slate-200 dark:hover:bg-[#1B2830] border border-transparent dark:border-[#1D2C35] dark:hover:border-[#273B47] rounded-lg whitespace-nowrap cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Defaults</span>
          </button>
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 md:hidden print:hidden">
          <div
            className="fixed inset-0 bg-slate-950/60 backdrop-blur-[1px]"
            onClick={() => setMobileMenuOpen(false)}
          />
          <div className="fixed inset-y-0 left-0 w-64 bg-white dark:bg-[#0D1418] border-r border-[#DDE3EC] dark:border-[#1D2C35] flex flex-col">
            <div className="h-14 px-4 flex items-center justify-between border-b border-[#DDE3EC] dark:border-[#1D2C35]">
              <span className="text-base font-bold text-slate-900 dark:text-[#F0F6FA] truncate">
                {displayBrand}
              </span>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                className="p-2 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white rounded-lg"
                aria-label="Close navigation"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <nav className="flex-1 px-3 py-4 space-y-1">
              {navItems.map((item) => {
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActiveTab(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-lg whitespace-nowrap ${
                      isActive
                        ? 'bg-teal-50 text-teal-800 dark:bg-[#13282B] dark:text-[#2DD4BF]'
                        : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-[#131D23] hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    {item.icon}
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
            <div className="p-4 border-t border-[#DDE3EC] dark:border-[#1D2C35] space-y-2.5">
              <div className="grid grid-cols-2 gap-1 p-1 rounded-lg bg-slate-100 dark:bg-[#131D23] border border-[#DDE3EC] dark:border-[#1D2C35]">
                <button
                  type="button"
                  onClick={() => setTheme('light')}
                  className={`inline-flex items-center justify-center gap-1.5 py-1.5 text-xs font-medium rounded-md ${
                    theme === 'light'
                      ? 'bg-white text-slate-900 shadow-sm'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  <Sun className="w-3.5 h-3.5 text-amber-600" />
                  <span>Light</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTheme('dark')}
                  className={`inline-flex items-center justify-center gap-1.5 py-1.5 text-xs font-medium rounded-md ${
                    theme === 'dark'
                      ? 'bg-[#0D1418] text-[#2DD4BF]'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  <Moon className="w-3.5 h-3.5" />
                  <span>Dark</span>
                </button>
              </div>
              <PWAInstallButton />
              {user ? (
                <button
                  type="button"
                  onClick={handleSignOut}
                  className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] rounded-lg"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Sign Out</span>
                </button>
              ) : (
                <button
                  type="button"
                  onClick={handleSignIn}
                  className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium text-white dark:text-[#042F2E] bg-teal-700 dark:bg-[#14B8A6] rounded-lg"
                >
                  <LogIn className="w-3.5 h-3.5" />
                  <span>Sign In with Google</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Main Content Shell */}
      <div className="flex-1 md:pl-64 print:pl-0 flex flex-col min-w-0">
        <header className="h-16 bg-white/95 dark:bg-[#0D1418]/95 backdrop-blur-sm border-b border-[#DDE3EC] dark:border-[#1D2C35] px-4 sm:px-8 flex items-center justify-between gap-8 sticky top-0 z-30 print:hidden transition-colors duration-200">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="md:hidden p-2 -ml-2 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white rounded-lg"
              aria-label="Open navigation"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2 text-sm truncate">
              <span className="text-slate-500 dark:text-slate-400 hidden sm:inline truncate max-w-[200px]">
                {displayBrand}
              </span>
              <span className="text-slate-400 dark:text-slate-600 hidden sm:inline" aria-hidden="true">
                /
              </span>
              <span className="font-semibold text-slate-900 dark:text-[#F0F6FA] truncate">
                {activeLabel}
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={() => {
              setActiveTab('report');
              setTimeout(() => window.print(), 120);
            }}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white dark:text-[#042F2E] bg-slate-900 hover:bg-teal-700 dark:bg-[#14B8A6] dark:hover:bg-[#2DD4BF] hover:shadow-[0_6px_18px_-4px_rgba(13,148,136,0.4)] dark:hover:shadow-[0_6px_22px_-4px_rgba(45,212,191,0.45)] rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print VAPT PDF</span>
          </button>
        </header>

        <main className="flex-1 px-4 sm:px-8 py-8 max-w-6xl w-full mx-auto print:p-0 print:max-w-none">
          {activeTab === 'overview' && (
            <OverviewView
              config={config}
              onUpdateConfig={handleUpdateConfig}
              milestones={milestones}
              onToggleMilestone={handleToggleMilestone}
              vectors={vectors}
              onNavigate={setActiveTab}
              isSignedIn={Boolean(user)}
              savedWorkspaces={savedWorkspaces}
              activeWorkspaceId={activeWorkspaceId}
              onSelectWorkspace={handleSelectWorkspace}
              onCreateWorkspace={handleCreateWorkspace}
              onDeleteWorkspace={handleDeleteWorkspace}
            />
          )}

          {activeTab === 'analyzer' && (
            <LiveAnalyzerView
              config={config}
              isSignedIn={Boolean(user)}
              savedScans={savedScans}
              onSaveScan={handleSaveScan}
              onDeleteScan={handleDeleteScan}
              onSendScanToReport={handleSendScanToReport}
            />
          )}

          {activeTab === 'automation' && <AutomationToolView config={config} />}

          {activeTab === 'playbook' && (
            <LabPlaybookView
              config={config}
              vectors={vectors}
              onUpdateVector={handleUpdateVector}
              onGoToReport={() => setActiveTab('report')}
            />
          )}

          {activeTab === 'report' && (
            <VaptReportView
              config={config}
              onUpdateConfig={handleUpdateConfig}
              vectors={vectors}
              sections={sections}
              onUpdateSections={handleUpdateSections}
            />
          )}
        </main>
      </div>

      <OfflineIndicator />
    </div>
  );
}
