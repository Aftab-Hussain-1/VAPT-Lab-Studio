export type WorkspaceTab = 'overview' | 'analyzer' | 'automation' | 'playbook' | 'report';

export type AutomationOption = 'option1' | 'option2' | 'modules';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

export interface ParsedPortItem {
  port: number;
  protocol: string;
  service: string;
  banner: string;
  nseNotes: string[];
}

export interface CorrelatedFindingItem {
  port: number;
  protocol: string;
  serviceBanner: string;
  title: string;
  cve: string;
  cvss: number;
  severity: Severity;
  remediation: string;
}

export interface SavedScanRecord {
  id: string;
  targetIp: string;
  osGuess: string;
  openPortCount: number;
  findingCount: number;
  createdAtLabel: string;
  openPorts: ParsedPortItem[];
  findings: CorrelatedFindingItem[];
}

export interface LabConfig {
  brandTitle: string;
  academyOrProgramName: string;
  labName: string;
  toolName: string;
  internName: string;
  githubUsername: string;
  repoName: string;
  kaliIp: string;
  targetIp: string;
  networkInterface: string;
  networkMode: 'Host-Only (vboxnet0)' | 'NAT Network';
  assessmentDate: string;
  submissionDeadline: string;
  phase1ToolFocus: string;
}

export interface MilestoneItem {
  id: string;
  category: 'Lab Setup' | 'VAPT Execution' | 'Scripting & GitHub' | 'Final Submission';
  title: string;
  description: string;
  completed: boolean;
}

export interface PlaybookVector {
  id: string;
  port: string;
  protocol: 'tcp' | 'udp';
  service: string;
  cve: string;
  cvss: string;
  severity: Severity;
  title: string;
  summary: string;
  commands: {
    label: string;
    cmd: (cfg: LabConfig) => string;
  }[];
  expectedProof: string;
  impact: string;
  remediation: string;
  verified: boolean;
  includeInReport: boolean;
  labNotes: string;
  evidenceOutput: string;
}

export interface ReportTextSections {
  projectOverview: string;
  labSetupNotes: string;
  targetDetails: string;
  scopeAndMethodology: string;
  reconRawOutput: string;
  proofOfCompromiseSummary: string;
  riskAssessmentNotes: string;
  conclusionAndLessons: string;
}

export interface RepoFile {
  path: string;
  language: 'python' | 'bash' | 'markdown' | 'text';
  optionGroup: 'shared' | 'option1' | 'option2' | 'modules';
  description: string;
  content: string;
}

export interface SavedWorkspaceSummary {
  id: string;
  title: string;
  updatedAtLabel: string;
}
