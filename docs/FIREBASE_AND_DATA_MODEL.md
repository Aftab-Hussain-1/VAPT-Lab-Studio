# Data Model & Firebase Cloud Sync

VAPT Lab Studio supports both **offline browser persistence** (`localStorage`) and **multi-device cloud persistence** via Firebase Authentication and Cloud Firestore.

---

## 1. Core TypeScript Interfaces (`src/types/vapt.ts`)

### `LabConfig`
Stores user-editable branding, automation CLI settings, GitHub identity, and VirtualBox network topology:
- `brandTitle`, `academyOrProgramName`, `labName`, `toolName`
- `internName`, `githubUsername`, `repoName`
- `kaliIp`, `targetIp`, `networkInterface`, `networkMode` (`'Host-Only (vboxnet0)' | 'NAT Network'`)
- `assessmentDate`, `submissionDeadline`, `phase1ToolFocus`

### `PlaybookVector`
Represents each attack vector in `LabPlaybookView` and Sections 6, 7, and 10 of `VaptReportView`:
- Metadata: `id`, `port`, `protocol`, `service`, `cve`, `cvss`, `severity`
- Technical details: `title`, `summary`, `expectedProof`, `impact`, `remediation`
- Command templates: `commands: { label: string; cmd: (cfg: LabConfig) => string }[]`
- User state: `verified`, `includeInReport`, `labNotes`, `evidenceOutput`

### `ReportTextSections`
Holds narrative sections editable inside **VAPT Report → Edit Sections**:
- `projectOverview`
- `labSetupNotes`
- `targetDetails`
- `scopeAndMethodology`
- `reconRawOutput`
- `proofOfCompromiseSummary`
- `riskAssessmentNotes`
- `conclusionAndLessons`

### `MilestoneItem` & `SavedScanRecord`
- `MilestoneItem`: Tracks engagement checklist completion across `Lab Setup`, `VAPT Execution`, `Scripting & GitHub`, and `Final Submission`.
- `SavedScanRecord`: Stores parsed Nmap XML or Live TCP Probe snapshots (`targetIp`, `osGuess`, `openPorts`, `findings`).

---

## 2. Persistence Modes

### Guest Mode (`localStorage`)
- Active automatically when not signed in.
- Key: `vapt_lab_studio_workspace_v2` (workspace state) and `vapt_studio_theme` (`'light' | 'dark'`).
- Automatically applies `normalizeLegacyAssessor()` and `rehydrateVectors()` on load so playbook command generator functions remain intact.

### Cloud Sync Mode (Firebase Auth + Cloud Firestore)
Configured in `firebase-applet-config.json` and `src/lib/firebase.ts`:
- Users authenticate via **Google Sign-In** (`signInWithPopup`).
- Workspaces and scan history sync to user-scoped Firestore subcollections.

---

## 3. Firestore Collections (`firebase-blueprint.json`)

| Collection Path | Entity | Purpose |
| --- | --- | --- |
| `/users/{userId}/workspaces/{workspaceId}` | `LabWorkspace` | Stores serialized `configJson`, `milestonesJson`, `vectorsJson`, `sectionsJson`, `title`, `ownerUid`, `createdAt`, `updatedAt`. |
| `/users/{userId}/scans/{scanId}` | `SavedScan` | Stores `ownerUid`, `targetIp`, `osGuess`, `openPortCount`, `findingCount`, `summaryJson`, and `createdAt`. |

---

## 4. Security Rules Summary (`firestore.rules`)

- **Default-Deny Safety Net**: All unmatched document paths deny read and write (`allow read, write: if false`).
- **Strict Ownership & Verified Email**: Reads and writes under `/users/{userId}/...` require `request.auth != null`, `request.auth.token.email_verified == true`, and `request.auth.uid == userId`.
- **Schema & Size Validation**:
  - `isValidWorkspace` enforces exact field keys, `ownerUid == userId`, string length limits (e.g., `vectorsJson <= 120000` chars), and server timestamps (`request.time`).
  - `isValidScan` enforces immutable `ownerUid`, non-negative `openPortCount` / `findingCount`, and server `createdAt == request.time`.
  - Updates to workspaces prevent altering `ownerUid` or `createdAt`.
