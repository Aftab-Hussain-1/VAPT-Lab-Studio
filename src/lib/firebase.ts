import { initializeApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut,
  type User,
} from 'firebase/auth';
import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocFromServer,
  getDocs,
  getFirestore,
  orderBy,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
} from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';
import {
  CorrelatedFindingItem,
  LabConfig,
  MilestoneItem,
  ParsedPortItem,
  PlaybookVector,
  ReportTextSections,
  SavedScanRecord,
  SavedWorkspaceSummary,
} from '../types/vapt';

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}
void testConnection();

export async function signInWithGoogle(): Promise<User> {
  const result = await signInWithPopup(auth, googleProvider);
  return result.user;
}

export async function signOutAccount(): Promise<void> {
  await signOut(auth);
}

export interface WorkspacePayload {
  config: LabConfig;
  milestones: MilestoneItem[];
  vectors: PlaybookVector[];
  sections: ReportTextSections;
}

function sanitizeId(rawId: string): string {
  const cleaned = rawId.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 80);
  return cleaned || 'default-lab';
}

function clampString(value: string, maxLen: number): string {
  return value.length <= maxLen ? value : value.slice(0, maxLen);
}

export async function listUserWorkspaces(uid: string): Promise<SavedWorkspaceSummary[]> {
  const path = `users/${uid}/workspaces`;
  try {
    const q = query(
      collection(db, 'users', uid, 'workspaces'),
      where('ownerUid', '==', uid),
      orderBy('updatedAt', 'desc')
    );
    const snap = await getDocs(q);
    return snap.docs.map((docSnap) => {
      const data = docSnap.data();
      const ts = data.updatedAt?.toDate ? data.updatedAt.toDate() : null;
      return {
        id: docSnap.id,
        title: typeof data.title === 'string' ? data.title : docSnap.id,
        updatedAtLabel: ts ? ts.toLocaleDateString() : 'Saved',
      };
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

export async function loadUserWorkspace(
  uid: string,
  workspaceId: string
): Promise<WorkspacePayload | null> {
  const safeId = sanitizeId(workspaceId);
  const path = `users/${uid}/workspaces/${safeId}`;
  try {
    const snap = await getDoc(doc(db, 'users', uid, 'workspaces', safeId));
    if (!snap.exists()) return null;
    const data = snap.data();
    return {
      config: JSON.parse(data.configJson) as LabConfig,
      milestones: JSON.parse(data.milestonesJson) as MilestoneItem[],
      vectors: JSON.parse(data.vectorsJson) as PlaybookVector[],
      sections: JSON.parse(data.sectionsJson) as ReportTextSections,
    };
  } catch (error) {
    handleFirestoreError(error, OperationType.GET, path);
  }
}

export async function saveUserWorkspace(
  uid: string,
  workspaceId: string,
  payload: WorkspacePayload
): Promise<void> {
  const safeId = sanitizeId(workspaceId);
  const path = `users/${uid}/workspaces/${safeId}`;
  const docRef = doc(db, 'users', uid, 'workspaces', safeId);

  const safeTitle = clampString(
    (payload.config.labName || payload.config.brandTitle || 'VAPT Lab Workspace').trim(),
    120
  );
  const configJson = clampString(JSON.stringify(payload.config), 11500);
  const milestonesJson = clampString(JSON.stringify(payload.milestones), 19500);
  const vectorsJson = clampString(JSON.stringify(payload.vectors), 118000);
  const sectionsJson = clampString(JSON.stringify(payload.sections), 79000);

  try {
    const existingSnap = await getDoc(docRef);
    if (!existingSnap.exists()) {
      await setDoc(docRef, {
        ownerUid: uid,
        title: safeTitle,
        configJson,
        milestonesJson,
        vectorsJson,
        sectionsJson,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(docRef, {
        title: safeTitle,
        configJson,
        milestonesJson,
        vectorsJson,
        sectionsJson,
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function deleteUserWorkspace(uid: string, workspaceId: string): Promise<void> {
  const safeId = sanitizeId(workspaceId);
  const path = `users/${uid}/workspaces/${safeId}`;
  try {
    await deleteDoc(doc(db, 'users', uid, 'workspaces', safeId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

export async function listUserScans(uid: string): Promise<SavedScanRecord[]> {
  const path = `users/${uid}/scans`;
  try {
    const q = query(
      collection(db, 'users', uid, 'scans'),
      where('ownerUid', '==', uid),
      orderBy('createdAt', 'desc')
    );
    const snap = await getDocs(q);
    return snap.docs.map((docSnap) => {
      const data = docSnap.data();
      const ts = data.createdAt?.toDate ? data.createdAt.toDate() : null;
      const parsedSummary = JSON.parse(data.summaryJson || '{}') as {
        openPorts?: ParsedPortItem[];
        findings?: CorrelatedFindingItem[];
      };
      return {
        id: docSnap.id,
        targetIp: String(data.targetIp || 'unknown'),
        osGuess: String(data.osGuess || 'Not identified'),
        openPortCount: Number(data.openPortCount || 0),
        findingCount: Number(data.findingCount || 0),
        createdAtLabel: ts ? ts.toLocaleString() : 'Saved',
        openPorts: parsedSummary.openPorts || [],
        findings: parsedSummary.findings || [],
      };
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

export async function saveUserScan(
  uid: string,
  scan: {
    targetIp: string;
    osGuess: string;
    openPorts: ParsedPortItem[];
    findings: CorrelatedFindingItem[];
  }
): Promise<string> {
  const scanId = `scan-${Date.now()}`;
  const path = `users/${uid}/scans/${scanId}`;
  const summaryJson = clampString(
    JSON.stringify({ openPorts: scan.openPorts, findings: scan.findings }),
    118000
  );
  try {
    await setDoc(doc(db, 'users', uid, 'scans', scanId), {
      ownerUid: uid,
      targetIp: clampString(scan.targetIp || 'unknown', 120),
      osGuess: clampString(scan.osGuess || 'Not identified', 200),
      openPortCount: scan.openPorts.length,
      findingCount: scan.findings.length,
      summaryJson,
      createdAt: serverTimestamp(),
    });
    return scanId;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function deleteUserScan(uid: string, scanId: string): Promise<void> {
  const safeId = sanitizeId(scanId);
  const path = `users/${uid}/scans/${safeId}`;
  try {
    await deleteDoc(doc(db, 'users', uid, 'scans', safeId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}
