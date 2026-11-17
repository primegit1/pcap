import React, { createContext, useContext, useReducer, type ReactNode } from "react";
import type { Packet } from "../types/packets";
import type { AnalysisResult, FlowRecord, HostInfo, SecurityFinding, ProtocolCount, AnalysisSummary } from "../types/analysis";

/* ========== State ========== */

export interface MultiFileState {
  files: File[];
  packets: Packet[];
  flows: FlowRecord[];
  hosts: Map<string, HostInfo>;
  findings: SecurityFinding[];
  protocolCounts: ProtocolCount[];
  summary: AnalysisSummary | null;
  result: AnalysisResult | null;
}

export interface AppState {
  // Parsing state
  isProcessing: boolean;
  progress: number;
  progressStage: string;
  fileName: string;
  fileSize: number;
  error: string | null;
  /** Files that failed to parse/analyze and were skipped (name + reason). */
  skippedFiles: string[];

  // Multi-file state (per-file results, canonical store for combining/add)
  multiFiles: MultiFileState[];

  // Combined analysis results
  combinedPackets: Packet[];
  combinedFlows: FlowRecord[];
  combinedHosts: Map<string, HostInfo>;
  combinedFindings: SecurityFinding[];
  combinedProtocolCounts: ProtocolCount[];
  combinedSummary: AnalysisSummary | null;
  combinedResult: AnalysisResult | null;

  // Analysis results (aliases of the combined result for page compatibility)
  packets: Packet[];
  flows: FlowRecord[];
  hosts: Map<string, HostInfo>;
  findings: SecurityFinding[];
  protocolCounts: ProtocolCount[];
  summary: AnalysisSummary | null;
  result: AnalysisResult | null;
}

const initialState: AppState = {
  isProcessing: false,
  progress: 0,
  progressStage: "",
  fileName: "",
  fileSize: 0,
  error: null,
  skippedFiles: [],
  multiFiles: [],
  combinedPackets: [],
  combinedFlows: [],
  combinedHosts: new Map(),
  combinedFindings: [],
  combinedProtocolCounts: [],
  combinedSummary: null,
  combinedResult: null,
  packets: [],
  flows: [],
  hosts: new Map(),
  findings: [],
  protocolCounts: [],
  summary: null,
  result: null,
};

/* ========== Actions ========== */

type AppAction =
  | { type: "START_PROCESSING"; fileName: string; fileSize: number }
  | { type: "SET_PROGRESS"; progress: number; stage: string }
  | { type: "SET_ERROR"; error: string }
  | { type: "RESET" }
  | { type: "FINISH_ANALYSIS"; result: AnalysisResult; multiFiles: MultiFileState[]; skipped: string[] };

function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case "START_PROCESSING":
      return {
        ...state,
        isProcessing: true,
        progress: 0,
        progressStage: "",
        error: null,
        skippedFiles: [],
        fileName: action.fileName,
        fileSize: action.fileSize,
      };

    case "SET_PROGRESS":
      return {
        ...state,
        progress: action.progress,
        progressStage: action.stage,
      };

    case "SET_ERROR":
      return {
        ...state,
        isProcessing: false,
        error: action.error,
      };

    case "RESET":
      return { ...initialState };

    case "FINISH_ANALYSIS": {
      const r = action.result;
      return {
        ...state,
        isProcessing: false,
        progress: 100,
        progressStage: "",
        error: null,
        skippedFiles: action.skipped,
        fileName: r.fileName,
        multiFiles: action.multiFiles,
        // Combined fields
        combinedPackets: r.packets,
        combinedFlows: r.flows,
        combinedHosts: r.hosts,
        combinedFindings: r.findings,
        combinedProtocolCounts: r.protocolCounts,
        combinedSummary: r.summary,
        combinedResult: r,
        // Single-file aliases (so all pages read the same data)
        packets: r.packets,
        flows: r.flows,
        hosts: r.hosts,
        findings: r.findings,
        protocolCounts: r.protocolCounts,
        summary: r.summary,
        result: r,
      };
    }

    default:
      return state;
  }
}

/* ========== Context ========== */

interface AppContextValue {
  state: AppState;
  dispatch: React.Dispatch<AppAction>;
}

const AppContext = createContext<AppContextValue | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(appReducer, initialState);

  return (
    <AppContext.Provider value={{ state, dispatch }}>
      {children}
    </AppContext.Provider>
  );
}

export function useAppContext(): AppContextValue {
  const ctx = useContext(AppContext);
  if (!ctx) {
    throw new Error("useAppContext must be used within AppProvider");
  }
  return ctx;
}
