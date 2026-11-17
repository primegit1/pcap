import type { AnalysisResult } from "../types/analysis";

/** Main thread → worker */
export interface AnalyzeRequest {
  type: "analyze";
  /** Every file to include in the analysis (in "add" mode that is the old files plus the new ones). */
  files: File[];
}

export interface PerFileResult {
  /** Index into the `files` array of the request */
  fileIndex: number;
  fileName: string;
  fileSize: number;
  result: AnalysisResult;
}

/** Worker → main thread */
export type WorkerMessage =
  | { type: "progress"; progress: number; stage: string }
  | {
      type: "done";
      perFile: PerFileResult[];
      combined: AnalysisResult;
      /** Files that failed, as "name — reason" */
      skipped: string[];
    }
  | { type: "error"; error: string };
