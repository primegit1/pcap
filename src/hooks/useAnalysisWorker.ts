import { useCallback, useEffect, useRef } from "react";
import type { AnalysisResult } from "../types/analysis";
import type { AnalyzeRequest, PerFileResult, WorkerMessage } from "../workers/messages";

export interface AnalysisOutput {
  perFile: PerFileResult[];
  combined: AnalysisResult;
  skipped: string[];
}

/** Thrown (as a rejection) when the user cancels a running analysis. */
export class AnalysisCancelled extends Error {
  constructor() {
    super("Analysis cancelled");
    this.name = "AnalysisCancelled";
  }
}

/**
 * Runs the whole parse → decode → analyze pipeline in a Web Worker.
 * `run` resolves with the results; `cancel` terminates the worker immediately.
 */
export function useAnalysisWorker() {
  const workerRef = useRef<Worker | null>(null);
  const rejectRef = useRef<((reason: Error) => void) | null>(null);

  const cancel = useCallback(() => {
    workerRef.current?.terminate();
    workerRef.current = null;
    rejectRef.current?.(new AnalysisCancelled());
    rejectRef.current = null;
  }, []);

  const run = useCallback(
    (files: File[], onProgress: (progress: number, stage: string) => void) =>
      new Promise<AnalysisOutput>((resolve, reject) => {
        cancel(); // never run two analyses at once
        const worker = new Worker(new URL("../workers/analysis.worker.ts", import.meta.url), {
          type: "module",
        });
        workerRef.current = worker;
        rejectRef.current = reject;

        const finish = () => {
          worker.terminate();
          if (workerRef.current === worker) workerRef.current = null;
          rejectRef.current = null;
        };

        worker.onmessage = (event: MessageEvent<WorkerMessage>) => {
          const msg = event.data;
          if (msg.type === "progress") {
            onProgress(msg.progress, msg.stage);
          } else if (msg.type === "done") {
            finish();
            resolve({ perFile: msg.perFile, combined: msg.combined, skipped: msg.skipped });
          } else {
            finish();
            reject(new Error(msg.error));
          }
        };
        worker.onerror = (event) => {
          finish();
          reject(new Error(event.message || "The analysis worker crashed (possibly out of memory)."));
        };

        const request: AnalyzeRequest = { type: "analyze", files };
        worker.postMessage(request);
      }),
    [cancel]
  );

  // Don't leave a worker running if the page unmounts.
  useEffect(() => cancel, [cancel]);

  return { run, cancel };
}
