/**
 * Analysis Web Worker.
 *
 * Reads, parses, decodes and analyzes capture files entirely off the main thread, so the UI
 * stays responsive and the progress bar can repaint. Only the finished results are sent back,
 * with the packet byte buffers *transferred* (zero-copy) rather than structured-cloned.
 */
import { decodeCapture } from "../parsers/capture";
import { analyzePackets, combineAnalysisResults } from "../analysis";
import { describeCaptureSizeProblem } from "../utils/limits";
import type { AnalysisResult } from "../types/analysis";
import type { AnalyzeRequest, PerFileResult, WorkerMessage } from "./messages";

/** Progress is posted at most this often, whatever the pipeline reports. */
const PROGRESS_INTERVAL_MS = 100;
let lastProgressAt = 0;

function post(message: WorkerMessage, transfer: Transferable[] = []) {
  // `self.postMessage(msg, { transfer })` is valid in a worker; the DOM typings model it on Window.
  self.postMessage(message, { transfer });
}

function progress(percent: number, stage: string, force = false) {
  const now = performance.now();
  if (!force && now - lastProgressAt < PROGRESS_INTERVAL_MS) return;
  lastProgressAt = now;
  post({ type: "progress", progress: Math.max(0, Math.min(100, Math.round(percent))), stage });
}

/** Every distinct packet byte buffer in the results, for zero-copy transfer. */
function collectBuffers(results: AnalysisResult[]): ArrayBuffer[] {
  const buffers = new Set<ArrayBuffer>();
  for (const r of results) {
    for (const p of r.packets) {
      buffers.add(p.raw);
      if (p.appPayload) buffers.add(p.appPayload);
    }
  }
  return [...buffers];
}

async function analyzeFiles(files: File[]) {
  const perFile: PerFileResult[] = [];
  const skipped: string[] = [];
  const n = files.length;
  // 0-90%: per-file work, 90-100%: combining.
  const perFileSpan = 90 / n;

  for (let i = 0; i < n; i++) {
    const file = files[i];
    const base = i * perFileSpan;
    const label = n > 1 ? ` (${file.name})` : "";

    try {
      const sizeProblem = describeCaptureSizeProblem(file.name, file.size);
      if (sizeProblem) throw new Error(sizeProblem);

      progress(base, `Reading file${label}`, true);
      const buffer = await file.arrayBuffer();

      const decoded = decodeCapture(buffer, (pct, stage) =>
        progress(base + (pct / 100) * perFileSpan * 0.4, `${stage}${label}`)
      );
      if (decoded.packets.length === 0) {
        const why = decoded.info.warnings.join(" ") || "the file contains no packets";
        throw new Error(`No decodable packets: ${why}`);
      }

      const result = analyzePackets(decoded.packets, file.name, (stage, current, total) =>
        progress(
          base + perFileSpan * 0.4 + (current / total) * perFileSpan * 0.6,
          `${stage}${label}`
        )
      );
      if (decoded.info.warnings.length > 0) {
        result.captureWarnings = decoded.info.warnings.map((w) => (n > 1 ? `${file.name}: ${w}` : w));
      }
      perFile.push({ fileIndex: i, fileName: file.name, fileSize: file.size, result });
    } catch (err) {
      skipped.push(`${file.name} — ${err instanceof Error ? err.message : "could not be parsed"}`);
    }
  }

  if (perFile.length === 0) {
    throw new Error(`Could not analyze any of the uploaded files. ${skipped.join(" ")}`);
  }

  progress(90, "Combining results", true);
  const combined =
    perFile.length === 1
      ? perFile[0].result
      : combineAnalysisResults(perFile.map((p) => p.result));

  progress(100, "Done", true);
  // `combined` re-uses the per-file buffers, and `collectBuffers` de-duplicates them.
  const transfer = collectBuffers([...perFile.map((p) => p.result), combined]);
  post({ type: "done", perFile, combined, skipped }, transfer);
}

self.onmessage = (event: MessageEvent<AnalyzeRequest>) => {
  if (event.data.type !== "analyze") return;
  lastProgressAt = 0;
  analyzeFiles(event.data.files).catch((err: unknown) => {
    post({
      type: "error",
      error: err instanceof Error ? err.message : "Analysis failed",
    });
  });
};
