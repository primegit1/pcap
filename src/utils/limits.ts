/** Hard limit for a single capture file. Larger files are rejected up front. */
export const MAX_CAPTURE_BYTES = 500 * 1024 * 1024;
/** Above this size the user is warned that analysis may be slow / memory hungry. */
export const WARN_CAPTURE_BYTES = 100 * 1024 * 1024;

export function describeCaptureSizeProblem(fileName: string, bytes: number): string | null {
  if (bytes > MAX_CAPTURE_BYTES) {
    return `${fileName} is ${(bytes / 1024 / 1024).toFixed(0)} MB, which exceeds the ${
      MAX_CAPTURE_BYTES / 1024 / 1024
    } MB limit. Split the capture (e.g. with editcap) or filter it first.`;
  }
  return null;
}

export function captureSizeWarning(bytes: number): string | null {
  if (bytes > WARN_CAPTURE_BYTES) {
    return `Large capture (${(bytes / 1024 / 1024).toFixed(0)} MB): analysis may take a while and use a lot of memory.`;
  }
  return null;
}
