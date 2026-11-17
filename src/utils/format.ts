/**
 * Format bytes to a human-readable string.
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1000));
  const value = bytes / Math.pow(1000, i);
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/**
 * Format a duration in microseconds to a human-readable string.
 */
export function formatDuration(us: number): string {
  if (us <= 0) return "0s";

  const totalSeconds = us / 1_000_000;

  if (totalSeconds < 1) return `${(us / 1000).toFixed(0)}ms`;
  if (totalSeconds < 60) return `${totalSeconds.toFixed(1)}s`;

  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = Math.floor(totalSeconds % 60);

  const parts: string[] = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  parts.push(`${seconds}s`);

  return parts.join(" ");
}

/**
 * Format a timestamp (in microseconds since epoch) to a readable date/time.
 */
export function formatDateTime(us: number): string {
  if (us <= 0) return "-";
  const ms = Math.floor(us / 1000);
  const d = new Date(ms);
  return d.toLocaleString();
}

/**
 * Format a timestamp to show relative time with microsecond precision.
 */
export function formatTimestamp(us: number): string {
  if (us <= 0) return "-";
  const ms = Math.floor(us / 1000);
  const d = new Date(ms);
  const time = d.toLocaleTimeString();
  const micro = (us % 1000).toString().padStart(3, "0");
  return `${time}.${micro}`;
}

/**
 * Format a number with commas.
 */
export function formatNumber(n: number): string {
  return n.toLocaleString();
}

/**
 * Truncate a string to a max length with ellipsis.
 */
export function truncate(str: string, max: number): string {
  if (str.length <= max) return str;
  return str.slice(0, max) + "...";
}

/**
 * Format a MAC address for display.
 */
export function formatMac(mac: string): string {
  if (!mac) return "-";
  return mac;
}

/**
 * Format file size for the upload component.
 */
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
