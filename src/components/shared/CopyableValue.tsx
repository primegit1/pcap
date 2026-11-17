import { useState, useCallback, useRef } from "react";

interface CopyableValueProps {
  /** The text to copy to clipboard */
  value: string;
  /** Display content — defaults to value if not provided */
  children?: React.ReactNode;
  /** Additional CSS classes for the wrapper */
  className?: string;
}

/**
 * Click-to-copy component with a brief "Copied!" tooltip.
 * Wraps any content and copies `value` to clipboard on click.
 */
export function CopyableValue({ value, children, className = "" }: CopyableValueProps) {
  const [copied, setCopied] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleCopy = useCallback(
    async (e: React.MouseEvent) => {
      e.stopPropagation(); // don't trigger row click / navigation

      try {
        await navigator.clipboard.writeText(value);
        setCopied(true);

        // Clear any existing timeout
        if (timeoutRef.current) clearTimeout(timeoutRef.current);
        timeoutRef.current = setTimeout(() => setCopied(false), 1500);
      } catch {
        // Clipboard API not available — silently ignore
      }
    },
    [value]
  );

  return (
    <span className={`relative inline-flex items-center group ${className}`}>
      <button
        type="button"
        onClick={handleCopy}
        className="inline-flex items-center gap-1 cursor-pointer hover:opacity-80 transition-opacity"
        title={`Copy ${value}`}
      >
        {children ?? <code className="text-cyan-400 text-xs font-mono">{value}</code>}

        {/* Copy icon — visible on hover */}
        <svg
          className="w-3 h-3 text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184"
          />
        </svg>
      </button>

      {/* "Copied!" tooltip */}
      {copied && (
        <span className="absolute -top-8 left-1/2 -translate-x-1/2 px-2.5 py-1 bg-cyan-600 text-white text-[10px] font-medium rounded-md shadow-lg whitespace-nowrap z-10 animate-pulse">
          Copied!
        </span>
      )}
    </span>
  );
}