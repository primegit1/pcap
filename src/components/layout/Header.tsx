import { useAppContext } from "../../context/AppContext";
import { ExportButton } from "../reports/ExportButton";

interface HeaderProps {
  title: string;
  onMenuToggle: () => void;
}

const PAGE_TITLES: Record<string, string> = {
  "/": "Overview",
  "/findings": "Security Findings",
  "/assets": "Assets",
  "/protocols": "Protocols",
  "/packets": "Packet Viewer",
};

export function Header({ title: _title, onMenuToggle }: HeaderProps) {
  const { state } = useAppContext();

  // Get title from path
  const path = window.location.pathname;
  const pageTitle = PAGE_TITLES[path] || "PCAP Analyzer";

  return (
    <header className="h-16 glass-strong border-b border-slate-800 flex items-center justify-between px-4 lg:px-6 sticky top-0 z-30">
      <div className="flex items-center gap-3">
        {/* Mobile menu button */}
        <button
          onClick={onMenuToggle}
          className="lg:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/50 transition-colors"
          aria-label="Toggle navigation menu"
        >
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
          </svg>
        </button>

        <h2 className="text-white text-lg font-semibold">{pageTitle}</h2>
      </div>

      {/* Right side: status and export */}
      <div className="flex items-center gap-3">
        {state.isProcessing && (
          <div className="flex items-center gap-2 text-sm text-cyan-400">
            <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth={4} />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Processing...
          </div>
        )}

        {state.result && !state.isProcessing && (
          <>
            <ExportButton />
            <span className="text-xs text-slate-400 bg-slate-800/60 px-2 py-1 rounded">
              {state.result.packets.length.toLocaleString()} packets
            </span>
          </>
        )}
      </div>
    </header>
  );
}