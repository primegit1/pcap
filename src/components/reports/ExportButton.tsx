import { useState, useRef, useEffect } from "react";
import { useAppContext } from "../../context/AppContext";
import { exportAsJson, exportAsCsv, exportAsHtml } from "../../utils/export";

export function ExportButton() {
  const { state } = useAppContext();
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close on click outside
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  if (!state.result) return null;

  const handleExport = (format: "json" | "csv" | "html" | "print") => {
    if (!state.result) return;

    switch (format) {
      case "json":
        exportAsJson(state.result);
        break;
      case "csv":
        exportAsCsv(state.result.findings);
        break;
      case "html":
        exportAsHtml(state.result);
        break;
      case "print":
        window.print();
        break;
    }

    setIsOpen(false);
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-1.5 px-3 py-1.5 glass-border text-slate-300 text-sm rounded-xl transition-colors active:scale-[0.97]"
        title="Export options"
      >
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
        </svg>
        Export
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-56 glass-strong border border-slate-800 rounded-xl shadow-xl shadow-black/50 z-50 py-1">
          <button
            onClick={() => handleExport("html")}
            className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-slate-300 hover:bg-slate-800/50 transition-colors text-left rounded-xl"
          >
            <svg className="w-4 h-4 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25" />
            </svg>
            <div>
              <p className="font-medium">HTML Report</p>
              <p className="text-xs text-slate-500">Full report with findings & assets</p>
            </div>
          </button>

          <button
            onClick={() => handleExport("json")}
            className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-slate-300 hover:bg-slate-800/50 transition-colors text-left rounded-xl"
          >
            <svg className="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 0v3.75m-16.5-3.75v3.75m16.5 0v3.75C20.25 16.153 16.556 18 12 18s-8.25-1.847-8.25-4.125v-3.75m16.5 0c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
            </svg>
            <div>
              <p className="font-medium">JSON Data</p>
              <p className="text-xs text-slate-500">Full analysis data dump</p>
            </div>
          </button>

          <button
            onClick={() => handleExport("csv")}
            className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-slate-300 hover:bg-slate-800/50 transition-colors text-left rounded-xl"
          >
            <svg className="w-4 h-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 9.776c.112-.017.227-.026.344-.026h15.812c.117 0 .232.009.344.026m-16.5 0a2.25 2.25 0 00-1.883 2.542l.857 6a2.25 2.25 0 002.227 1.932H19.05a2.25 2.25 0 002.227-1.932l.857-6a2.25 2.25 0 00-1.883-2.542m-16.5 0V6A2.25 2.25 0 016 3.75h3.879a1.5 1.5 0 011.06.44l2.122 2.12a1.5 1.5 0 001.06.44H18A2.25 2.25 0 0120.25 9v.776" />
            </svg>
            <div>
              <p className="font-medium">CSV Findings</p>
              <p className="text-xs text-slate-500">Flat table of security findings</p>
            </div>
          </button>

          <div className="border-t border-slate-800 my-1" />

          <button
            onClick={() => handleExport("print")}
            className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-slate-300 hover:bg-slate-800/50 transition-colors text-left rounded-xl"
          >
            <svg className="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 3v4m6-4v4m-6 4v4m6-4v4m-6 4v4m-6-4v4m6-4v4m6 4v4m-6 4v4m6 4v4" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 19a2 2 0 012-2h12a2 2 0 012 2v2H3v-2z" />
            </svg>
            <div>
              <p className="font-medium">Print to PDF</p>
              <p className="text-xs text-slate-500">Generate printable report</p>
            </div>
          </button>
        </div>
      )}
    </div>
  );
}