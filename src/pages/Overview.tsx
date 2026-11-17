import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAppContext, type MultiFileState } from "../context/AppContext";
import { FileUpload } from "../components/upload/FileUpload";
import { StatCard } from "../components/dashboard/StatCard";
import { ProtocolChart } from "../components/dashboard/ProtocolChart";
import { TopTalkers } from "../components/dashboard/TopTalkers";
import { TopDestinations } from "../components/dashboard/TopDestinations";
import { formatBytes, formatDuration, formatNumber } from "../utils/format";
import { fetchTestPcap } from "../utils/loadTestData";
import { useAnalysisWorker, AnalysisCancelled } from "../hooks/useAnalysisWorker";

const MAX_FILES = 5;

export default function OverviewPage() {
  const { state, dispatch } = useAppContext();
  const navigate = useNavigate();
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isLoadingTest, setIsLoadingTest] = useState(false);
  const [isAddMode, setIsAddMode] = useState(false);
  const { run: runInWorker, cancel: cancelWorker } = useAnalysisWorker();

  // Determine what to show
  const resultData = state.result;
  const summaryData = state.summary;
  const findingsData = state.findings;
  const protocolData = state.protocolCounts;
  const isMulti = state.multiFiles.length > 1;

  const showUpload = !state.isProcessing && !state.error && (!resultData || isAddMode);
  const showProgress = state.isProcessing;
  const showResult = resultData && !state.isProcessing && !isAddMode;
  const showError = state.error && !state.isProcessing;

  // Analyze a set of files in the worker. In "add" mode the previously analyzed files are
  // re-analyzed together with the new ones (the worker needs the originals to merge correctly);
  // in "new" mode they replace it. Corrupt files are skipped so one bad file doesn't block the rest.
  const runAnalysis = async (files: File[], mode: "new" | "add") => {
    if (files.length === 0) return;

    const existingFiles =
      mode === "add" ? state.multiFiles.filter((mf) => mf.result).flatMap((mf) => mf.files) : [];
    const allFiles = [...existingFiles, ...files];

    dispatch({
      type: "START_PROCESSING",
      fileName: allFiles.map((f) => f.name).join(", "),
      fileSize: allFiles.reduce((sum, f) => sum + f.size, 0),
    });

    try {
      const out = await runInWorker(allFiles, (progress, stage) =>
        dispatch({ type: "SET_PROGRESS", progress, stage })
      );

      const multiFiles: MultiFileState[] = out.perFile.map(({ fileIndex, result }) => ({
        files: [allFiles[fileIndex]],
        packets: result.packets,
        flows: result.flows,
        hosts: result.hosts,
        findings: result.findings,
        protocolCounts: result.protocolCounts,
        summary: result.summary,
        result,
      }));

      dispatch({
        type: "FINISH_ANALYSIS",
        result: out.combined,
        multiFiles,
        skipped: out.skipped,
      });
      setIsAddMode(false);
    } catch (err) {
      if (err instanceof AnalysisCancelled) return; // the user already reset the page
      setIsAddMode(false);
      dispatch({
        type: "SET_ERROR",
        error: err instanceof Error ? err.message : "Analysis failed",
      });
    }
  };

  // Handle file analysis
  const handleAnalyze = (files: File[]) => {
    runAnalysis(files, isAddMode ? "add" : "new");
  };

  const handleReset = () => {
    cancelWorker();
    dispatch({ type: "RESET" });
    setSelectedFiles([]);
    setIsAddMode(false);
  };

  const handleAddForAnalysis = () => {
    setIsAddMode(true);
    setSelectedFiles([]);
  };

  const handleLoadTestData = async () => {
    setIsLoadingTest(true);
    try {
      const file = await fetchTestPcap();
      setSelectedFiles([file]);
      setIsAddMode(false);
      await runAnalysis([file], "new");
    } catch (err) {
      dispatch({
        type: "SET_ERROR",
        error: err instanceof Error ? err.message : "Failed to load test data",
      });
    } finally {
      setIsLoadingTest(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Upload Zone */}
      {showUpload && (
        <div className="py-12">
          {isAddMode && (
            <div className="max-w-2xl mx-auto mb-6 glass border border-cyan-500/50 rounded-xl p-4 text-sm text-cyan-400 flex items-start justify-between gap-4">
              <div>
                <p className="font-medium">Adding to existing analysis</p>
                <p className="text-xs text-slate-400 mt-1">
                  New files will be merged with your current results. Click "New Analysis" to start fresh instead.
                </p>
              </div>
              <button
                onClick={() => setIsAddMode(false)}
                className="px-3 py-1.5 glass-border text-slate-300 text-xs rounded-lg transition-colors shrink-0"
              >
                Cancel
              </button>
            </div>
          )}
          <div className="text-center mb-8">
            <h2 className="text-2xl font-bold text-white mb-2">PCAP Security Analyzer</h2>
            <p className="text-slate-400 text-sm max-w-lg mx-auto">
              Security Analysis Tool by HKG
            </p>
            <div className="flex items-center justify-center gap-4 mt-4">
              <span className="text-xs text-slate-500 bg-slate-800/50 px-2.5 py-1 rounded">
                Single file
              </span>
              <span className="text-xs text-slate-500 bg-slate-800/50 px-2.5 py-1 rounded">
                Multi-file (up to 5)
              </span>
            </div>
          </div>
          <FileUpload
            onFileSelected={setSelectedFiles}
            onAnalyze={handleAnalyze}
            isProcessing={false}
            maxFiles={MAX_FILES}
          />

          {/* Divider */}
          <div className="flex items-center gap-3 max-w-md mx-auto mt-6">
            <div className="flex-1 h-px bg-slate-800" />
            <span className="text-xs text-slate-500 font-medium">or</span>
            <div className="flex-1 h-px bg-slate-800" />
          </div>

          {/* Load test data button */}
          <div className="text-center mt-6">
            <button
              onClick={handleLoadTestData}
              disabled={isLoadingTest}
              className="group inline-flex items-center gap-2 px-5 py-2.5 glass-border text-slate-300 text-sm font-medium rounded-lg transition-all duration-200 disabled:opacity-50"
            >
              {isLoadingTest ? (
                <svg className="w-4 h-4 animate-spin text-slate-400" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth={4} />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : (
                <svg className="w-4 h-4 text-cyan-400 group-hover:text-cyan-300 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23.693L5 14.5m14.8.8l1.402 1.402c1.232 1.232.65 3.318-1.067 3.611A48.309 48.309 0 0112 21c-2.773 0-5.491-.235-8.135-.687-1.718-.293-2.3-2.379-1.067-3.61L5 14.5" />
                </svg>
              )}
              {isLoadingTest ? "Loading..." : "Load Test PCAP Data"}
            </button>
            <p className="text-xs text-slate-600 mt-2">
              Synthetic network traffic — includes HTTP, DNS, TLS, SSH brute-force, and more
            </p>
          </div>
        </div>
      )}

      {/* Progress */}
      {showProgress && (
        <div className="py-12">
          <div className="max-w-2xl mx-auto w-full">
            <div className="glass-strong border border-slate-800 rounded-xl p-6">
              <h3 className="text-white font-medium mb-1 flex items-center gap-2">
                <svg className="w-4 h-4 animate-spin text-cyan-400" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth={4} />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Analyzing {selectedFiles.length > 1 ? `(${selectedFiles.length} files)` : state.fileName}
              </h3>
              <p className="text-xs text-slate-500 mb-4">Running security rules and building flows...</p>

              <div className="space-y-3">
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 to-violet-500 rounded-full"
                    style={{ width: `${state.progress}%` }}
                  />
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-purple-400">{state.progressStage || "Analyzing..."}</span>
                  <span className="text-slate-500 font-mono">{state.progress}%</span>
                </div>
                <button
                  onClick={handleReset}
                  className="mt-2 px-3 py-1.5 glass-border text-slate-400 text-xs rounded-lg transition-colors"
                >
                  Cancel analysis
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Error */}
      {showError && (
        <div className="max-w-2xl mx-auto py-12">
          <div className="bg-red-900/20 border border-red-800/50 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-3">
              <svg className="w-6 h-6 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
              </svg>
              <h3 className="text-red-400 font-medium">Error</h3>
            </div>
            <p className="text-slate-300 text-sm mb-4">{state.error}</p>
            <button
              onClick={handleReset}
              className="px-4 py-2 glass-border text-slate-300 text-sm rounded-lg transition-colors"
            >
              Try again
            </button>
          </div>
        </div>
      )}

      {/* Dashboard */}
      {showResult && summaryData && (
        <div className="space-y-6">
          {/* File info bar */}
          <div className="flex items-center justify-between glass-strong border border-slate-800 rounded-xl px-5 py-3">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center glass-border">
                <span className="text-cyan-400 text-xs font-bold">PA</span>
              </div>
              <div>
                <p className="text-white text-sm font-medium">
                  {isMulti ? `${state.multiFiles.length} files analyzed` : state.fileName}
                </p>
                <p className="text-slate-500 text-xs">Analysis complete</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleReset}
                className="px-3 py-1.5 glass-border text-slate-400 text-xs rounded-lg transition-colors"
              >
                New Analysis
              </button>
              <button
                onClick={handleAddForAnalysis}
                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium rounded-lg transition-colors"
              >
                Add for Analysis
              </button>
            </div>
          </div>

          {/* Multi-file status banner */}
          {isMulti && (
            <div className="glass border border-cyan-500/50 rounded-xl p-4 text-sm text-cyan-400">
              <p className="font-medium mb-1">Combined Analysis Results</p>
              <p className="text-xs text-slate-400">
                Analyzed {state.multiFiles.length} files with combined statistics and aggregated findings.
              </p>
            </div>
          )}

          {/* Capture warnings (unsupported link types, truncation, ...) */}
          {resultData?.captureWarnings && resultData.captureWarnings.length > 0 && (
            <div className="glass border border-amber-500/50 rounded-xl p-4 text-sm text-amber-400">
              <p className="font-medium mb-1">Some capture data could not be analyzed</p>
              <ul className="text-xs text-slate-400 list-disc pl-4 space-y-1">
                {resultData.captureWarnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Skipped files warning */}
          {state.skippedFiles.length > 0 && (
            <div className="glass border border-amber-500/50 rounded-xl p-4 text-sm text-amber-400">
              <p className="font-medium mb-1">Some files were skipped</p>
              <ul className="text-xs text-slate-400 list-disc pl-4 space-y-1">
                {state.skippedFiles.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Stat cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              label="Total Packets"
              value={formatNumber(summaryData.totalPackets)}
              accent="text-cyan-400"
              navigateTo="/packets"
              icon={
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 6.878V6a2.25 2.25 0 012.25-2.25h7.5A2.25 2.25 0 0118 6v.878m-12 0c.235-.083.487-.128.75-.128h10.5c.263 0 .515.045.75.128m-12 0A2.25 2.25 0 004.5 9v.75m6-6V3m0 3v6m0 0v.75M3 18h18M3 18l2.25-9h13.5L21 18M3 18l-2.25-3m18 3l2.25-3" />
                </svg>
              }
            />
            <StatCard
              label="Total Traffic"
              value={formatBytes(summaryData.totalBytes)}
              accent="text-blue-400"
              icon={
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5" />
                </svg>
              }
            />
            <StatCard
              label="Duration"
              value={formatDuration(summaryData.durationUs)}
              accent="text-violet-400"
              icon={
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              }
            />
            <StatCard
              label="Unique Hosts"
              value={formatNumber(summaryData.uniqueHosts)}
              accent="text-teal-400"
              navigateTo="/assets"
              icon={
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
                </svg>
              }
            />
          </div>

          {/* Protocol Chart + Top Talkers grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div
              className="glass rounded-xl border border-slate-800 p-5 cursor-pointer hover:border-cyan-500/50 transition-colors"
              onClick={() => navigate("/protocols")}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); navigate("/protocols"); } }}
            >
              <h3 className="text-white font-medium mb-4 text-sm">Protocol Distribution</h3>
              <ProtocolChart
                protocols={protocolData}
                totalPackets={summaryData.totalPackets}
              />
            </div>

            <div className="glass rounded-xl border border-slate-800 p-5">
              <h3 className="text-white font-medium mb-4 text-sm">Top Talkers</h3>
              <TopTalkers talkers={summaryData.topTalkers} />
            </div>
          </div>

          {/* Top Destinations */}
          <div className="glass rounded-xl border border-slate-800 p-5">
            <h3 className="text-white font-medium mb-4 text-sm">Top Destinations</h3>
            <TopDestinations destinations={summaryData.topDestinations} />
          </div>

          {/* Findings summary */}
          {findingsData.length > 0 && (
            <div className="glass rounded-xl border border-slate-800 p-5">
              <h3 className="text-white font-medium mb-3 text-sm">Security Findings Summary</h3>
              <div className="flex flex-wrap gap-3">
                {(["Critical", "High", "Medium", "Low", "Info"] as const).map((sev) => {
                  const count = findingsData.filter((f) => f.severity === sev).length;
                  if (count === 0) return null;
                  const colors: Record<string, string> = {
                    Critical: "bg-red-900/30 text-red-400 border-red-800/50",
                    High: "bg-orange-900/30 text-orange-400 border-orange-800/50",
                    Medium: "bg-yellow-900/30 text-yellow-400 border-yellow-800/50",
                    Low: "bg-blue-900/30 text-blue-400 border-blue-800/50",
                    Info: "bg-slate-800 text-slate-400 border-slate-700",
                  };
                  return (
                    <div key={sev} className={`px-4 py-2 rounded-lg border ${colors[sev]}`}>
                      <span className="text-sm font-medium">{count}</span>
                      <span className="text-xs ml-1">{sev}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Flows info */}
          <div className="text-center text-xs text-slate-600">
            {summaryData.flowCount.toLocaleString()} flows analyzed
          </div>
        </div>
      )}
    </div>
  );
}