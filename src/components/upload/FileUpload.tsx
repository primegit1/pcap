import { useCallback, useRef, useState } from "react";
import { useDropzone, type FileRejection } from "react-dropzone";
import { formatFileSize } from "../../utils/format";
import {
  MAX_CAPTURE_BYTES,
  captureSizeWarning,
  describeCaptureSizeProblem,
} from "../../utils/limits";

interface FileUploadProps {
  onFileSelected: (files: File[]) => void;
  onAnalyze: (files: File[]) => void;
  isProcessing: boolean;
  maxFiles?: number;
}

export function FileUpload({
  onFileSelected,
  onAnalyze,
  isProcessing,
  maxFiles = 5,
}: FileUploadProps) {
  const [files, setFiles] = useState<File[]>([]);
  const [rejections, setRejections] = useState<string[]>([]);
  const filesRef = useRef<File[]>([]);

  const syncFiles = useCallback((next: File[]) => {
    filesRef.current = next;
    setFiles(next);
    onFileSelected(next);
  }, [onFileSelected]);

  const onDrop = useCallback(
    (acceptedFiles: File[]) => {
      setRejections([]);
      if (acceptedFiles.length > 0) {
        const merged = [...filesRef.current, ...acceptedFiles].slice(0, maxFiles);
        syncFiles(merged);
      }
    },
    [syncFiles, maxFiles]
  );

  const onDropRejected = useCallback((rejected: FileRejection[]) => {
    setRejections(
      rejected.map(({ file, errors }) => {
        const code = errors[0]?.code;
        if (code === "file-too-large") {
          return describeCaptureSizeProblem(file.name, file.size) ?? `${file.name} is too large.`;
        }
        if (code === "file-invalid-type") {
          return `${file.name}: only .pcap and .pcapng files are supported.`;
        }
        if (code === "too-many-files") {
          return `Too many files: you can analyze up to ${maxFiles} at a time.`;
        }
        return `${file.name}: ${errors[0]?.message ?? "could not be added"}`;
      })
    );
  }, [maxFiles]);

  const { getRootProps, getInputProps, isDragActive: dropIsActive, isDragReject: dropIsReject } = useDropzone({
    onDrop,
    onDropRejected,
    maxSize: MAX_CAPTURE_BYTES,
    accept: {
      "application/vnd.tcpdump.pcap": [".pcap"],
      "application/x-pcapng": [".pcapng"],
      "application/octet-stream": [".pcap", ".pcapng"],
    },
    maxFiles,
    disabled: isProcessing,
  });

  const clearFiles = () => {
    syncFiles([]);
  };

  const removeFile = (index: number) => {
    syncFiles(filesRef.current.filter((_, i) => i !== index));
  };

  const handleAnalyze = () => {
    if (files.length === 0) return;
    onAnalyze(files);
  };

  // Determine drag state
  const currentIsDragActive = dropIsActive && !dropIsReject;
  const currentIsDragReject = dropIsReject;

  return (
    <div className="max-w-2xl mx-auto w-full">
      <div
        {...getRootProps()}
        className={`
          glass-strong border-2 border-dashed rounded-xl p-10 text-center cursor-pointer
          transition-all duration-200
          ${currentIsDragActive && !currentIsDragReject
            ? "border-cyan-500 bg-cyan-500/10 glass-border-glow"
            : currentIsDragReject
              ? "border-red-500 bg-red-500/10"
              : "border-slate-700 hover:border-slate-600 bg-slate-900/30"
          }
          ${isProcessing ? "opacity-50 pointer-events-none" : ""}
        `}
      >
        <input {...getInputProps()} />

        {files.length > 0 ? (
          <div className="space-y-4" onClick={(e) => e.stopPropagation()}>
            {/* File list */}
            <div className="space-y-3">
              {files.map((file, index) => (
                <div
                  key={index}
                  className="glass border border-slate-800 rounded-lg p-3 flex items-center gap-3"
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="w-10 h-10 rounded-lg bg-cyan-500/20 flex items-center justify-center glass-border">
                    <span className="text-cyan-400 text-xs font-bold">PCAP</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-white font-medium text-sm truncate">{file.name}</p>
                    <p className="text-slate-400 text-xs">{formatFileSize(file.size)}</p>
                    {captureSizeWarning(file.size) && (
                      <p className="text-amber-400 text-xs mt-0.5">{captureSizeWarning(file.size)}</p>
                    )}
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      removeFile(index);
                    }}
                    className="p-1 text-slate-500 hover:text-red-400 transition-colors"
                    title="Remove file"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </div>
              ))}
            </div>

            {/* Action buttons */}
            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleAnalyze();
                }}
                disabled={isProcessing || files.length === 0}
                className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium rounded-xl transition-all duration-200 active:scale-[0.97] disabled:opacity-50 glow-authority"
              >
                Analyze All
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  clearFiles();
                }}
                disabled={isProcessing}
                className="px-5 py-2.5 glass-border text-slate-300 text-sm font-medium rounded-xl transition-colors"
              >
                Clear All
              </button>
            </div>

            <p className="text-xs text-slate-500">
              {files.length} of {maxFiles} files selected
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="w-14 h-14 mx-auto rounded-full bg-slate-800 flex items-center justify-center glass-border">
              <svg className="w-7 h-7 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
              </svg>
            </div>
            <div>
              <p className="text-white font-medium">
                {currentIsDragActive
                  ? "Drop your PCAP files here"
                  : `Drag & drop up to ${maxFiles} PCAP files here`}
              </p>
              <p className="text-slate-400 text-sm mt-1">
                or click to browse — supports .pcap and .pcapng
              </p>
            </div>
            {currentIsDragReject && (
              <p className="text-red-400 text-xs">Only .pcap and .pcapng files are supported</p>
            )}
          </div>
        )}
      </div>

      {rejections.length > 0 && (
        <div role="alert" className="mt-3 border border-red-800/50 bg-red-900/20 rounded-lg p-3">
          <ul className="text-xs text-red-300 list-disc pl-4 space-y-1">
            {rejections.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}