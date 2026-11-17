import { formatBytes } from "../../utils/format";
import { CopyableValue } from "../shared/CopyableValue";

interface TopTalkersProps {
  talkers: { ip: string; packetCount: number; byteCount: number }[];
}

export function TopTalkers({ talkers }: TopTalkersProps) {
  if (talkers.length === 0) {
    return <p className="text-slate-500 text-sm py-4 text-center">No talkers</p>;
  }

  const maxBytes = talkers[0]?.byteCount ?? 1;

  return (
    <div className="glass rounded-xl border border-slate-800 overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-800 text-left text-slate-500">
            <th className="pb-2 pr-3 font-medium">#</th>
            <th className="pb-2 pr-3 font-medium">IP Address</th>
            <th className="pb-2 pr-3 font-medium">Packets</th>
            <th className="pb-2 font-medium">Bytes</th>
          </tr>
        </thead>
        <tbody>
          {talkers.slice(0, 10).map((t, i) => {
            const barWidth = (t.byteCount / maxBytes) * 100;
            return (
              <tr key={t.ip} className="border-b border-slate-800/50">
                <td className="py-2 pr-3 text-slate-500 text-xs">{i + 1}</td>
                <td className="py-2 pr-3">
                  <CopyableValue value={t.ip} />
                </td>
                <td className="py-2 pr-3 text-white text-xs">{t.packetCount.toLocaleString()}</td>
                <td className="py-2">
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 bg-slate-800 rounded-full w-20 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-cyan-500 glow-authority"
                        style={{ width: `${barWidth}%` }}
                      />
                    </div>
                    <span className="text-xs text-slate-400">{formatBytes(t.byteCount)}</span>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}