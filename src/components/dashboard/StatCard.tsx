import { useNavigate } from "react-router-dom";

interface StatCardProps {
  label: string;
  value: string;
  icon: React.ReactNode;
  accent?: string;
  /** Route to navigate to on click (e.g. "/packets", "/assets") */
  navigateTo?: string;
}

export function StatCard({ label, value, icon, accent = "text-cyan-400", navigateTo }: StatCardProps) {
  const navigate = useNavigate();

  const isClickable = !!navigateTo;

  return (
    <div
      onClick={navigateTo ? () => navigate(navigateTo) : undefined}
      className={`glass-elevated border transition-colors ${
        isClickable
          ? "cursor-pointer hover:scale-[1.02] hover:shadow-authority"
          : "hover:scale-[1.01]"
      }`}
      role={isClickable ? "button" : undefined}
      tabIndex={isClickable ? 0 : undefined}
      onKeyDown={
        isClickable
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                navigate(navigateTo!);
              }
            }
          : undefined
      }
      aria-label={isClickable ? `${label}: ${value} — click to view details` : undefined}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-slate-400 text-xs font-medium uppercase tracking-wider">{label}</p>
          <p className="text-white text-2xl font-semibold mt-1">{value}</p>
        </div>
        <div className={`w-10 h-10 rounded-xl bg-slate-800/60 flex items-center justify-center ${accent} glass-border`}>
          {icon}
        </div>
      </div>
    </div>
  );
}