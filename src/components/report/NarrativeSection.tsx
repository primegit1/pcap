interface NarrativeSectionProps {
  title?: string;
  children: React.ReactNode;
  icon?: string;
}

export function NarrativeSection({ title, children, icon }: NarrativeSectionProps) {
  return (
    <div className="glass rounded-xl border border-slate-800 p-5">
      {title && (
        <h3 className="text-white font-medium mb-3 text-sm flex items-center gap-2">
          {icon && <span>{icon}</span>}
          {title}
        </h3>
      )}
      <div className="text-slate-300 text-sm leading-relaxed space-y-2">
        {children}
      </div>
    </div>
  );
}