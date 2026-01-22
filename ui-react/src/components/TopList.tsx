interface TopListProps {
  title: string;
  items: { label: string; value: string }[];
}

export function TopList({ title, items }: TopListProps) {
  return (
    <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
      <div className="text-xs uppercase tracking-[0.16em] text-slate-400">{title}</div>
      <div className="mt-2 space-y-2">
        {items.map((item) => (
          <div key={item.label} className="flex items-center justify-between text-sm text-slate-200">
            <span className="truncate max-w-[70%]">{item.label}</span>
            <span className="text-slate-300 font-medium">{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
