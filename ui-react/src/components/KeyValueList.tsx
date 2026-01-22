interface KeyValueListProps {
  items: { label: string; value: string }[];
  compact?: boolean;
}

export function KeyValueList({ items, compact }: KeyValueListProps) {
  return (
    <div className={`grid gap-1 ${compact ? 'text-xs' : 'text-sm'}`}>
      {items.map((item) => (
        <div key={item.label} className="flex items-center justify-between gap-3 text-slate-200">
          <span className="text-slate-400">{item.label}</span>
          <span className="font-medium text-slate-100">{item.value}</span>
        </div>
      ))}
    </div>
  );
}
