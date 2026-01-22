import { ReactNode, useState } from 'react';

interface AccordionSectionProps {
  title: string;
  summary: string;
  children: ReactNode;
  defaultOpen?: boolean;
}

export function AccordionSection({ title, summary, children, defaultOpen = false }: AccordionSectionProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <section className="border border-white/10 rounded-xl bg-slate-900/40 overflow-hidden">
      <button
        onClick={() => setOpen((prev) => !prev)}
        className="w-full flex items-center justify-between gap-4 px-4 py-3 bg-slate-950/60 text-left"
      >
        <div>
          <div className="text-sm uppercase tracking-[0.2em] text-emerald-300">{title}</div>
          <div className="text-xs text-slate-400 mt-1">{summary}</div>
        </div>
        <span className="text-slate-300 text-xl">{open ? '−' : '+'}</span>
      </button>
      <div
        className={`grid gap-4 px-4 py-4 transition-all duration-300 ${open ? 'max-h-[2000px] opacity-100' : 'max-h-0 opacity-0 overflow-hidden py-0'}`}
      >
        {children}
      </div>
    </section>
  );
}
