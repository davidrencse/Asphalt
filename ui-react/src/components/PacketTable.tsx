import { PacketRow } from '../types';

interface PacketTableProps {
  rows: PacketRow[];
  collapsed: boolean;
}

export function PacketTable({ rows, collapsed }: PacketTableProps) {
  return (
    <div className={`transition-all duration-300 ${collapsed ? 'max-h-0 opacity-0 overflow-hidden' : 'max-h-[600px] opacity-100'}`}>
      <div className="border border-white/10 rounded-xl overflow-hidden bg-slate-900/50">
        <div className="max-h-[520px] overflow-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-slate-950/80 text-slate-300">
              <tr className="text-xs uppercase tracking-[0.14em]">
                {['ID', 'TIME', 'STACK', 'SRC', 'DST', 'PORTS', 'L4', 'FLAGS', 'QUALITY'].map((col) => (
                  <th key={col} className="text-left px-3 py-2 border-b border-white/10">{col}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={row.id} className={index % 2 === 0 ? 'bg-slate-900/40' : 'bg-slate-950/20'}>
                  <td className="px-3 py-2 text-slate-100">{row.id}</td>
                  <td className="px-3 py-2 text-slate-300">{row.time}</td>
                  <td className="px-3 py-2 text-slate-300">{row.stack}</td>
                  <td className="px-3 py-2 text-slate-200">{row.src}</td>
                  <td className="px-3 py-2 text-slate-200">{row.dst}</td>
                  <td className="px-3 py-2 text-slate-300">{row.ports}</td>
                  <td className="px-3 py-2 text-slate-300">{row.l4}</td>
                  <td className="px-3 py-2 text-slate-300">{row.flags}</td>
                  <td className="px-3 py-2 text-slate-300">{row.quality}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
