import { useEffect, useMemo, useState } from 'react';
import { AccordionSection } from './components/AccordionSection';
import { KeyValueList } from './components/KeyValueList';
import { PacketTable } from './components/PacketTable';
import { StatCard } from './components/StatCard';
import { TopList } from './components/TopList';
import { createInitialState, simulateUpdate } from './mockData';
import { DashboardState } from './types';

const divider = 'border border-white/10';

export default function App() {
  const [state, setState] = useState<DashboardState>(() => createInitialState());
  const [running, setRunning] = useState(false);
  const [collapsedTable, setCollapsedTable] = useState(false);
  const [backend, setBackend] = useState('scapy');
  const [iface, setIface] = useState('\\\\Device\\\\NPF_{GUID}');
  const [duration, setDuration] = useState(3);
  const [limit, setLimit] = useState(50);
  const [filter, setFilter] = useState('udp port 53 or tcp port 443');

  useEffect(() => {
    if (!running) return;
    const handle = setInterval(() => {
      setState((prev) => simulateUpdate(prev));
    }, 1000);
    return () => clearInterval(handle);
  }, [running]);

  const protocolMixSummary = useMemo(() => {
    return `TCP ${state.protocolMix.tcpPct}% · UDP ${state.protocolMix.udpPct}% · UNKNOWN ${state.protocolMix.unknownPct}%`;
  }, [state.protocolMix]);

  return (
    <div className="min-h-screen bg-[#0b1118] text-slate-100 font-['Space_Grotesk']">
      <div className="max-w-7xl mx-auto px-6 py-8 grid gap-6">
        <header className="rounded-2xl border border-white/10 bg-gradient-to-br from-emerald-500/10 via-slate-900/40 to-amber-300/10 p-6">
          <div className="text-xs uppercase tracking-[0.3em] text-emerald-300">Asphalt Live Decode</div>
          <h1 className="text-3xl font-semibold mt-2">Live Decode Dashboard</h1>
          <p className="text-slate-400 mt-2">Capture  Decode  UI (local)</p>
        </header>

        <section className="grid gap-4">
          <div className="grid gap-4 xl:grid-cols-[1.4fr_1.2fr_1fr_1fr_0.8fr] lg:grid-cols-3">
            <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
              <label className="text-xs uppercase tracking-[0.16em] text-slate-400">Backend</label>
              <select value={backend} onChange={(e) => setBackend(e.target.value)} className="mt-2 w-full bg-slate-950/60 border border-white/10 rounded-md px-3 py-2 text-sm">
                <option value="scapy">scapy</option>
                <option value="dummy">dummy</option>
              </select>
            </div>
            <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
              <label className="text-xs uppercase tracking-[0.16em] text-slate-400">Interface</label>
              <input value={iface} onChange={(e) => setIface(e.target.value)} className="mt-2 w-full bg-slate-950/60 border border-white/10 rounded-md px-3 py-2 text-sm" />
            </div>
            <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
              <label className="text-xs uppercase tracking-[0.16em] text-slate-400">Duration (s)</label>
              <input type="number" value={duration} onChange={(e) => setDuration(Number(e.target.value))} className="mt-2 w-full bg-slate-950/60 border border-white/10 rounded-md px-3 py-2 text-sm" />
            </div>
            <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
              <label className="text-xs uppercase tracking-[0.16em] text-slate-400">Limit</label>
              <input type="number" value={limit} onChange={(e) => setLimit(Number(e.target.value))} className="mt-2 w-full bg-slate-950/60 border border-white/10 rounded-md px-3 py-2 text-sm" />
            </div>
            <button
              onClick={() => setRunning((prev) => !prev)}
              className="rounded-xl bg-emerald-400 text-slate-950 font-semibold px-4 py-3 hover:bg-emerald-300 transition"
            >
              {running ? 'Stop' : 'Start'}
            </button>
          </div>

          <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
            <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
              <label className="text-xs uppercase tracking-[0.16em] text-slate-400">Filter (BPF)</label>
              <input value={filter} onChange={(e) => setFilter(e.target.value)} className="mt-2 w-full bg-slate-950/60 border border-white/10 rounded-md px-3 py-2 text-sm" />
            </div>
            <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3 flex flex-col justify-center">
              <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Status</div>
              <div className="text-lg text-amber-200 mt-1">Loaded {state.stats.packetCount} packets</div>
            </div>
          </div>
        </section>

        <section className="grid gap-4 md:grid-cols-4">
          <StatCard label="Packets" value={state.stats.packetCount.toLocaleString()} />
          <StatCard label="IPv4 / IPv6" value={`${state.stats.ipv4Count} / ${state.stats.ipv6Count}`} />
          <StatCard label="TCP / UDP" value={`${state.stats.tcpCount} / ${state.stats.udpCount}`} />
          <StatCard label="Flows" value={state.stats.flowCount.toString()} />
        </section>

        <section className="grid gap-4 md:grid-cols-4">
          <StatCard label="Protocol Mix" value={protocolMixSummary} />
          <StatCard label="Abnormal Activity" value={state.abnormal.summary} sub={state.abnormal.details[0]} />
          <StatCard label="TCP Handshakes" value={`${state.tcpHandshake.total} total`} sub={`${state.tcpHandshake.complete} complete`} />
          <StatCard label="Packet Chunks" value={`${state.packetChunks.chunks} chunks`} sub={`last ${state.packetChunks.lastPackets} pkts`} />
        </section>

        <section className="grid gap-4 md:grid-cols-3">
          <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
            <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Capture Quality</div>
            <KeyValueList
              items={[
                { label: 'Start', value: state.captureQuality.start },
                { label: 'End', value: state.captureQuality.end },
                { label: 'Duration', value: state.captureQuality.duration },
                { label: 'Link', value: state.captureQuality.link },
                { label: 'Snaplen', value: state.captureQuality.snaplen },
                { label: 'Promisc', value: state.captureQuality.promisc },
                { label: 'Drops', value: state.captureQuality.drops },
              ]}
              compact
            />
          </div>
          <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
            <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Decode Health</div>
            <KeyValueList
              items={[
                { label: 'Success', value: state.decodeHealth.successRate },
                { label: 'Malformed', value: state.decodeHealth.malformed },
                { label: 'Truncated', value: state.decodeHealth.truncated },
                { label: 'Unknown L3', value: state.decodeHealth.unknownL3 },
                { label: 'Unknown L4', value: state.decodeHealth.unknownL4 },
              ]}
              compact
            />
          </div>
          <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
            <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Filtering and Sampling</div>
            <KeyValueList
              items={[
                { label: 'Filter', value: state.filtering.filter },
                { label: 'Filtered out', value: state.filtering.filteredOut },
                { label: 'Sampling', value: state.filtering.sampling },
              ]}
              compact
            />
          </div>
        </section>

        <section className="grid gap-4">
          <AccordionSection
            title="Traffic overview"
            summary={`Throughput ${state.analysis.throughput.bpsNow} · Packet sizes p95 ${state.analysis.packetSizes.p95}`}
            defaultOpen
          >
            <div className="grid gap-4 md:grid-cols-3">
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Throughput</div>
                <KeyValueList
                  items={[
                    { label: 'Bps now', value: state.analysis.throughput.bpsNow },
                    { label: 'Bps avg', value: state.analysis.throughput.bpsAvg },
                    { label: 'Pps now', value: state.analysis.throughput.ppsNow },
                    { label: 'Pps avg', value: state.analysis.throughput.ppsAvg },
                    { label: 'Peak bps', value: state.analysis.throughput.peakBps },
                    { label: 'Peak pps', value: state.analysis.throughput.peakPps },
                    { label: 'Peak ts', value: state.analysis.throughput.peakTs },
                  ]}
                  compact
                />
              </div>
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Packet Size Stats</div>
                <KeyValueList
                  items={[
                    { label: 'Min', value: state.analysis.packetSizes.min },
                    { label: 'Median', value: state.analysis.packetSizes.median },
                    { label: 'p95', value: state.analysis.packetSizes.p95 },
                    { label: 'Max', value: state.analysis.packetSizes.max },
                    { label: 'Fragments', value: state.analysis.packetSizes.fragments },
                  ]}
                  compact
                />
                <div className="mt-3 text-xs text-slate-400">Histogram</div>
                <div className="mt-2 space-y-1 text-xs text-slate-300">
                  {state.analysis.packetSizes.histogram.map((bucket) => (
                    <div key={bucket.label} className="flex items-center justify-between">
                      <span>{bucket.label}</span>
                      <span>{bucket.value}%</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">L2/L3 Breakdown</div>
                <KeyValueList
                  items={[
                    { label: 'Ethernet', value: state.analysis.l2l3.ethernet },
                    { label: 'VLAN', value: state.analysis.l2l3.vlan },
                    { label: 'ARP', value: state.analysis.l2l3.arp },
                    { label: 'ICMP', value: state.analysis.l2l3.icmp },
                    { label: 'ICMPv6', value: state.analysis.l2l3.icmpv6 },
                    { label: 'Multicast', value: state.analysis.l2l3.multicast },
                    { label: 'Broadcast', value: state.analysis.l2l3.broadcast },
                  ]}
                  compact
                />
              </div>
            </div>
          </AccordionSection>

          <AccordionSection
            title="Top entities"
            summary={`Top src ${state.analysis.topEntities.srcTalkers[0]?.label} · TCP 443 ${state.analysis.topEntities.tcpPorts[0]?.value}`}
          >
            <div className="grid gap-4 lg:grid-cols-3">
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Top Talkers</div>
                <div className="mt-3 text-xs text-slate-500">Source IPs</div>
                <div className="mt-2 space-y-2">
                  {state.analysis.topEntities.srcTalkers.map((item) => (
                    <div key={item.label} className="text-sm text-slate-200">
                      <div className="flex justify-between"><span>{item.label}</span><span>{item.bytes}</span></div>
                      <div className="text-xs text-slate-400">{item.packets} pkts</div>
                    </div>
                  ))}
                </div>
                <div className="mt-4 text-xs text-slate-500">Destination IPs</div>
                <div className="mt-2 space-y-2">
                  {state.analysis.topEntities.dstTalkers.map((item) => (
                    <div key={item.label} className="text-sm text-slate-200">
                      <div className="flex justify-between"><span>{item.label}</span><span>{item.bytes}</span></div>
                      <div className="text-xs text-slate-400">{item.packets} pkts</div>
                    </div>
                  ))}
                </div>
                <div className="mt-4 text-xs text-slate-400">{state.analysis.topEntities.internalExternalSplit}</div>
              </div>
              <div className="grid gap-4">
                <TopList
                  title="Top MAC Addresses"
                  items={state.analysis.topEntities.macs.map((item) => ({ label: item.label, value: item.bytes }))}
                />
                <TopList
                  title="Vendor OUIs"
                  items={state.analysis.topEntities.macVendors}
                />
              </div>
              <div className="grid gap-4">
                <TopList
                  title="Top TCP Ports"
                  items={state.analysis.topEntities.tcpPorts}
                />
                <TopList
                  title="Top UDP Ports"
                  items={state.analysis.topEntities.udpPorts}
                />
              </div>
            </div>
          </AccordionSection>

          <AccordionSection
            title="Flow analytics"
            summary={`Flows ${state.analysis.flowAnalytics.summary.totalFlows} · New ${state.analysis.flowAnalytics.summary.newFlows}`}
          >
            <div className="grid gap-4 lg:grid-cols-3">
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Flow Summary</div>
                <KeyValueList
                  items={[
                    { label: 'Total flows', value: state.analysis.flowAnalytics.summary.totalFlows },
                    { label: 'New flows/sec', value: state.analysis.flowAnalytics.summary.newFlows },
                    { label: 'Durations', value: state.analysis.flowAnalytics.summary.duration },
                    { label: 'Bytes/flow', value: state.analysis.flowAnalytics.summary.bytesPerFlow },
                  ]}
                  compact
                />
              </div>
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Heavy Hitters</div>
                <div className="mt-2 space-y-2">
                  {state.analysis.flowAnalytics.heavyHitters.map((flow) => (
                    <div key={flow.label} className="text-sm text-slate-200">
                      <div className="truncate">{flow.label}</div>
                      <div className="text-xs text-slate-400">{flow.bytes} · {flow.packets} pkts · {flow.duration}</div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Flow States</div>
                <KeyValueList items={state.analysis.flowAnalytics.states} compact />
              </div>
            </div>
          </AccordionSection>

          <AccordionSection
            title="TCP health and behavior"
            summary={`Handshake completion ${state.analysis.tcpHealth.handshake.completionRate} · Retrans ${state.analysis.tcpHealth.reliability[0].value}`}
          >
            <div className="grid gap-4 lg:grid-cols-3">
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Handshake Detail</div>
                <KeyValueList
                  items={[
                    { label: 'SYN', value: state.analysis.tcpHealth.handshake.syn },
                    { label: 'SYN-ACK', value: state.analysis.tcpHealth.handshake.synAck },
                    { label: 'ACK', value: state.analysis.tcpHealth.handshake.ack },
                    { label: 'Completion rate', value: state.analysis.tcpHealth.handshake.completionRate },
                    { label: 'RTT median', value: state.analysis.tcpHealth.handshake.rttMedian },
                    { label: 'RTT p95', value: state.analysis.tcpHealth.handshake.rttP95 },
                  ]}
                  compact
                />
              </div>
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Reliability Indicators</div>
                <KeyValueList items={state.analysis.tcpHealth.reliability} compact />
              </div>
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">TCP Performance Signals</div>
                <KeyValueList items={state.analysis.tcpHealth.performance} compact />
              </div>
            </div>
          </AccordionSection>

          <AccordionSection
            title="UDP and DNS insights"
            summary={`UDP ${state.analysis.udpDns.udpQuality[0].value} · DNS ${state.analysis.udpDns.dnsDashboard[2].value}`}
          >
            <div className="grid gap-4 lg:grid-cols-3">
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">UDP Quality</div>
                <KeyValueList items={state.analysis.udpDns.udpQuality} compact />
              </div>
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">DNS Dashboard</div>
                <KeyValueList items={state.analysis.udpDns.dnsDashboard} compact />
              </div>
              <TopList title="Top Queried Domains" items={state.analysis.udpDns.topDomains} />
            </div>
          </AccordionSection>

          <AccordionSection
            title="Timing and burst detection"
            summary={`Peak ${state.analysis.timingBurst.burstMonitor[0].value} · Jitter ${state.analysis.timingBurst.interArrival[2].value}`}
          >
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Burst Monitor</div>
                <KeyValueList items={state.analysis.timingBurst.burstMonitor} compact />
              </div>
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Inter-arrival Stats</div>
                <KeyValueList items={state.analysis.timingBurst.interArrival} compact />
              </div>
            </div>
          </AccordionSection>

          <AccordionSection
            title="Security and anomaly signals"
            summary={`Scan ratio ${state.analysis.security.scanBehavior[2].value} · ARP changes ${state.analysis.security.arpAttacks[1].value}`}
          >
            <div className="grid gap-4 lg:grid-cols-3">
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Scan-like Behavior</div>
                <KeyValueList items={state.analysis.security.scanBehavior} compact />
              </div>
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">DNS Anomalies</div>
                <KeyValueList items={state.analysis.security.dnsAnomalies} compact />
              </div>
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">ARP and LAN Attacks</div>
                <KeyValueList items={state.analysis.security.arpAttacks} compact />
              </div>
            </div>
          </AccordionSection>

          <AccordionSection
            title="Application metadata"
            summary={`TLS ${state.analysis.appMeta.tlsMetadata[0].value} · HTTP ${state.analysis.appMeta.httpPlaintext[1].value}`}
          >
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">TLS Handshake Metadata</div>
                <KeyValueList items={state.analysis.appMeta.tlsMetadata} compact />
              </div>
              <div className="bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3">
                <div className="text-xs uppercase tracking-[0.16em] text-slate-400">HTTP Plaintext</div>
                <KeyValueList items={state.analysis.appMeta.httpPlaintext} compact />
              </div>
            </div>
          </AccordionSection>
        </section>

        <section className="grid gap-3">
          <div className="flex items-center justify-between">
            <div className="text-sm uppercase tracking-[0.2em] text-slate-400">Packet List</div>
            <button
              onClick={() => setCollapsedTable((prev) => !prev)}
              className={`${divider} rounded-lg px-3 py-2 text-xs uppercase tracking-[0.2em] text-slate-300 hover:text-white transition`}
            >
              {collapsedTable ? 'Expand Packet List' : 'Collapse Packet List'}
            </button>
          </div>
          <PacketTable rows={state.packets} collapsed={collapsedTable} />
        </section>
      </div>
    </div>
  );
}
