export type L4Protocol = 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | 'ARP' | 'UNKNOWN';

export interface PacketRow {
  id: number;
  time: string;
  stack: string;
  src: string;
  dst: string;
  ports: string;
  l4: L4Protocol;
  flags: string;
  quality: string;
}

export interface StatTile {
  label: string;
  value: string;
  sub?: string;
}

export interface ProtocolMix {
  tcpPct: number;
  udpPct: number;
  unknownPct: number;
}

export interface AbnormalActivity {
  summary: string;
  details: string[];
}

export interface TcpHandshakeSummary {
  total: number;
  complete: number;
}

export interface PacketChunksSummary {
  chunks: number;
  lastPackets: number;
}

export interface CaptureQuality {
  start: string;
  end: string;
  duration: string;
  link: string;
  snaplen: string;
  promisc: string;
  drops: string;
}

export interface DecodeHealth {
  successRate: string;
  malformed: string;
  truncated: string;
  unknownL3: string;
  unknownL4: string;
}

export interface FilteringSampling {
  filter: string;
  filteredOut: string;
  sampling: string;
}

export interface ThroughputStats {
  bpsNow: string;
  bpsAvg: string;
  ppsNow: string;
  ppsAvg: string;
  peakBps: string;
  peakPps: string;
  peakTs: string;
}

export interface PacketSizeStats {
  min: string;
  median: string;
  p95: string;
  max: string;
  histogram: { label: string; value: number }[];
  fragments: string;
}

export interface L2L3Breakdown {
  ethernet: string;
  vlan: string;
  arp: string;
  icmp: string;
  icmpv6: string;
  multicast: string;
  broadcast: string;
}

export interface TopEntity {
  label: string;
  packets: string;
  bytes: string;
}

export interface TopEntities {
  srcTalkers: TopEntity[];
  dstTalkers: TopEntity[];
  internalExternalSplit: string;
  macs: TopEntity[];
  macVendors: { label: string; value: string }[];
  tcpPorts: { label: string; value: string }[];
  udpPorts: { label: string; value: string }[];
}

export interface FlowSummaryStats {
  totalFlows: string;
  newFlows: string;
  duration: string;
  bytesPerFlow: string;
}

export interface HeavyHitterFlow {
  label: string;
  bytes: string;
  packets: string;
  duration: string;
}

export interface FlowAnalytics {
  summary: FlowSummaryStats;
  heavyHitters: HeavyHitterFlow[];
  states: { label: string; value: string }[];
}

export interface TcpHealth {
  handshake: {
    syn: string;
    synAck: string;
    ack: string;
    completionRate: string;
    rttMedian: string;
    rttP95: string;
  };
  reliability: { label: string; value: string }[];
  performance: { label: string; value: string }[];
}

export interface UdpDnsInsights {
  udpQuality: { label: string; value: string }[];
  dnsDashboard: { label: string; value: string }[];
  topDomains: { label: string; value: string }[];
}

export interface TimingBurstDetection {
  burstMonitor: { label: string; value: string }[];
  interArrival: { label: string; value: string }[];
}

export interface SecurityAnomalies {
  scanBehavior: { label: string; value: string }[];
  dnsAnomalies: { label: string; value: string }[];
  arpAttacks: { label: string; value: string }[];
}

export interface AppMetadata {
  tlsMetadata: { label: string; value: string }[];
  httpPlaintext: { label: string; value: string }[];
}

export interface AnalysisSections {
  throughput: ThroughputStats;
  packetSizes: PacketSizeStats;
  l2l3: L2L3Breakdown;
  topEntities: TopEntities;
  flowAnalytics: FlowAnalytics;
  tcpHealth: TcpHealth;
  udpDns: UdpDnsInsights;
  timingBurst: TimingBurstDetection;
  security: SecurityAnomalies;
  appMeta: AppMetadata;
}

export interface DashboardState {
  packets: PacketRow[];
  stats: {
    packetCount: number;
    ipv4Count: number;
    ipv6Count: number;
    tcpCount: number;
    udpCount: number;
    flowCount: number;
  };
  protocolMix: ProtocolMix;
  abnormal: AbnormalActivity;
  tcpHandshake: TcpHandshakeSummary;
  packetChunks: PacketChunksSummary;
  captureQuality: CaptureQuality;
  decodeHealth: DecodeHealth;
  filtering: FilteringSampling;
  analysis: AnalysisSections;
}
