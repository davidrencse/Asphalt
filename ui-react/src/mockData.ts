import { DashboardState, PacketRow } from './types';

const basePackets: PacketRow[] = [
  {
    id: 1201,
    time: '14:21:05.192',
    stack: 'ETH/IP4/UDP',
    src: '192.168.0.14',
    dst: '224.0.0.251',
    ports: '5353 -> 5353',
    l4: 'UDP',
    flags: '-',
    quality: 'OK',
  },
  {
    id: 1202,
    time: '14:21:05.225',
    stack: 'ETH/IP4/TCP',
    src: '192.168.0.14',
    dst: '34.120.32.2',
    ports: '53144 -> 443',
    l4: 'TCP',
    flags: 'SYN',
    quality: 'OK',
  },
  {
    id: 1203,
    time: '14:21:05.255',
    stack: 'ETH/IP4/TCP',
    src: '34.120.32.2',
    dst: '192.168.0.14',
    ports: '443 -> 53144',
    l4: 'TCP',
    flags: 'SYN,ACK',
    quality: 'OK',
  },
  {
    id: 1204,
    time: '14:21:05.266',
    stack: 'ETH/IP4/TCP',
    src: '192.168.0.14',
    dst: '34.120.32.2',
    ports: '53144 -> 443',
    l4: 'TCP',
    flags: 'ACK',
    quality: 'OK',
  },
  {
    id: 1205,
    time: '14:21:05.312',
    stack: 'ETH/IP4/UDP',
    src: '192.168.0.14',
    dst: '8.8.8.8',
    ports: '54231 -> 53',
    l4: 'UDP',
    flags: '-',
    quality: 'OK',
  },
];

const protocols = ['TCP', 'UDP', 'UDP', 'UDP', 'TCP', 'UDP', 'TCP', 'UDP'] as const;

export function createInitialState(): DashboardState {
  return {
    packets: [...basePackets],
    stats: {
      packetCount: 1402,
      ipv4Count: 1360,
      ipv6Count: 42,
      tcpCount: 402,
      udpCount: 960,
      flowCount: 132,
    },
    protocolMix: {
      tcpPct: 28,
      udpPct: 68,
      unknownPct: 4,
    },
    abnormal: {
      summary: 'None',
      details: ['No abnormal activity detected'],
    },
    tcpHandshake: {
      total: 54,
      complete: 49,
    },
    packetChunks: {
      chunks: 14,
      lastPackets: 200,
    },
    captureQuality: {
      start: '14:20:12.003',
      end: '14:21:05.312',
      duration: '53.3s',
      link: 'Ethernet',
      snaplen: '65535',
      promisc: 'true',
      drops: '0 (0.00%)',
    },
    decodeHealth: {
      successRate: '98.6%',
      malformed: '9',
      truncated: '4',
      unknownL3: '2',
      unknownL4: '6',
    },
    filtering: {
      filter: 'udp port 53 or tcp port 443',
      filteredOut: '124',
      sampling: 'None',
    },
    analysis: {
      throughput: {
        bpsNow: '18.4 Mbps',
        bpsAvg: '12.1 Mbps',
        ppsNow: '3,820',
        ppsAvg: '2,940',
        peakBps: '41.2 Mbps',
        peakPps: '6,900',
        peakTs: '14:20:54.122',
      },
      packetSizes: {
        min: '64 B',
        median: '312 B',
        p95: '1,472 B',
        max: '9,014 B',
        histogram: [
          { label: '0-128B', value: 32 },
          { label: '128-512B', value: 44 },
          { label: '512-1024B', value: 16 },
          { label: '1024-1518B', value: 8 },
        ],
        fragments: '2 (IPv4), 0 (IPv6)',
      },
      l2l3: {
        ethernet: '1,362',
        vlan: '24',
        arp: '16',
        icmp: '11',
        icmpv6: '8',
        multicast: '148',
        broadcast: '42',
      },
      topEntities: {
        srcTalkers: [
          { label: '192.168.0.14', packets: '502', bytes: '22.1MB' },
          { label: '192.168.0.12', packets: '320', bytes: '8.6MB' },
          { label: '192.168.0.1', packets: '210', bytes: '6.1MB' },
        ],
        dstTalkers: [
          { label: '8.8.8.8', packets: '298', bytes: '3.2MB' },
          { label: '34.120.32.2', packets: '188', bytes: '10.2MB' },
          { label: '224.0.0.251', packets: '182', bytes: '1.1MB' },
        ],
        internalExternalSplit: 'Internal 62% / External 38%',
        macs: [
          { label: 'CC:98:8B:2A:4C:11', packets: '490', bytes: '21.4MB' },
          { label: 'B0:AA:36:14:9D:20', packets: '310', bytes: '8.0MB' },
          { label: 'F4:9D:EF:01:2B:9C', packets: '204', bytes: '6.7MB' },
        ],
        macVendors: [
          { label: 'Apple', value: '44%' },
          { label: 'Google', value: '18%' },
          { label: 'Dell', value: '12%' },
        ],
        tcpPorts: [
          { label: '443 (HTTPS)', value: '62%' },
          { label: '80 (HTTP)', value: '12%' },
          { label: '22 (SSH)', value: '5%' },
        ],
        udpPorts: [
          { label: '53 (DNS)', value: '34%' },
          { label: '5353 (mDNS)', value: '24%' },
          { label: '123 (NTP)', value: '9%' },
        ],
      },
      flowAnalytics: {
        summary: {
          totalFlows: '132',
          newFlows: '3.2/s',
          duration: 'median 2.1s, p95 16.2s',
          bytesPerFlow: 'avg 182KB, p95 1.2MB',
        },
        heavyHitters: [
          { label: '192.168.0.14:53144 -> 34.120.32.2:443', bytes: '9.1MB', packets: '180', duration: '14.3s' },
          { label: '192.168.0.12:51422 -> 52.43.112.8:443', bytes: '6.2MB', packets: '142', duration: '11.8s' },
          { label: '192.168.0.1:1900 -> 239.255.255.250:1900', bytes: '1.6MB', packets: '220', duration: '40.3s' },
        ],
        states: [
          { label: 'TCP Established', value: '44' },
          { label: 'TCP Half-open', value: '5' },
          { label: 'TCP Reset/Failed', value: '3' },
          { label: 'UDP Paired', value: '56' },
          { label: 'UDP Unpaired', value: '24' },
        ],
      },
      tcpHealth: {
        handshake: {
          syn: '58',
          synAck: '54',
          ack: '49',
          completionRate: '90.7%',
          rttMedian: '28ms',
          rttP95: '120ms',
        },
        reliability: [
          { label: 'Retransmissions', value: '12 (2.1%)' },
          { label: 'Out-of-order', value: '7' },
          { label: 'Dup ACKs', value: '21' },
          { label: 'RST', value: '5 (0.9%)' },
        ],
        performance: [
          { label: 'Window median', value: '256KB' },
          { label: 'Window p95', value: '1.2MB' },
          { label: 'Zero-window', value: '0' },
          { label: 'MSS top', value: '1460 (82%)' },
        ],
      },
      udpDns: {
        udpQuality: [
          { label: 'UDP rate', value: '2.4k pps / 9.1 Mbps' },
          { label: 'Largest flow', value: '192.168.0.14 -> 224.0.0.251 (1.1MB)' },
          { label: 'Burstiness', value: '0.62 (moderate)' },
        ],
        dnsDashboard: [
          { label: 'Queries', value: '221' },
          { label: 'Responses', value: '214' },
          { label: 'Response rate', value: '96.8%' },
          { label: 'NXDOMAIN', value: '6 (2.7%)' },
          { label: 'Avg latency', value: '18ms' },
        ],
        topDomains: [
          { label: 'api.apple.com', value: '44' },
          { label: 'clients4.google.com', value: '31' },
          { label: 'time.cloudflare.com', value: '18' },
        ],
      },
      timingBurst: {
        burstMonitor: [
          { label: 'Peak PPS', value: '6,900 @ 14:20:54.122' },
          { label: 'Peak BPS', value: '41.2 Mbps @ 14:20:54.122' },
          { label: 'Burst events', value: '7' },
        ],
        interArrival: [
          { label: 'Median', value: '0.5ms' },
          { label: 'p95', value: '6.2ms' },
          { label: 'Jitter', value: '1.1ms' },
        ],
      },
      security: {
        scanBehavior: [
          { label: 'Distinct dst ports/src', value: 'max 41 (192.168.0.12)' },
          { label: 'Distinct dst IPs/src', value: 'max 23 (192.168.0.14)' },
          { label: 'SYN:SYN-ACK ratio', value: '1.12' },
        ],
        dnsAnomalies: [
          { label: 'High-entropy domains', value: '2' },
          { label: 'Long labels', value: '4' },
          { label: 'NXDOMAIN spike', value: 'None' },
        ],
        arpAttacks: [
          { label: 'IP claimed by multiple MACs', value: '0' },
          { label: 'Frequent ARP changes', value: '1' },
        ],
      },
      appMeta: {
        tlsMetadata: [
          { label: 'SNI count', value: '24' },
          { label: 'Top SNI', value: 'api.apple.com (7)' },
          { label: 'ALPN', value: 'h2 68%, http/1.1 32%' },
          { label: 'TLS version', value: '1.3 74%, 1.2 26%' },
        ],
        httpPlaintext: [
          { label: 'Hosts', value: '12' },
          { label: 'Methods', value: 'GET 61%, POST 24%' },
          { label: 'Status', value: '200 91%, 404 4%' },
          { label: 'Slowest', value: '/upload 1.2s' },
        ],
      },
    },
  };
}

export function generatePacket(seedId: number, baseTime: Date): PacketRow {
  const proto = protocols[seedId % protocols.length];
  const isTcp = proto === 'TCP';
  const src = seedId % 2 === 0 ? '192.168.0.14' : '192.168.0.12';
  const dst = isTcp ? '34.120.32.2' : '224.0.0.251';
  const ports = isTcp ? `${53000 + (seedId % 500)} -> 443` : '5353 -> 5353';
  const flags = isTcp ? (seedId % 3 === 0 ? 'PSH,ACK' : 'ACK') : '-';
  const time = new Date(baseTime.getTime() + seedId * 40).toTimeString().slice(0, 8) + '.' + String(seedId % 1000).padStart(3, '0');

  return {
    id: seedId,
    time,
    stack: `ETH/IP4/${proto}`,
    src,
    dst,
    ports,
    l4: proto,
    flags,
    quality: 'OK',
  };
}

export function simulateUpdate(prev: DashboardState): DashboardState {
  const nextId = prev.packets.length ? prev.packets[0].id + prev.packets.length + 1 : 1400;
  const now = new Date();
  const newPackets = [
    generatePacket(nextId, now),
    generatePacket(nextId + 1, now),
    generatePacket(nextId + 2, now),
  ];

  const packets = [...newPackets, ...prev.packets].slice(0, 200);
  const addedTcp = newPackets.filter((p) => p.l4 === 'TCP').length;
  const addedUdp = newPackets.filter((p) => p.l4 === 'UDP').length;

  const packetCount = prev.stats.packetCount + newPackets.length;
  const tcpCount = prev.stats.tcpCount + addedTcp;
  const udpCount = prev.stats.udpCount + addedUdp;

  return {
    ...prev,
    packets,
    stats: {
      ...prev.stats,
      packetCount,
      tcpCount,
      udpCount,
      flowCount: prev.stats.flowCount + (Math.random() > 0.7 ? 1 : 0),
    },
    protocolMix: {
      tcpPct: Math.min(90, Math.max(10, Math.round((tcpCount / packetCount) * 100))),
      udpPct: Math.min(90, Math.max(5, Math.round((udpCount / packetCount) * 100))),
      unknownPct: Math.max(0, 100 - Math.round((tcpCount / packetCount) * 100) - Math.round((udpCount / packetCount) * 100)),
    },
    tcpHandshake: {
      total: prev.tcpHandshake.total + (Math.random() > 0.5 ? 1 : 0),
      complete: prev.tcpHandshake.complete + (Math.random() > 0.7 ? 1 : 0),
    },
    packetChunks: {
      chunks: prev.packetChunks.chunks + (Math.random() > 0.8 ? 1 : 0),
      lastPackets: 200,
    },
    abnormal: {
      summary: Math.random() > 0.96 ? 'Potential scan detected' : 'None',
      details: prev.abnormal.details,
    },
  };
}
