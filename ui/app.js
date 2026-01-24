const backendSelect = document.getElementById('backendSelect');
const interfaceInput = document.getElementById('interfaceInput');
const durationInput = document.getElementById('durationInput');
const limitInput = document.getElementById('limitInput');
const startBtn = document.getElementById('startBtn');
const filterInput = document.getElementById('filterInput');
const tableBody = document.getElementById('tableBody');
const statusEl = document.getElementById('status');
const footerStatus = document.getElementById('footerStatus');

const statPackets = document.getElementById('statPackets');
const statIp = document.getElementById('statIp');
const statL4 = document.getElementById('statL4');
const statFlows = document.getElementById('statFlows');
const protocolMixEl = document.getElementById('protocolMix');
const abnormalSummaryEl = document.getElementById('abnormalSummary');
const handshakeSummaryEl = document.getElementById('handshakeSummary');
const chunkSummaryEl = document.getElementById('chunkSummary');
const throughputSummaryEl = document.getElementById('throughputSummary');
const packetSizeSummaryEl = document.getElementById('packetSizeSummary');
const l2l3SummaryEl = document.getElementById('l2l3Summary');
const captureQualityEl = document.getElementById('captureQuality');
const decodeHealthEl = document.getElementById('decodeHealth');
const filteringSamplingEl = document.getElementById('filteringSampling');

let allRows = [];

function formatNumber(value, digits = 2) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  const fixed = Number(value).toFixed(digits);
  return fixed.replace(/\.00$/, '');
}

function formatCount(value) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  return Math.round(Number(value)).toLocaleString('en-US');
}

function formatBps(value) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
  let v = Number(value);
  let idx = 0;
  while (v >= 1000 && idx < units.length - 1) {
    v /= 1000;
    idx += 1;
  }
  return `${formatNumber(v, 2)} ${units[idx]}`;
}

function formatPps(value) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  const units = ['pps', 'Kpps', 'Mpps', 'Gpps'];
  let v = Number(value);
  let idx = 0;
  while (v >= 1000 && idx < units.length - 1) {
    v /= 1000;
    idx += 1;
  }
  return `${formatNumber(v, 2)} ${units[idx]}`;
}

function formatBytes(value) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  const units = ['B', 'KB', 'MB', 'GB'];
  let v = Number(value);
  let idx = 0;
  while (v >= 1024 && idx < units.length - 1) {
    v /= 1024;
    idx += 1;
  }
  return `${formatNumber(v, idx === 0 ? 0 : 2)} ${units[idx]}`;
}

function formatTimestampUtc(tsUs) {
  if (!tsUs) return 'n/a';
  const ms = Math.floor(Number(tsUs) / 1000);
  const date = new Date(ms);
  const pad = (num, size = 2) => String(num).padStart(size, '0');
  const hh = pad(date.getUTCHours());
  const mm = pad(date.getUTCMinutes());
  const ss = pad(date.getUTCSeconds());
  const msStr = pad(date.getUTCMilliseconds(), 3);
  return `${hh}:${mm}:${ss}.${msStr}Z`;
}

function setStatus(text) {
  statusEl.textContent = text;
  footerStatus.textContent = text;
}

function toRow(packet) {
  const ports = packet.src_port != null && packet.dst_port != null
    ? `${packet.src_port}->${packet.dst_port}`
    : '-';
  const flags = Array.isArray(packet.tcp_flags_names) && packet.tcp_flags_names.length
    ? packet.tcp_flags_names.join(',')
    : '-';
  const quality = Array.isArray(packet.quality_names) && packet.quality_names.length
    ? packet.quality_names.join(',')
    : '-';

  return {
    id: packet.packet_id ?? '-',
    time: packet.timestamp_us ?? '-',
    stack: packet.stack_summary ?? '-',
    src: packet.src_ip ?? '-',
    dst: packet.dst_ip ?? '-',
    ports,
    l4: packet.l4_protocol ?? '-',
    flags,
    quality,
    raw: packet,
  };
}

function render(rows) {
  tableBody.innerHTML = rows.map((row) => `
    <tr>
      <td>${row.id}</td>
      <td>${row.time}</td>
      <td>${row.stack}</td>
      <td>${row.src}</td>
      <td>${row.dst}</td>
      <td>${row.ports}</td>
      <td>${row.l4}</td>
      <td>${row.flags}</td>
      <td>${row.quality}</td>
    </tr>
  `).join('');
}

function updateStats(rows) {
  const ipv4 = rows.filter((r) => r.raw.ip_version === 4).length;
  const ipv6 = rows.filter((r) => r.raw.ip_version === 6).length;
  const tcp = rows.filter((r) => r.raw.l4_protocol === 'TCP').length;
  const udp = rows.filter((r) => r.raw.l4_protocol === 'UDP').length;
  const flows = new Set();

  rows.forEach((r) => {
    const key = r.raw.flow_key;
    if (Array.isArray(key) && key.length === 5) {
      flows.add(key.join(':'));
    }
  });

  statPackets.textContent = rows.length.toString();
  statIp.textContent = `${ipv4} / ${ipv6}`;
  statL4.textContent = `${tcp} / ${udp}`;
  statFlows.textContent = flows.size.toString();
}

function applyFilter() {
  const value = filterInput.value.trim().toLowerCase();
  if (!value) {
    render(allRows);
    updateStats(allRows);
    return;
  }
  const filtered = allRows.filter((row) => {
    const raw = row.raw;
    const haystack = [
      row.stack,
      row.src,
      row.dst,
      row.ports,
      row.l4,
      row.flags,
      row.quality,
      raw.flow_key ? raw.flow_key.join(':') : '',
    ].join(' ').toLowerCase();
    return haystack.includes(value);
  });
  render(filtered);
  updateStats(filtered);
}

function loadPackets(packets, analysis) {
  allRows = packets.map(toRow);
  render(allRows);
  updateStats(allRows);
  setStatus(`Loaded ${allRows.length} packets`);
  renderAnalysis(analysis);
}

async function runCapture() {
  const backend = backendSelect.value;
  const iface = interfaceInput.value.trim();
  const duration = Number(durationInput.value || 0);
  const limit = Number(limitInput.value || 0);

  const params = new URLSearchParams();
  params.set('backend', backend);
  if (iface) params.set('interface', iface);
  if (duration > 0) params.set('duration', String(duration));
  if (limit > 0) params.set('limit', String(limit));
  params.set('analysis', '1');

  setStatus('Capturing...');
  try {
    const response = await fetch(`/capture?${params.toString()}`);
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `HTTP ${response.status}`);
    }
    const payload = await response.json();
    const packets = Array.isArray(payload) ? payload : (payload.packets || []);
    const analysis = Array.isArray(payload) ? null : (payload.analysis || null);
    loadPackets(packets, analysis);
  } catch (err) {
    setStatus(`Capture failed: ${err.message}`);
  }
}

function renderAnalysis(analysis) {
  if (!analysis) {
    protocolMixEl.textContent = '-';
    abnormalSummaryEl.textContent = '-';
    handshakeSummaryEl.textContent = '-';
    chunkSummaryEl.textContent = '-';
    throughputSummaryEl.textContent = '-';
    packetSizeSummaryEl.textContent = '-';
    l2l3SummaryEl.textContent = '-';
    captureQualityEl.textContent = '-';
    decodeHealthEl.textContent = '-';
    filteringSamplingEl.textContent = '-';
    return;
  }

  const protocol = analysis.global_results?.protocol_mix;
  if (protocol && protocol.protocol_percentages) {
    const parts = Object.entries(protocol.protocol_percentages)
      .map(([key, value]) => `${key}: ${value}%`)
      .join('\n');
    protocolMixEl.textContent = parts || '-';
  } else {
    protocolMixEl.textContent = '-';
  }

  const abnormal = analysis.global_results?.abnormal_activity;
  if (abnormal) {
    const findings = abnormal.findings || [];
    if (findings.length === 0) {
      abnormalSummaryEl.textContent = 'No abnormal activity detected';
    } else {
      const lines = findings.map((finding) => {
        if (finding.type === 'possible_port_scan') {
          return `possible_port_scan (${finding.sources.length} sources)`;
        }
        if (finding.type === 'high_tcp_rst_ratio') {
          return `high_tcp_rst_ratio (${finding.ratio})`;
        }
        return `${finding.type}`;
      });
      abnormalSummaryEl.textContent = lines.join('\n');
    }
  } else {
    abnormalSummaryEl.textContent = '-';
  }

  const handshakes = analysis.global_results?.tcp_handshakes;
  if (handshakes) {
    handshakeSummaryEl.textContent =
      `total: ${handshakes.handshakes_total}\n` +
      `complete: ${handshakes.handshakes_complete}\n` +
      `incomplete: ${handshakes.handshakes_incomplete}`;
  } else {
    handshakeSummaryEl.textContent = '-';
  }

  const chunks = analysis.time_series?.packet_chunks;
  if (chunks) {
    const list = chunks.chunks || [];
    if (list.length === 0) {
      chunkSummaryEl.textContent = 'No chunks';
    } else {
      const last = list[list.length - 1];
      chunkSummaryEl.textContent =
        `chunks: ${list.length}\n` +
        `last packets: ${last.packets}\n` +
        `last bytes: ${last.bytes_captured}`;
    }
  } else {
    chunkSummaryEl.textContent = '-';
  }

  const throughput = analysis.global_results?.throughput_peaks;
  if (throughput) {
    throughputSummaryEl.textContent = [
      `bps_now: ${formatBps(throughput.bps_now)}`,
      `bps_avg: ${formatBps(throughput.bps_avg)}`,
      `pps_now: ${formatPps(throughput.pps_now)}`,
      `pps_avg: ${formatPps(throughput.pps_avg)}`,
      `peak_bps: ${formatBps(throughput.peak_bps)}`,
      `peak_pps: ${formatPps(throughput.peak_pps)}`,
      `peak_bps_ts: ${formatTimestampUtc(throughput.peak_bps_timestamp)}`,
      `peak_pps_ts: ${formatTimestampUtc(throughput.peak_pps_timestamp)}`,
    ].join('\n');
  } else {
    throughputSummaryEl.textContent = '-';
  }

  const sizeStats = analysis.global_results?.packet_size_stats;
  if (sizeStats) {
    const captured = sizeStats.captured_length || {};
    const original = sizeStats.original_length || {};
    const hist = sizeStats.histogram || {};
    packetSizeSummaryEl.textContent = [
      `cap min/med/p95/max: ${formatBytes(captured.min)} / ${formatBytes(captured.median)} / ${formatBytes(captured.p95)} / ${formatBytes(captured.max)}`,
      `orig min/med/p95/max: ${formatBytes(original.min)} / ${formatBytes(original.median)} / ${formatBytes(original.p95)} / ${formatBytes(original.max)}`,
      `hist 0-63: ${formatCount(hist['0-63'] ?? 0)}, 64-127: ${formatCount(hist['64-127'] ?? 0)}`,
      `hist 128-511: ${formatCount(hist['128-511'] ?? 0)}, 512-1023: ${formatCount(hist['512-1023'] ?? 0)}`,
      `hist 1024-1514: ${formatCount(hist['1024-1514'] ?? 0)}, jumbo: ${formatCount(hist.jumbo ?? 0)}`,
      `frags v4/v6: ${formatCount(sizeStats.fragments?.ipv4_fragments ?? 0)} / ${formatCount(sizeStats.fragments?.ipv6_fragments ?? 0)}`,
    ].join('\n');
  } else {
    packetSizeSummaryEl.textContent = '-';
  }

  const l2l3 = analysis.global_results?.l2_l3_breakdown;
  if (l2l3) {
    l2l3SummaryEl.textContent = [
      `ethernet: ${formatCount(l2l3.ethernet_frames ?? 0)}`,
      `vlan: ${formatCount(l2l3.vlan_frames ?? 0)}`,
      `arp: ${formatCount(l2l3.arp_packets ?? 0)}`,
      `icmp: ${formatCount(l2l3.icmp_packets ?? 0)}`,
      `icmpv6: ${formatCount(l2l3.icmpv6_packets ?? 0)}`,
      `multicast: ${formatCount(l2l3.multicast_packets ?? 0)}`,
      `broadcast: ${formatCount(l2l3.broadcast_packets ?? 0)}`,
    ].join('\n');
  } else {
    l2l3SummaryEl.textContent = '-';
  }

  const health = analysis.global_results?.capture_health;
  if (health) {
    const quality = health.capture_quality || {};
    const session = quality.session || {};
    const drops = quality.drops || {};
    captureQualityEl.textContent = [
      `start: ${session.capture_start_us ?? 'n/a'}`,
      `end: ${session.capture_end_us ?? 'n/a'}`,
      `duration_us: ${session.duration_us ?? 'n/a'}`,
      `link_types: ${Array.isArray(session.link_types) ? session.link_types.join(',') : (session.link_types ?? 'n/a')}`,
      `snaplen: ${session.snaplen ?? 'n/a'}`,
      `promisc: ${session.promiscuous ?? 'n/a'}`,
      `drops: ${drops.dropped_packets ?? 'n/a'}`,
      `drop_rate: ${drops.drop_rate ?? 'n/a'}`,
      `kernel_drops: ${drops.kernel_drops ?? 'n/a'}`,
    ].join('\n');

    const decode = health.decode_health || {};
    decodeHealthEl.textContent = [
      `decode_success_rate: ${decode.decode_success_rate ?? 'n/a'}`,
      `malformed: ${decode.malformed_packets ?? 'n/a'}`,
      `truncated: ${decode.truncated_packets ?? 'n/a'}`,
      `unknown_l3: ${decode.unknown_l3_packets ?? 'n/a'}`,
      `unknown_l4: ${decode.unknown_l4_packets ?? 'n/a'}`,
    ].join('\n');

    const filtering = health.filtering_sampling || {};
    filteringSamplingEl.textContent = [
      `filter: ${filtering.capture_filter ?? 'n/a'}`,
      `filtered_out: ${filtering.packets_filtered_out ?? 'n/a'}`,
      `sampling_rate: ${filtering.sampling_rate ?? 'n/a'}`,
    ].join('\n');
  } else {
    captureQualityEl.textContent = '-';
    decodeHealthEl.textContent = '-';
    filteringSamplingEl.textContent = '-';
  }
}

startBtn.addEventListener('click', runCapture);
filterInput.addEventListener('input', applyFilter);

// Auto-run on page load
runCapture();
