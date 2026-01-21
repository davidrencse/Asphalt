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

let allRows = [];

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

function loadPackets(packets) {
  allRows = packets.map(toRow);
  render(allRows);
  updateStats(allRows);
  setStatus(`Loaded ${allRows.length} packets`);
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

  setStatus('Capturing...');
  try {
    const response = await fetch(`/capture?${params.toString()}`);
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `HTTP ${response.status}`);
    }
    const packets = await response.json();
    loadPackets(packets);
  } catch (err) {
    setStatus(`Capture failed: ${err.message}`);
  }
}

startBtn.addEventListener('click', runCapture);
filterInput.addEventListener('input', applyFilter);

// Auto-run on page load
runCapture();
