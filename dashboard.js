// dashboard.js

function loadDashboard() {
  chrome.storage.local.get(
    ['threatHistory', 'totalBlocked', 'totalProceeded', 'whitelist'],
    data => {
      const history   = data.threatHistory || [];
      const whitelist = data.whitelist     || [];

      // ── Stats ──────────────────────────────────────────────
      document.getElementById('totalBlocked').textContent   = data.totalBlocked   || 0;
      document.getElementById('totalProceeded').textContent = data.totalProceeded || 0;
      document.getElementById('whitelistCount').textContent = whitelist.length;
      document.getElementById('historyCount').textContent   = history.length;
      document.getElementById('lastUpdated').textContent    =
        'Updated ' + new Date().toLocaleString();

      // ── History table ──────────────────────────────────────
      const tbody = document.getElementById('historyBody');
      const empty = document.getElementById('emptyHistory');

      if (history.length === 0) {
        tbody.innerHTML   = '';
        empty.style.display = 'block';
      } else {
        empty.style.display = 'none';
        tbody.innerHTML = [...history].reverse().map(item => `
          <tr>
            <td class="td-sus">${item.suspicious || '—'}</td>
            <td class="td-lk">${item.lookalike   || '—'}</td>
            <td>${renderBadge(item.detectedBy)}</td>
            <td style="font-family:'Space Mono',monospace; font-size:12px; color:${item.vtMalicious > 0 ? 'var(--red)' : 'var(--muted)'}">
              ${item.vtMalicious != null ? `${item.vtMalicious}/${item.vtTotal}` : '—'}
            </td>
            <td style="font-family:'Space Mono',monospace; font-size:12px; color:${item.ageRisk === 'critical' ? 'var(--red)' : item.ageRisk === 'high' ? 'var(--yellow)' : 'var(--muted)'}">
              ${item.domainAge != null ? `${item.domainAge}d` : '—'}
            </td>
            <td style="font-size:12px">${new Date(item.timestamp).toLocaleString()}</td>
          </tr>
        `).join('');
      }

      // ── Whitelist chips ────────────────────────────────────
      const chips = document.getElementById('whitelistChips');
      if (whitelist.length === 0) {
        chips.innerHTML = '<div style="color:var(--border); font-size:13px">No whitelisted domains.</div>';
      } else {
        chips.innerHTML = whitelist.map(domain => `
          <div class="chip">
            ${domain}
            <button class="chip-remove" onclick="removeDomain('${domain}')" title="Remove">✕</button>
          </div>
        `).join('');
      }
    }
  );
}

function renderBadge(source) {
  if (source === 'both')
    return '<span class="badge badge-both">🔴 Both</span>';
  if (source === 'virustotal')
    return '<span class="badge badge-vt">🔬 VirusTotal</span>';
  return '<span class="badge badge-lev">📏 Similarity</span>';
}

function removeDomain(domain) {
  chrome.storage.local.get(['whitelist'], data => {
    const updated = (data.whitelist || []).filter(d => d !== domain);
    chrome.storage.local.set({ whitelist: updated }, loadDashboard);
  });
}

document.getElementById('clearHistory').addEventListener('click', () => {
  if (confirm('Clear all threat history? This cannot be undone.')) {
    chrome.storage.local.set({
      threatHistory: [], totalBlocked: 0, totalProceeded: 0
    }, loadDashboard);
  }
});

document.getElementById('clearWhitelist').addEventListener('click', () => {
  if (confirm('Remove all whitelisted domains?')) {
    chrome.storage.local.set({ whitelist: [] }, loadDashboard);
  }
});

document.addEventListener('DOMContentLoaded', loadDashboard);
