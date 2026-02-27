// popup.js

document.addEventListener('DOMContentLoaded', async () => {
  const statusCard  = document.getElementById('statusCard');
  const statusIcon  = document.getElementById('statusIcon');
  const statusTitle = document.getElementById('statusTitle');
  const statusSub   = document.getElementById('statusSub');

  // ── Get current tab ───────────────────────────────────────
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (tab?.url) {
    try {
      const url = new URL(tab.url);
      document.getElementById('currentDomain').textContent = url.hostname || '—';
    } catch {
      document.getElementById('currentDomain').textContent = 'N/A';
    }
  }

  // ── Check warning status for this tab ────────────────────
  chrome.storage.session.get([`warning_${tab.id}`], data => {
    const warning = data[`warning_${tab.id}`];
    if (warning) {
      statusCard.className  = 'status danger';
      statusIcon.textContent  = '🚨';
      statusTitle.textContent = 'Threat Detected!';
      statusSub.textContent   = `Looks like "${warning.lookalike}"`;
    } else {
      statusCard.className  = 'status safe';
      statusIcon.textContent  = '✅';
      statusTitle.textContent = 'Site Looks Safe';
      statusSub.textContent   = 'No threats detected';
    }
  });

  // ── Load stats ────────────────────────────────────────────
  chrome.storage.local.get(
    ['totalBlocked', 'totalProceeded', 'whitelist'],
    data => {
      document.getElementById('totalBlocked').textContent   = data.totalBlocked   || 0;
      document.getElementById('totalProceeded').textContent = data.totalProceeded || 0;
      document.getElementById('whitelistCount').textContent = (data.whitelist || []).length;
    }
  );

  // ── Dashboard button ──────────────────────────────────────
  document.getElementById('openDashboard').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
  });

  // ── Whitelist manager ─────────────────────────────────────
  document.getElementById('manageWhitelist').addEventListener('click', () => {
    chrome.storage.local.get(['whitelist'], data => {
      const list = data.whitelist || [];
      if (list.length === 0) {
        alert('Your whitelist is empty.\n\nDomains you choose to trust on the warning page will appear here.');
        return;
      }
      const formatted = list.map((d, i) => `${i + 1}. ${d}`).join('\n');
      const ok = confirm(`Whitelisted Domains:\n\n${formatted}\n\nClick OK to CLEAR the entire whitelist.`);
      if (ok) {
        chrome.storage.local.set({ whitelist: [] }, () => {
          document.getElementById('whitelistCount').textContent = 0;
          alert('Whitelist cleared!');
        });
      }
    });
  });
});
