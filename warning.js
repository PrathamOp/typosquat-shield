// warning.js — Populates the warning page with threat data

const p = new URLSearchParams(window.location.search);

const suspicious    = p.get('suspicious')   || 'Unknown';
const lookalike     = p.get('lookalike')    || 'Unknown';
const distance      = p.get('distance')     || 'N/A';
const hasHomoglyphs = p.get('homoglyphs')   === 'true';
const originalUrl   = p.get('original')     || null;
const vtStatus      = p.get('vtStatus')     || 'skipped';
const vtMalicious   = parseInt(p.get('vtMalicious') || '0');
const vtTotal       = parseInt(p.get('vtTotal')     || '0');
const detectedBy    = p.get('detectedBy')   || 'levenshtein';
const domainAge     = p.get('domainAge')    || null;
const domainCreated = p.get('domainCreated')|| null;
const ageRisk       = p.get('ageRisk')      || null;

// ── Domain names ──────────────────────────────────────────────
document.getElementById('suspiciousDomain').textContent = suspicious;
document.getElementById('lookalikeDomain').textContent  = lookalike;

// ── Distance ──────────────────────────────────────────────────
if (distance && distance !== 'N/A') {
  document.getElementById('distanceValue').textContent = distance;
} else {
  document.getElementById('distanceRow').style.display = 'none';
}

// ── Homoglyph warning ─────────────────────────────────────────
if (hasHomoglyphs) {
  document.getElementById('homoglyphBlock').classList.add('visible');
}

// ── VirusTotal block ──────────────────────────────────────────
if (vtStatus !== 'skipped' && vtStatus !== 'error' && vtStatus !== 'unknown') {
  const block = document.getElementById('vtBlock');
  block.classList.add('visible');
  const color = vtMalicious > 0 ? '#ff8fa3' : '#90cdf4';
  document.getElementById('vtDetails').innerHTML =
    `Flagged by <strong style="color:${color}">${vtMalicious} out of ${vtTotal}</strong> security engines. ` +
    `Status: <strong style="color:${color}">${vtStatus.toUpperCase()}</strong>`;
}

// ── Domain age block ──────────────────────────────────────────
if (domainAge && (ageRisk === 'critical' || ageRisk === 'high')) {
  const block = document.getElementById('ageBlock');
  block.classList.add('visible');
  document.getElementById('ageDetails').innerHTML =
    `This domain is only <strong>${domainAge} days old</strong>` +
    (domainCreated ? ` (registered ${domainCreated})` : '') +
    `. Phishing domains are almost always newly registered.`;
}

// ── Detection source ──────────────────────────────────────────
const sourceMap = {
  both:        '🔴 Detected by domain similarity analysis AND VirusTotal threat database.',
  virustotal:  '🔬 Detected by VirusTotal — flagged by multiple security engines.',
  levenshtein: '📏 Detected by domain similarity analysis — very close to a trusted domain.'
};
document.getElementById('detectionText').textContent =
  sourceMap[detectedBy] || sourceMap.levenshtein;

// ── Go Back button ────────────────────────────────────────────
document.getElementById('goBack').addEventListener('click', () => {
  window.location.href = `https://www.${lookalike}`;
});

// ── Proceed Anyway button ─────────────────────────────────────
document.getElementById('proceedAnyway').addEventListener('click', () => {
  if (!originalUrl) { window.history.back(); return; }

  const ok = confirm(
    `⚠️ Proceed to "${suspicious}"?\n\n` +
    `This domain looks like a fake version of "${lookalike}".\n` +
    `Only continue if you are 100% certain this site is legitimate.\n\n` +
    `It will be added to your whitelist so you won't be warned again.`
  );

  if (!ok) return;

  // Track that user bypassed the warning
  chrome.runtime.sendMessage({ action: 'recordProceeded' });

  // Whitelist the domain and navigate
  chrome.runtime.sendMessage(
    { action: 'addToWhitelist', domain: suspicious },
    res => { if (res?.success) window.location.href = originalUrl; }
  );
});
