// ═══════════════════════════════════════════════════════════════
// TYPOSQUAT SHIELD — background.js
// All enhancements: Levenshtein + VirusTotal + RDAP + Context Menu
// ═══════════════════════════════════════════════════════════════

console.log('[TQS] Background script loaded ✅');

// ───────────────────────────────────────────────────────────────
// ⚙️  CONFIGURATION — Edit these values
// ───────────────────────────────────────────────────────────────

// Paste your FREE VirusTotal API key here (https://www.virustotal.com → Profile → API Key)
// If left empty, VirusTotal check is skipped gracefully — extension still works
const VT_API_KEY = '';

// How many character edits to flag as suspicious (2–3 recommended)
const LEVENSHTEIN_THRESHOLD = 3;

// VT cache duration — avoids hitting rate limits for same domain
const VT_CACHE_MS = 30 * 60 * 1000; // 30 minutes

// ───────────────────────────────────────────────────────────────
// 🌐  TRUSTED DOMAINS LIST
// ───────────────────────────────────────────────────────────────
const TRUSTED_DOMAINS = [
  // Search
  'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',
  // Google services
  'gmail.com', 'youtube.com', 'googleplay.com', 'googledrive.com',
  // Social
  'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
  'tiktok.com', 'snapchat.com', 'pinterest.com', 'linkedin.com',
  'reddit.com', 'discord.com', 'telegram.org', 'whatsapp.com',
  // Shopping
  'amazon.com', 'ebay.com', 'etsy.com', 'walmart.com', 'shopify.com',
  // Finance & Banking
  'paypal.com', 'stripe.com', 'chase.com', 'bankofamerica.com',
  'wellsfargo.com', 'capitalone.com', 'americanexpress.com',
  // Crypto
  'coinbase.com', 'binance.com', 'kraken.com', 'crypto.com',
  'metamask.io', 'opensea.io',
  // Tech
  'apple.com', 'icloud.com', 'microsoft.com', 'office.com',
  'outlook.com', 'github.com', 'gitlab.com', 'dropbox.com',
  'adobe.com', 'slack.com', 'zoom.us', 'notion.so',
  // Entertainment
  'netflix.com', 'spotify.com', 'twitch.tv', 'hulu.com',
  // Other
  'wikipedia.org', 'cloudflare.com'
];

// ───────────────────────────────────────────────────────────────
// 🔤  LEVENSHTEIN DISTANCE ALGORITHM
// ───────────────────────────────────────────────────────────────
function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      matrix[i][j] = b[i - 1] === a[j - 1]
        ? matrix[i - 1][j - 1]
        : Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
    }
  }
  return matrix[b.length][a.length];
}

// ───────────────────────────────────────────────────────────────
// 🔡  HOMOGLYPH NORMALIZATION
// ───────────────────────────────────────────────────────────────
const HOMOGLYPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
  'ѕ': 's', 'і': 'i', 'ј': 'j', 'ԁ': 'd', 'ɡ': 'g',
  'ɑ': 'a', 'ʼ': "'", '0': 'o', '1': 'l', '|': 'l', 'ı': 'i'
};

function normalizeHomoglyphs(str) {
  return str.split('').map(c => HOMOGLYPH_MAP[c] || c).join('');
}

// ───────────────────────────────────────────────────────────────
// 🌍  DOMAIN HELPERS
// ───────────────────────────────────────────────────────────────
function extractRootDomain(hostname) {
  const parts = hostname.replace(/^www\./, '').split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}

function isSafeUrl(url) {
  if (!url) return false;
  if (url.startsWith('chrome://')) return false;
  if (url.startsWith('chrome-extension://')) return false;
  if (url.startsWith('about:')) return false;
  if (url.startsWith('devtools://')) return false;
  if (url.startsWith('file://')) return false;
  return true;
}

// ───────────────────────────────────────────────────────────────
// 🦠  VIRUSTOTAL API
// ───────────────────────────────────────────────────────────────
const vtCache = new Map();

async function checkVirusTotal(domain) {
  // Skip if no API key configured
  if (!VT_API_KEY || VT_API_KEY === '') {
    return { status: 'skipped', malicious: 0, suspicious: 0, total: 0 };
  }

  // Return cached result if still fresh
  const cached = vtCache.get(domain);
  if (cached && Date.now() - cached.ts < VT_CACHE_MS) {
    return cached.result;
  }

  try {
    const res = await fetch(
      `https://www.virustotal.com/api/v3/domains/${domain}`,
      { headers: { 'x-apikey': VT_API_KEY, 'Accept': 'application/json' } }
    );

    if (res.status === 404) {
      return { status: 'unknown', malicious: 0, suspicious: 0, total: 0 };
    }
    if (res.status === 401) {
      console.warn('[TQS][VT] Invalid API key — VT checks disabled. Add your key in background.js');
      return { status: 'skipped', malicious: 0, suspicious: 0, total: 0 };
    }
    if (!res.ok) {
      throw new Error(`VT HTTP ${res.status}`);
    }

    const data  = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const result = {
      status:     vtStatus(stats),
      malicious:  stats.malicious  || 0,
      suspicious: stats.suspicious || 0,
      harmless:   stats.harmless   || 0,
      total:      Object.values(stats).reduce((a, b) => a + b, 0),
      reputation: data.data?.attributes?.reputation || 0
    };

    vtCache.set(domain, { result, ts: Date.now() });
    return result;

  } catch (err) {
    console.error('[TQS][VT] Error:', err.message);
    return { status: 'error', malicious: 0, suspicious: 0, total: 0 };
  }
}

function vtStatus(stats) {
  if ((stats.malicious  || 0) >= 3) return 'malicious';
  if ((stats.malicious  || 0) >= 1) return 'suspicious';
  if ((stats.suspicious || 0) >= 3) return 'suspicious';
  if ((stats.harmless   || 0) >  0) return 'clean';
  return 'unknown';
}

// ───────────────────────────────────────────────────────────────
// 📅  DOMAIN AGE VIA RDAP (no API key needed)
// ───────────────────────────────────────────────────────────────
const rdapCache = new Map();
const RDAP_CACHE_MS = 60 * 60 * 1000; // 1 hour

async function getDomainAge(domain) {
  const cached = rdapCache.get(domain);
  if (cached && Date.now() - cached.ts < RDAP_CACHE_MS) {
    return cached.result;
  }

  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, {
      headers: { 'Accept': 'application/json' }
    });

    if (!res.ok) return { age: null, risk: 'unknown', createdAt: null };

    const data = await res.json();
    const regEvent = (data.events || []).find(e => e.eventAction === 'registration');

    if (!regEvent) return { age: null, risk: 'unknown', createdAt: null };

    const created = new Date(regEvent.eventDate);
    const ageDays = Math.floor((Date.now() - created.getTime()) / 86400000);

    const result = {
      age: ageDays,
      risk: ageDays < 7  ? 'critical'
          : ageDays < 30 ? 'high'
          : ageDays < 90 ? 'moderate'
          : 'low',
      createdAt: created.toLocaleDateString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric'
      })
    };

    rdapCache.set(domain, { result, ts: Date.now() });
    return result;

  } catch (err) {
    return { age: null, risk: 'unknown', createdAt: null };
  }
}

// ───────────────────────────────────────────────────────────────
// 🔍  LEVENSHTEIN DOMAIN ANALYSIS
// ───────────────────────────────────────────────────────────────
function analyzeDomain(url) {
  try {
    const urlObj = new URL(url);
    if (!['http:', 'https:'].includes(urlObj.protocol)) return null;

    const rootDomain = extractRootDomain(urlObj.hostname);
    if (rootDomain.length < 5) return null;

    const normalized = normalizeHomoglyphs(rootDomain);

    for (const trusted of TRUSTED_DOMAINS) {
      if (rootDomain === trusted || normalized === trusted) return null;

      const lengthDiff = Math.abs(rootDomain.length - trusted.length);
      if (lengthDiff > 4) continue;

      const distance = levenshtein(normalized, trusted);

      if (distance > 0 && distance <= LEVENSHTEIN_THRESHOLD) {
        return {
          suspicious:    rootDomain,
          lookalike:     trusted,
          distance,
          hasHomoglyphs: normalized !== rootDomain,
          originalUrl:   url
        };
      }
    }
  } catch (e) {}
  return null;
}

// ───────────────────────────────────────────────────────────────
// ✅  WHITELIST
// ───────────────────────────────────────────────────────────────
async function isWhitelisted(domain) {
  return new Promise(resolve => {
    chrome.storage.local.get(['whitelist'], data => {
      resolve((data.whitelist || []).includes(domain));
    });
  });
}

// ───────────────────────────────────────────────────────────────
// 📝  RECORD THREAT TO HISTORY
// ───────────────────────────────────────────────────────────────
async function recordThreat(result) {
  return new Promise(resolve => {
    chrome.storage.local.get(['threatHistory', 'totalBlocked'], data => {
      const history = data.threatHistory || [];
      history.push({
        suspicious:  result.suspicious,
        lookalike:   result.lookalike,
        distance:    result.distance,
        detectedBy:  result.detectedBy,
        vtStatus:    result.vtStatus,
        vtMalicious: result.vtMalicious,
        vtTotal:     result.vtTotal,
        domainAge:   result.domainAge,
        ageRisk:     result.domainAgeRisk,
        timestamp:   Date.now()
      });
      if (history.length > 500) history.shift();
      chrome.storage.local.set({
        threatHistory: history,
        totalBlocked: (data.totalBlocked || 0) + 1
      }, resolve);
    });
  });
}

// ───────────────────────────────────────────────────────────────
// 🚦  MAIN URL HANDLER
// ───────────────────────────────────────────────────────────────
async function handleUrl(url, tabId) {
  if (!isSafeUrl(url)) return;

  try {
    const hostname   = new URL(url).hostname;
    const rootDomain = extractRootDomain(hostname);

    if (await isWhitelisted(rootDomain)) return;

    // Run all three checks in parallel
    const [levResult, vtResult, ageResult] = await Promise.all([
      Promise.resolve(analyzeDomain(url)),
      checkVirusTotal(rootDomain),
      getDomainAge(rootDomain)
    ]);

    const isTyposquat = levResult !== null;
    const isVtThreat  = vtResult.status === 'malicious' || vtResult.status === 'suspicious';
    const isNewDomain = (ageResult.risk === 'critical' || ageResult.risk === 'high') && isTyposquat;

    if (isTyposquat || isVtThreat) {
      const result = {
        suspicious:    levResult?.suspicious    || rootDomain,
        lookalike:     levResult?.lookalike     || 'Unknown',
        distance:      levResult?.distance      || null,
        hasHomoglyphs: levResult?.hasHomoglyphs || false,
        vtStatus:      vtResult.status,
        vtMalicious:   vtResult.malicious,
        vtSuspicious:  vtResult.suspicious,
        vtTotal:       vtResult.total,
        domainAge:     ageResult.age,
        domainCreatedAt: ageResult.createdAt,
        domainAgeRisk: ageResult.risk,
        detectedBy: isTyposquat && isVtThreat ? 'both'
                  : isVtThreat               ? 'virustotal'
                  : 'levenshtein',
        originalUrl: url
      };

      console.warn('[TQS] 🚨 THREAT DETECTED:', result);

      await recordThreat(result);
      chrome.storage.session.set({ [`warning_${tabId}`]: result });

      const q = new URLSearchParams({
        suspicious:  result.suspicious,
        lookalike:   result.lookalike,
        distance:    result.distance   ?? 'N/A',
        homoglyphs:  result.hasHomoglyphs,
        vtStatus:    result.vtStatus,
        vtMalicious: result.vtMalicious,
        vtTotal:     result.vtTotal,
        detectedBy:  result.detectedBy,
        domainAge:   result.domainAge    ?? '',
        domainCreated: result.domainCreatedAt ?? '',
        ageRisk:     result.domainAgeRisk ?? '',
        original:    url
      }).toString();

      chrome.tabs.update(tabId, {
        url: chrome.runtime.getURL('warning.html') + '?' + q
      });

    } else {
      chrome.storage.session.remove([`warning_${tabId}`]);
    }

  } catch (err) {
    console.error('[TQS] handleUrl error:', err);
  }
}

// ───────────────────────────────────────────────────────────────
// 👂  NAVIGATION LISTENER — fires BEFORE redirects
// ───────────────────────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId !== 0) return;
  handleUrl(details.url, details.tabId);
});

// ───────────────────────────────────────────────────────────────
// 🖱️  RIGHT-CLICK CONTEXT MENU
// ───────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id:       'checkLinkSafety',
    title:    '🛡️ Check Link Safety',
    contexts: ['link']
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'checkLinkSafety') return;
  const url = info.linkUrl;
  if (!url) return;

  try {
    const hostname   = new URL(url).hostname;
    const rootDomain = extractRootDomain(hostname);

    const [levResult, vtResult, ageResult] = await Promise.all([
      Promise.resolve(analyzeDomain(url)),
      checkVirusTotal(rootDomain),
      getDomainAge(rootDomain)
    ]);

    const payload = {
      domain:      rootDomain,
      isSafe:      !levResult && vtResult.status !== 'malicious' && vtResult.status !== 'suspicious',
      isTyposquat: levResult !== null,
      lookalike:   levResult?.lookalike ?? null,
      vtStatus:    vtResult.status,
      vtMalicious: vtResult.malicious,
      vtTotal:     vtResult.total,
      domainAge:   ageResult.age,
      ageRisk:     ageResult.risk
    };

    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func:   injectToast,
      args:   [payload]
    });

  } catch (e) {
    console.error('[TQS] Context menu error:', e);
  }
});

// Injected into the page — must be fully self-contained
function injectToast(r) {
  document.getElementById('tqs-toast')?.remove();
  document.getElementById('tqs-style')?.remove();

  const style = document.createElement('style');
  style.id = 'tqs-style';
  style.textContent = `
    @keyframes tqsIn { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
    #tqs-toast { animation: tqsIn 0.3s ease; }
  `;
  document.head.appendChild(style);

  const accent = r.isSafe ? '#4ecca3' : '#e94560';
  const rows = [];
  if (r.isTyposquat && r.lookalike)
    rows.push(`📏 Looks like: <b style="color:#4ecca3">${r.lookalike}</b>`);
  if (r.vtStatus !== 'unknown' && r.vtStatus !== 'skipped' && r.vtStatus !== 'error')
    rows.push(`🔬 VirusTotal: <b style="color:${r.vtMalicious > 0 ? '#e94560' : '#4ecca3'}">${r.vtMalicious}/${r.vtTotal} flagged</b>`);
  if (r.domainAge !== null && (r.ageRisk === 'critical' || r.ageRisk === 'high'))
    rows.push(`📅 Domain age: <b style="color:#ffaa44">${r.domainAge} days old</b>`);

  const toast = document.createElement('div');
  toast.id = 'tqs-toast';
  toast.style.cssText = `
    position:fixed; bottom:24px; right:24px; z-index:2147483647;
    background:#12121f; border:2px solid ${accent}; border-radius:14px;
    padding:18px 22px; color:#e0e0e0; font-family:'Segoe UI',sans-serif;
    font-size:13px; max-width:320px; box-shadow:0 8px 40px rgba(0,0,0,.7); line-height:1.7;
  `;
  toast.innerHTML = `
    <div style="font-weight:700;font-size:15px;color:${accent};margin-bottom:8px">
      ${r.isSafe ? '✅ Link Looks Safe' : '⚠️ Suspicious Link'}
    </div>
    <div style="font-family:monospace;font-size:12px;color:#555577;margin-bottom:10px;word-break:break-all">${r.domain}</div>
    ${rows.map(row => `<div style="margin-bottom:3px">${row}</div>`).join('')}
    <div onclick="document.getElementById('tqs-toast').remove()"
         style="margin-top:12px;color:#333355;font-size:11px;cursor:pointer;text-align:right">
      Dismiss ✕
    </div>`;
  document.body.appendChild(toast);
  setTimeout(() => document.getElementById('tqs-toast')?.remove(), 9000);
}

// ───────────────────────────────────────────────────────────────
// 💬  MESSAGE HANDLER (whitelist additions + proceeded tracking)
// ───────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'addToWhitelist') {
    chrome.storage.local.get(['whitelist'], data => {
      const list = data.whitelist || [];
      if (!list.includes(msg.domain)) list.push(msg.domain);
      chrome.storage.local.set({ whitelist: list }, () => sendResponse({ success: true }));
    });
    return true;
  }

  if (msg.action === 'recordProceeded') {
    chrome.storage.local.get(['totalProceeded'], data => {
      chrome.storage.local.set({
        totalProceeded: (data.totalProceeded || 0) + 1
      }, () => sendResponse({ success: true }));
    });
    return true;
  }
});

// ───────────────────────────────────────────────────────────────
// 🧹  TAB CLEANUP
// ───────────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.session.remove([`warning_${tabId}`]);
});
