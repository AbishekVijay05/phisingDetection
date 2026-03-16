/* ============================================
   PhishGuard Extension — Background Service Worker
   v2.1: Scans URLs and sends results to content script
         for in-page overlay (no redirects)
   ============================================ */

const API_BASE = 'http://localhost:5000';

// Temporary whitelist for URLs the user chose to proceed to
const allowedUrls = new Set();

// Track URLs currently being scanned to avoid duplicate requests
const pendingScans = new Map();

// Cache scan results to avoid re-scanning the same URL
const scanCache = new Map();

// ---- Context Menu ---- //
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'scanWithPhishGuard',
    title: 'Scan with PhishGuard',
    contexts: ['link'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'scanWithPhishGuard' && info.linkUrl) {
    const result = await scanUrl(info.linkUrl);
    if (result && tab?.id) {
      chrome.tabs.sendMessage(tab.id, {
        type: 'contextMenuResult',
        result,
        url: info.linkUrl,
      });
    }
  }
});

// ---- Tab Navigation Listener ---- //
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'loading') return;

  const url = tab.url || tab.pendingUrl;
  if (!url || !isScannableUrl(url)) {
    chrome.action.setBadgeText({ text: '', tabId });
    return;
  }

  // Don't scan extension pages
  if (url.includes(chrome.runtime.id)) return;

  // Skip if user explicitly allowed this URL
  if (allowedUrls.has(url)) {
    allowedUrls.delete(url);
    // Tell content script to reveal the page immediately
    sendToTab(tabId, { type: 'scanResult', action: 'allow', url });
    chrome.action.setBadgeText({ text: '⚠', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#ff9a00', tabId });
    return;
  }

  // Check if auto-scan is enabled
  const { autoScan = true } = await chrome.storage.local.get('autoScan');
  if (!autoScan) {
    sendToTab(tabId, { type: 'scanResult', action: 'allow', url });
    return;
  }

  // Check cache first
  const cached = scanCache.get(url);
  if (cached) {
    handleResult(tabId, url, cached);
    return;
  }

  // Set scanning badge
  chrome.action.setBadgeText({ text: '...', tabId });
  chrome.action.setBadgeBackgroundColor({ color: '#64748b', tabId });

  // Tell content script we're scanning (it should keep page hidden)
  sendToTab(tabId, { type: 'scanning', url });

  // Scan the URL via API
  const result = await scanUrl(url);

  if (result) {
    scanCache.set(url, result);
    setTimeout(() => scanCache.delete(url), 10 * 60 * 1000);
    handleResult(tabId, url, result);
  } else {
    // API unreachable — let the page load
    sendToTab(tabId, { type: 'scanResult', action: 'allow', url });
    chrome.action.setBadgeText({ text: '!', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#64748b', tabId });
  }
});

// ---- Determine Action and Notify Content Script ---- //
function handleResult(tabId, url, result) {
  const score = result.risk_score || 0;
  const verdict = result.verdict || 'SAFE';
  const color = getBadgeColor(verdict);

  chrome.action.setBadgeText({ text: String(score), tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });

  if (verdict === 'PHISHING' && score >= 70) {
    // ⛔ BLOCK — keep page hidden, show block overlay
    sendToTab(tabId, {
      type: 'scanResult',
      action: 'block',
      result,
      url,
    });
  } else if (verdict === 'SUSPICIOUS' || (verdict === 'PHISHING' && score < 70)) {
    // ⚠️ WARN — keep page hidden, show warning with proceed button
    sendToTab(tabId, {
      type: 'scanResult',
      action: 'warn',
      result,
      url,
    });
  } else {
    // ✅ SAFE — reveal the page immediately
    sendToTab(tabId, {
      type: 'scanResult',
      action: 'allow',
      result,
      url,
    });
  }
}

// ---- Send message to tab (with retry) ---- //
function sendToTab(tabId, message, retries = 3) {
  chrome.tabs.sendMessage(tabId, message).catch(() => {
    if (retries > 0) {
      setTimeout(() => sendToTab(tabId, message, retries - 1), 200);
    }
  });
}

// ---- API Call ---- //
async function scanUrl(url) {
  if (pendingScans.has(url)) {
    return pendingScans.get(url);
  }

  const scanPromise = (async () => {
    try {
      const response = await fetch(`${API_BASE}/analyze/url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      if (!response.ok) return null;
      return await response.json();
    } catch (err) {
      console.warn('[PhishGuard] API error:', err.message);
      return null;
    } finally {
      pendingScans.delete(url);
    }
  })();

  pendingScans.set(url, scanPromise);
  return scanPromise;
}

// ---- Helpers ---- //
function isScannableUrl(url) {
  if (!url) return false;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return false;
  if (url.startsWith(API_BASE)) return false;
  if (url.includes('localhost') || url.includes('127.0.0.1')) return false;
  return true;
}

function getBadgeColor(verdict) {
  switch (verdict) {
    case 'SAFE': return '#2aff2a';
    case 'SUSPICIOUS': return '#ff9a00';
    case 'PHISHING': return '#ff003c';
    default: return '#64748b';
  }
}

// ---- Message Handler ---- //
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'toggleAutoScan') {
    sendResponse({ ok: true });
  }

  if (message.type === 'scanUrl') {
    scanUrl(message.url).then(result => sendResponse(result));
    return true;
  }

  // "Proceed" from warning overlay — whitelist URL temporarily
  if (message.type === 'allowUrl') {
    const url = message.url;
    allowedUrls.add(url);
    setTimeout(() => allowedUrls.delete(url), 5 * 60 * 1000);
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === 'clearCache') {
    scanCache.clear();
    allowedUrls.clear();
    sendResponse({ ok: true });
  }
});
