/* ============================================
   PhishGuard Extension — Background Service Worker
   ============================================ */

const API_BASE = 'http://localhost:5000';

// ---- Context Menu ---- //
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'scanWithPhishGuard',
    title: 'Scan with PhishGuard',
    contexts: ['link'],
  });
});

// Context menu click handler
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
  // Only scan on complete navigation
  if (changeInfo.status !== 'complete') return;
  
  const url = tab.url;
  if (!url || !isScannableUrl(url)) {
    // Reset badge for non-scannable pages
    chrome.action.setBadgeText({ text: '', tabId });
    return;
  }

  // Check if auto-scan is enabled
  const { autoScan = true } = await chrome.storage.local.get('autoScan');
  if (!autoScan) return;

  // Avoid scanning the same URL repeatedly
  const cacheKey = `lastScan_${tabId}`;
  const cache = await chrome.storage.session.get(cacheKey).catch(() => ({}));
  if (cache[cacheKey] === url) return;

  // Set scanning badge
  chrome.action.setBadgeText({ text: '...', tabId });
  chrome.action.setBadgeBackgroundColor({ color: '#64748b', tabId });

  const result = await scanUrl(url);
  
  if (result) {
    // Cache this scan
    chrome.storage.session.set({ [cacheKey]: url }).catch(() => {});

    // Update badge
    const score = result.risk_score || 0;
    const color = getBadgeColor(result.verdict);
    chrome.action.setBadgeText({ text: String(score), tabId });
    chrome.action.setBadgeBackgroundColor({ color, tabId });

    // Send warning to content script if needed
    if (result.verdict === 'PHISHING' || result.verdict === 'SUSPICIOUS') {
      try {
        chrome.tabs.sendMessage(tabId, {
          type: 'showWarning',
          result,
          url,
        });
      } catch (e) {
        // Content script might not be loaded yet
      }
    }
  } else {
    chrome.action.setBadgeText({ text: '!', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#64748b', tabId });
  }
});

// ---- API Call ---- //
async function scanUrl(url) {
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
  }
}

// ---- Helpers ---- //
function isScannableUrl(url) {
  return url.startsWith('http://') || url.startsWith('https://');
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
    // Already saved by popup, just acknowledged
    sendResponse({ ok: true });
  }
  if (message.type === 'scanUrl') {
    scanUrl(message.url).then(result => sendResponse(result));
    return true; // async response
  }
});
