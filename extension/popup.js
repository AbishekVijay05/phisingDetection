/* ============================================
   PhishGuard Extension — Popup Logic
   ============================================ */

const API_BASE = 'http://localhost:5000';

// DOM Elements
const $ = (sel) => document.querySelector(sel);
const loadingState = $('#loadingState');
const idleState = $('#idleState');
const errorState = $('#errorState');
const resultsState = $('#resultsState');
const loadingUrl = $('#loadingUrl');
const errorMessage = $('#errorMessage');
const riskScore = $('#riskScore');
const verdict = $('#verdict');
const verdictIcon = $('#verdictIcon');
const verdictMessage = $('#verdictMessage');
const scoreGauge = $('#scoreGauge');
const scannedUrl = $('#scannedUrl');
const checksList = $('#checksList');
const infoCard = $('#infoCard');
const infoTitle = $('#infoTitle');
const infoText = $('#infoText');

// Buttons
const autoScanToggle = $('#autoScanToggle');
const retryBtn = $('#retryBtn');
const viewFullBtn = $('#viewFullBtn');
const scanNowBtn = $('#scanNowBtn');
const settingsBtn = $('#settingsBtn');
const reportBtn = $('#reportBtn');
const dashboardBtn = $('#dashboardBtn');

let currentUrl = '';

// ---- State Management ---- //
function showState(state) {
  [loadingState, idleState, errorState, resultsState].forEach(el => el.classList.add('hidden'));
  state.classList.remove('hidden');
}

// ---- Initialize ---- //
document.addEventListener('DOMContentLoaded', async () => {
  // Load auto-scan preference
  const { autoScan = true } = await chrome.storage.local.get('autoScan');
  autoScanToggle.classList.toggle('active', autoScan);

  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentUrl = tab?.url || '';

  if (!currentUrl || currentUrl.startsWith('chrome://') || currentUrl.startsWith('chrome-extension://') ||
      currentUrl.startsWith('edge://') || currentUrl.startsWith('about:') || currentUrl.startsWith('file://')) {
    showState(idleState);
    return;
  }

  // Auto-scan on popup open
  scanUrl(currentUrl);
});

// ---- Scan URL ---- //
async function scanUrl(url) {
  showState(loadingState);
  loadingUrl.textContent = truncateUrl(url);

  try {
    const response = await fetch(`${API_BASE}/analyze/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Server error (${response.status})`);
    }

    const result = await response.json();
    renderResults(result, url);
  } catch (err) {
    showState(errorState);
    errorMessage.textContent = err.message || 'Could not reach PhishGuard API';
  }
}

// ---- Render Results ---- //
function renderResults(result, url) {
  showState(resultsState);

  const score = result.risk_score || 0;
  const verdictText = result.verdict || 'UNKNOWN';
  const checks = result.checks || [];

  // Score + Gauge
  riskScore.textContent = score;
  scannedUrl.textContent = truncateUrl(url);

  // Gauge conic gradient
  const gaugeColor = getVerdictColor(verdictText);
  const pct = Math.min(score, 100);
  scoreGauge.style.background = `conic-gradient(from 0deg, ${gaugeColor} ${pct * 3.6}deg, var(--surface) ${pct * 3.6}deg)`;
  scoreGauge.style.boxShadow = `0 0 15px ${gaugeColor}33`;

  // Verdict text
  verdict.textContent = verdictText === 'SAFE' ? 'SAFE SITE' : verdictText;

  // Verdict icon & message
  const vInfo = getVerdictInfo(verdictText);
  verdictIcon.textContent = vInfo.icon;
  verdictMessage.textContent = vInfo.message;

  // Apply verdict color class
  const scoreCard = resultsState.querySelector('.score-card');
  if (scoreCard) {
    scoreCard.parentElement.className = scoreCard.parentElement.className.replace(/verdict-\w+/g, '');
  }
  resultsState.classList.remove('verdict-safe', 'verdict-suspicious', 'verdict-phishing');
  resultsState.classList.add(`verdict-${verdictText.toLowerCase()}`);

  // Checks list
  checksList.innerHTML = '';
  if (checks.length === 0) {
    const noChecks = document.createElement('p');
    noChecks.style.cssText = 'font-size:12px;color:var(--text-muted);text-align:center;padding:12px;';
    noChecks.textContent = 'No detailed checks available';
    checksList.appendChild(noChecks);
  } else {
    checks.forEach(check => {
      const item = document.createElement('div');
      const status = (check.status || check.result || 'info').toLowerCase();
      const isPass = status === 'pass' || status === 'safe' || status === 'ok';
      const isFail = status === 'fail' || status === 'danger' || status === 'phishing';
      const className = isFail ? 'danger' : (isPass ? '' : 'warning');
      
      item.className = `check-item ${className}`;
      item.innerHTML = `
        <div class="check-item-left">
          <span class="material-symbols-outlined">${getCheckIcon(check, status)}</span>
          <span class="check-item-label">${escapeHtml(check.name || check.check || 'Check')}</span>
        </div>
        <span class="check-item-badge">${isPass ? 'Secure' : (isFail ? 'Risk' : 'Warn')}</span>
      `;
      checksList.appendChild(item);
    });
  }

  // Info card — show gemini analysis if available
  const gemini = result.gemini_analysis;
  if (gemini) {
    infoCard.classList.remove('hidden');
    infoTitle.textContent = 'AI Analysis';
    infoText.textContent = typeof gemini === 'string' ? gemini.substring(0, 200) : 'Analysis complete';
  } else {
    infoCard.classList.add('hidden');
  }
}

// ---- Helpers ---- //
function getVerdictColor(v) {
  switch (v) {
    case 'SAFE': return '#2aff2a';
    case 'SUSPICIOUS': return '#ff9a00';
    case 'PHISHING': return '#ff003c';
    default: return '#64748b';
  }
}

function getVerdictInfo(v) {
  switch (v) {
    case 'SAFE': return { icon: 'check_circle', message: 'Low risk detected' };
    case 'SUSPICIOUS': return { icon: 'warning', message: 'Potential threat detected' };
    case 'PHISHING': return { icon: 'dangerous', message: 'High risk — phishing detected!' };
    default: return { icon: 'help', message: 'Unknown status' };
  }
}

function getCheckIcon(check, status) {
  const isPass = status === 'pass' || status === 'safe' || status === 'ok';
  const isFail = status === 'fail' || status === 'danger' || status === 'phishing';
  if (isFail) return 'error';
  if (isPass) return 'verified_user';
  return 'warning';
}

function truncateUrl(url) {
  try {
    const u = new URL(url);
    let display = u.hostname + u.pathname;
    if (display.length > 45) display = display.substring(0, 42) + '...';
    return display;
  } catch {
    return url.substring(0, 45);
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---- Event Listeners ---- //

// Auto-scan toggle
autoScanToggle.addEventListener('click', async () => {
  const isActive = autoScanToggle.classList.toggle('active');
  await chrome.storage.local.set({ autoScan: isActive });
  // Notify background script
  chrome.runtime.sendMessage({ type: 'toggleAutoScan', enabled: isActive });
});

// Retry
retryBtn.addEventListener('click', () => {
  if (currentUrl) scanUrl(currentUrl);
});

// Scan Now
scanNowBtn.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentUrl = tab?.url || '';
  if (currentUrl && !currentUrl.startsWith('chrome://') && !currentUrl.startsWith('edge://')) {
    scanUrl(currentUrl);
  }
});

// View Full Analysis
viewFullBtn.addEventListener('click', () => {
  chrome.tabs.create({ url: `${API_BASE}/url` });
});

// Dashboard
dashboardBtn.addEventListener('click', () => {
  chrome.tabs.create({ url: API_BASE });
});

// Settings (placeholder — stores toggle prefs)
settingsBtn.addEventListener('click', () => {
  chrome.tabs.create({ url: `${API_BASE}/history` });
});

// Report Site
reportBtn.addEventListener('click', () => {
  if (currentUrl) {
    const mailto = `mailto:?subject=PhishGuard Report&body=Reporting URL: ${encodeURIComponent(currentUrl)}`;
    chrome.tabs.create({ url: mailto });
  }
});
