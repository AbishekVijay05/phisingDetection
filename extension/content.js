/* ============================================
   PhishGuard Extension — Content Script
   v2.1: In-page overlays for blocking & warnings
   Runs at document_start to hide page before render
   ============================================ */

(function() {
  'use strict';

  // ---- Immediately hide the page while scanning ---- //
  // This runs BEFORE the DOM is built, so we inject a style tag
  const hideStyle = document.createElement('style');
  hideStyle.id = 'phishguard-hide-style';
  hideStyle.textContent = `
    html.phishguard-scanning body {
      visibility: hidden !important;
      pointer-events: none !important;
    }
    html.phishguard-scanning::after {
      content: '';
      position: fixed;
      inset: 0;
      background: #050505;
      z-index: 2147483646;
    }
  `;
  (document.head || document.documentElement).appendChild(hideStyle);
  document.documentElement.classList.add('phishguard-scanning');

  let overlayShown = false;
  let pageRevealed = false;

  // ---- Listen for scan results from background ---- //
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'scanning') {
      // Keep page hidden — scanning in progress
      document.documentElement.classList.add('phishguard-scanning');
      sendResponse({ ok: true });
    }

    if (message.type === 'scanResult') {
      const action = message.action;

      if (action === 'block') {
        showBlockOverlay(message.result, message.url);
      } else if (action === 'warn') {
        showWarningOverlay(message.result, message.url);
      } else {
        // SAFE or allowed — reveal the page
        revealPage();
        if (message.result && message.result.verdict === 'SAFE') {
          showSafeBadge(message.result);
        }
      }
      sendResponse({ ok: true });
    }

    if (message.type === 'contextMenuResult' && message.result) {
      showContextToast(message.result, message.url);
      sendResponse({ ok: true });
    }
  });

  // ---- Auto-reveal if no message received within 8 seconds (failsafe) ---- //
  setTimeout(() => {
    if (!overlayShown && !pageRevealed) {
      revealPage();
    }
  }, 8000);


  // ================================================================
  //  BLOCK OVERLAY (PHISHING — Critical)
  //  Page content stays completely hidden behind this.
  // ================================================================
  function showBlockOverlay(result, url) {
    if (overlayShown) return;
    overlayShown = true;

    const score = result.risk_score || 0;
    const domain = extractDomain(url);

    const overlay = document.createElement('div');
    overlay.id = 'phishguard-block-overlay';
    overlay.innerHTML = `
      <div class="pg-overlay-bg pg-block-bg">

        <!-- Top Bar -->
        <div class="pg-topbar pg-topbar-danger">
          <div class="pg-topbar-inner">
            <div class="pg-topbar-left">
              <div class="pg-logo-icon">
                <svg fill="none" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" width="22" height="22">
                  <path clip-rule="evenodd" d="M24 18.4228L42 11.475V34.3663C42 34.7796 41.7457 35.1504 41.3601 35.2992L24 42V18.4228Z" fill="currentColor" fill-rule="evenodd"></path>
                  <path clip-rule="evenodd" d="M24 8.18819L33.4123 11.574L24 15.2071L14.5877 11.574L24 8.18819ZM9 15.8487L21 20.4805V37.6263L9 32.9945V15.8487ZM27 37.6263V20.4805L39 15.8487V32.9945L27 37.6263ZM25.354 2.29885C24.4788 1.98402 23.5212 1.98402 22.646 2.29885L4.98454 8.65208C3.7939 9.08038 3 10.2097 3 11.475V34.3663C3 36.0196 4.01719 37.5026 5.55962 38.098L22.9197 44.7987C23.6149 45.0671 24.3851 45.0671 25.0803 44.7987L42.4404 38.098C43.9828 37.5026 45 36.0196 45 34.3663V11.475C45 10.2097 44.2061 9.08038 43.0155 8.65208L25.354 2.29885Z" fill="currentColor" fill-rule="evenodd"></path>
                </svg>
              </div>
              <span class="pg-brand">PhishGuard</span>
              <span class="pg-divider"></span>
              <span class="pg-badge-icon pg-pulse">⛔</span>
              <span class="pg-badge-label pg-badge-danger">SITE BLOCKED</span>
            </div>
            <div class="pg-topbar-right">
              <button class="pg-btn pg-btn-danger" id="pg-block-leave">← BACK TO SAFETY</button>
            </div>
          </div>
        </div>

        <!-- Center Card -->
        <div class="pg-center">
          <div class="pg-card pg-card-danger">
            <div class="pg-card-corner-tr"></div>
            <div class="pg-card-corner-bl"></div>

            <!-- Shield Icon -->
            <div class="pg-shield-wrap">
              <div class="pg-shield-glow pg-glow-danger"></div>
              <div class="pg-shield-icon">
                <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M32 4L8 16V32C8 48 18.4 58.4 32 62C45.6 58.4 56 48 56 32V16L32 4Z" fill="rgba(255,0,60,0.12)" stroke="#ff003c" stroke-width="2"/>
                  <line x1="22" y1="22" x2="42" y2="42" stroke="#ff003c" stroke-width="3" stroke-linecap="round"/>
                  <line x1="42" y1="22" x2="22" y2="42" stroke="#ff003c" stroke-width="3" stroke-linecap="round"/>
                </svg>
              </div>
            </div>

            <h1 class="pg-title">This site has been <span class="pg-highlight-danger">blocked</span></h1>
            <p class="pg-desc">
              PhishGuard detected <span class="pg-domain-tag pg-domain-danger">${esc(domain)}</span> as a 
              <strong>confirmed phishing threat</strong>. The page was prevented from loading to protect your personal information.
            </p>

            <!-- URL Display -->
            <div class="pg-url-bar pg-url-danger">
              <span class="pg-url-icon">🔗</span>
              <span class="pg-url-text">${esc(url)}</span>
            </div>

            <!-- Risk Meter -->
            <div class="pg-risk-meter">
              <div class="pg-risk-circle pg-risk-danger">
                <span class="pg-risk-num">${score}</span>
              </div>
              <div class="pg-risk-info">
                <div class="pg-risk-verdict pg-text-danger">PHISHING DETECTED</div>
                <div class="pg-risk-explain">Multi-layer AI analysis confirmed this URL as a phishing attempt designed to steal your credentials.</div>
              </div>
            </div>

            <!-- Threat List -->
            <ul class="pg-threat-list" id="pg-block-threats">
              ${buildThreatItems(result.checks)}
            </ul>

            <!-- Actions -->
            <div class="pg-actions">
              <button class="pg-btn pg-btn-primary-danger" id="pg-block-safety">
                🛡️ Back to Safety
              </button>
              <button class="pg-btn pg-btn-secondary" id="pg-block-report">
                View Full Report
              </button>
            </div>

            <div class="pg-meta">
              <span class="pg-meta-status pg-text-danger"><span class="pg-meta-dot pg-dot-danger"></span> PhishGuard: Active</span>
              <span class="pg-meta-score">Risk Score: ${score}/100</span>
            </div>
          </div>
        </div>

        <!-- Floating Footer -->
        <div class="pg-float-badge">
          <div class="pg-float-icon pg-float-danger">⛔</div>
          <div class="pg-float-info">
            <div class="pg-float-label pg-text-danger">Status</div>
            <div class="pg-float-value">Threat Blocked</div>
          </div>
        </div>
      </div>
    `;

    document.documentElement.appendChild(overlay);

    // Event listeners
    overlay.querySelector('#pg-block-leave').onclick = () => goToSafety();
    overlay.querySelector('#pg-block-safety').onclick = () => goToSafety();
    overlay.querySelector('#pg-block-report').onclick = () => window.open('http://localhost:5000/url', '_blank');
  }


  // ================================================================
  //  WARNING POPUP (SUSPICIOUS — Small compact card)
  //  Page loads behind it (dimmed). Proceed button reveals it fully.
  // ================================================================
  function showWarningOverlay(result, url) {
    if (overlayShown) return;
    overlayShown = true;

    // Reveal page but dim it
    revealPage();

    const score = result.risk_score || 0;
    const domain = extractDomain(url);

    // Add dim overlay behind the popup
    const dimmer = document.createElement('div');
    dimmer.id = 'phishguard-dimmer';
    document.documentElement.appendChild(dimmer);

    // Create the small popup card
    const popup = document.createElement('div');
    popup.id = 'phishguard-warn-popup';
    popup.innerHTML = `
      <div class="pgw-popup-card">
        <!-- Header — matches extension header -->
        <div class="pgw-header">
          <div class="pgw-header-left">
            <span class="pgw-shield-icon">🛡</span>
            <span class="pgw-brand-text">PhishGuard</span>
          </div>
          <span class="pgw-badge">⚠ SUSPICIOUS</span>
        </div>

        <!-- Risk Score Row — like extension score-card -->
        <div class="pgw-risk-row">
          <div class="pgw-score-ring">
            <span class="pgw-score-num">${score}</span>
          </div>
          <div class="pgw-risk-detail">
            <div class="pgw-risk-label">Risk Score</div>
            <div class="pgw-domain">${esc(domain)}</div>
          </div>
        </div>

        <!-- Warning Message — like extension info-card -->
        <div class="pgw-message">
          ⚠ This site has potential security concerns. <strong>Do not enter personal information or passwords.</strong>
        </div>

        <!-- Proceed Question -->
        <div class="pgw-question">
          Would you like to <span class="pgw-highlight">proceed</span>?
        </div>

        <!-- Buttons — like extension btn-primary + btn-scan-now -->
        <div class="pgw-buttons">
          <button class="pgw-btn pgw-btn-back" id="pgw-goback">🛡 Go Back</button>
          <button class="pgw-btn pgw-btn-proceed" id="pgw-proceed">Proceed →</button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(popup);

    // Event listeners
    popup.querySelector('#pgw-goback').onclick = () => {
      popup.remove();
      dimmer.remove();
      goBack();
    };
    popup.querySelector('#pgw-proceed').onclick = () => {
      popup.remove();
      dimmer.remove();
      overlayShown = false;
      chrome.runtime.sendMessage({ type: 'allowUrl', url });
    };
    // Clicking the dimmer = go back
    dimmer.onclick = () => {
      popup.remove();
      dimmer.remove();
      goBack();
    };
  }


  // ================================================================
  //  SAFE BADGE — brief "Safe" indicator
  // ================================================================
  function showSafeBadge(result) {
    if (document.getElementById('phishguard-safe-badge')) return;

    const badge = document.createElement('div');
    badge.id = 'phishguard-safe-badge';
    badge.innerHTML = `
      <div class="pg-safe-inner">
        <span class="pg-safe-icon">🛡️</span>
        <span class="pg-safe-text">PhishGuard: <strong>Safe</strong></span>
        <span class="pg-safe-score">${result.risk_score}/100</span>
      </div>
    `;
    document.documentElement.appendChild(badge);

    setTimeout(() => {
      if (badge.parentNode) {
        badge.style.animation = 'pg-fadeOut 0.5s ease forwards';
        setTimeout(() => badge.remove(), 500);
      }
    }, 3000);
  }


  // ================================================================
  //  CONTEXT MENU TOAST
  // ================================================================
  function showContextToast(result, url) {
    const existing = document.getElementById('phishguard-toast');
    if (existing) existing.remove();

    const verdict = result.verdict || 'UNKNOWN';
    const color = verdict === 'SAFE' ? '#2aff2a' : (verdict === 'PHISHING' ? '#ff003c' : '#ff9a00');

    const toast = document.createElement('div');
    toast.id = 'phishguard-toast';
    toast.innerHTML = `
      <div class="pg-toast-inner" style="border-left-color: ${color};">
        <div class="pg-toast-header">
          <span>🛡️</span>
          <span class="pg-toast-title">PhishGuard Scan</span>
        </div>
        <div class="pg-toast-body">
          <span class="pg-toast-verdict" style="color: ${color};">${esc(verdict)}</span>
          <span class="pg-toast-score">Score: ${result.risk_score}/100</span>
        </div>
        <div class="pg-toast-url">${esc(extractDomain(url))}</div>
      </div>
    `;
    document.documentElement.appendChild(toast);

    setTimeout(() => {
      if (toast.parentNode) {
        toast.style.animation = 'pg-slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
      }
    }, 6000);
  }


  // ================================================================
  //  HELPERS
  // ================================================================
  function revealPage() {
    if (pageRevealed) return;
    pageRevealed = true;
    document.documentElement.classList.remove('phishguard-scanning');
    const style = document.getElementById('phishguard-hide-style');
    if (style) style.remove();
  }

  function goToSafety() {
    window.location.href = 'https://www.google.com';
  }

  function goBack() {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'https://www.google.com';
    }
  }

  function extractDomain(url) {
    try { return new URL(url).hostname; }
    catch { return url.substring(0, 50); }
  }

  function esc(str) {
    const el = document.createElement('div');
    el.textContent = str || '';
    return el.innerHTML;
  }

  function buildThreatItems(checks) {
    if (!checks || checks.length === 0) {
      return `
        <li class="pg-threat-item">
          <span class="pg-threat-icon">⚠️</span>
          <span class="pg-threat-text"><strong>High Risk:</strong> AI analysis confirmed this as a dangerous phishing site.</span>
        </li>
      `;
    }
    let html = '';
    const failed = checks.filter(c => {
      const s = (c.status || c.result || '').toLowerCase();
      return s === 'fail' || s === 'danger' || s === 'phishing';
    });
    const items = failed.length > 0 ? failed : checks.slice(0, 3);
    items.forEach(c => {
      html += `
        <li class="pg-threat-item">
          <span class="pg-threat-icon">⚠️</span>
          <span class="pg-threat-text"><strong>${esc(c.name || c.check || 'Threat')}:</strong> ${esc(c.detail || c.message || 'Flagged as dangerous')}</span>
        </li>
      `;
    });
    return html;
  }

  function buildWarningItems(checks) {
    if (!checks || checks.length === 0) {
      return `
        <li class="pg-threat-item">
          <span class="pg-threat-icon">⚠️</span>
          <span class="pg-threat-text"><strong>Suspicious Activity:</strong> AI analysis detected potential risks with this site.</span>
        </li>
        <li class="pg-threat-item">
          <span class="pg-threat-icon">ℹ️</span>
          <span class="pg-threat-text"><strong>Recommendation:</strong> Do not enter personal information or passwords.</span>
        </li>
      `;
    }
    let html = '';
    const flagged = checks.filter(c => {
      const s = (c.status || c.result || '').toLowerCase();
      return s !== 'pass' && s !== 'safe' && s !== 'ok';
    });
    const items = flagged.length > 0 ? flagged.slice(0, 4) : checks.slice(0, 3);
    items.forEach(c => {
      html += `
        <li class="pg-threat-item">
          <span class="pg-threat-icon">⚠️</span>
          <span class="pg-threat-text"><strong>${esc(c.name || c.check || 'Warning')}:</strong> ${esc(c.detail || c.message || 'Flagged as suspicious')}</span>
        </li>
      `;
    });
    return html;
  }

})();
