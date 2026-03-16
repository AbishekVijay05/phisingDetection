/* ============================================
   PhishGuard Extension — Content Script
   Injects warning overlays on dangerous pages
   ============================================ */

(function() {
  'use strict';

  let warningInjected = false;

  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'showWarning' && message.result) {
      injectWarning(message.result, message.url);
      sendResponse({ ok: true });
    }

    if (message.type === 'contextMenuResult' && message.result) {
      showContextMenuToast(message.result, message.url);
      sendResponse({ ok: true });
    }
  });

  // ---- Full Page Warning (PHISHING) ---- //
  function injectWarning(result, url) {
    if (warningInjected) return;
    warningInjected = true;

    const verdict = result.verdict;
    const score = result.risk_score || 0;

    if (verdict === 'PHISHING' && score >= 75) {
      injectFullPageOverlay(result, url);
    } else if (verdict === 'SUSPICIOUS' || (verdict === 'PHISHING' && score < 75)) {
      injectTopBanner(result, url);
    }
  }

  function injectFullPageOverlay(result, url) {
    const overlay = document.createElement('div');
    overlay.id = 'phishguard-overlay';
    overlay.innerHTML = `
      <div class="phishguard-overlay-bg">
        <!-- Top Banner -->
        <div class="phishguard-top-banner">
          <div class="phishguard-top-inner">
            <div class="phishguard-top-left">
              <div class="phishguard-logo-sm">
                <svg fill="none" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" width="24" height="24">
                  <path clip-rule="evenodd" d="M24 18.4228L42 11.475V34.3663C42 34.7796 41.7457 35.1504 41.3601 35.2992L24 42V18.4228Z" fill="currentColor" fill-rule="evenodd"></path>
                  <path clip-rule="evenodd" d="M24 8.18819L33.4123 11.574L24 15.2071L14.5877 11.574L24 8.18819ZM9 15.8487L21 20.4805V37.6263L9 32.9945V15.8487ZM27 37.6263V20.4805L39 15.8487V32.9945L27 37.6263ZM25.354 2.29885C24.4788 1.98402 23.5212 1.98402 22.646 2.29885L4.98454 8.65208C3.7939 9.08038 3 10.2097 3 11.475V34.3663C3 36.0196 4.01719 37.5026 5.55962 38.098L22.9197 44.7987C23.6149 45.0671 24.3851 45.0671 25.0803 44.7987L42.4404 38.098C43.9828 37.5026 45 36.0196 45 34.3663V11.475C45 10.2097 44.2061 9.08038 43.0155 8.65208L25.354 2.29885Z" fill="currentColor" fill-rule="evenodd"></path>
                </svg>
              </div>
              <span class="phishguard-brand">PhishGuard</span>
              <span class="phishguard-warning-icon">⚠</span>
              <span class="phishguard-warning-text">CRITICAL WARNING: Phishing Attempt Detected</span>
            </div>
            <div class="phishguard-top-right">
              <button class="phishguard-btn-danger" id="phishguard-leave">GET ME OUT OF HERE</button>
              <button class="phishguard-btn-ghost" id="phishguard-proceed">Proceed Anyway</button>
            </div>
          </div>
        </div>

        <!-- Center Content -->
        <div class="phishguard-center">
          <div class="phishguard-center-card">
            <div class="phishguard-card-corner-tr"></div>
            <div class="phishguard-card-corner-bl"></div>
            <div class="phishguard-danger-icon-wrap">
              <div class="phishguard-danger-glow"></div>
              <span class="phishguard-danger-icon">⚠</span>
            </div>
            <h1 class="phishguard-title">Deceptive site ahead</h1>
            <p class="phishguard-desc">
              Attackers on <span class="phishguard-domain">${escapeHtml(extractDomain(url))}</span> may trick you into doing something dangerous like installing software or revealing personal information.
            </p>
            <div class="phishguard-actions">
              <button class="phishguard-btn-primary" id="phishguard-safety">
                <span>🛡</span> Back to Safety
              </button>
              <button class="phishguard-btn-secondary" id="phishguard-report-full">
                Detailed Report
              </button>
            </div>
            <div class="phishguard-meta">
              <span class="phishguard-meta-status">● PhishGuard Core: Online</span>
              <span class="phishguard-meta-score">Risk Score: ${result.risk_score}/100</span>
            </div>
          </div>
        </div>

        <!-- Floating Footer -->
        <div class="phishguard-floating-footer">
          <div class="phishguard-footer-icon">⚠</div>
          <div class="phishguard-footer-info">
            <span class="phishguard-footer-label">Status</span>
            <span class="phishguard-footer-value">Danger Blocked</span>
          </div>
        </div>
      </div>
    `;

    document.documentElement.appendChild(overlay);

    // Blur page content
    document.body.style.filter = 'blur(8px)';
    document.body.style.pointerEvents = 'none';
    document.body.style.userSelect = 'none';

    // Event listeners
    overlay.querySelector('#phishguard-leave').addEventListener('click', () => {
      window.location.href = 'https://www.google.com';
    });
    overlay.querySelector('#phishguard-safety').addEventListener('click', () => {
      window.location.href = 'https://www.google.com';
    });
    overlay.querySelector('#phishguard-proceed').addEventListener('click', () => {
      dismissOverlay(overlay);
    });
    overlay.querySelector('#phishguard-report-full').addEventListener('click', () => {
      window.open('http://localhost:5000/url', '_blank');
    });
  }

  // ---- Top Banner (SUSPICIOUS) ---- //
  function injectTopBanner(result, url) {
    const banner = document.createElement('div');
    banner.id = 'phishguard-banner';
    banner.innerHTML = `
      <div class="phishguard-banner-inner">
        <div class="phishguard-banner-left">
          <span class="phishguard-banner-icon">⚠</span>
          <span class="phishguard-banner-text">
            <strong>PhishGuard Warning:</strong> This site has been flagged as <strong>${escapeHtml(result.verdict)}</strong> (Risk: ${result.risk_score}/100)
          </span>
        </div>
        <div class="phishguard-banner-right">
          <button class="phishguard-banner-btn" id="phishguard-banner-details">Details</button>
          <button class="phishguard-banner-close" id="phishguard-banner-dismiss">✕</button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(banner);

    // Push page content down
    document.body.style.marginTop = '48px';

    banner.querySelector('#phishguard-banner-dismiss').addEventListener('click', () => {
      banner.remove();
      document.body.style.marginTop = '';
      warningInjected = false;
    });

    banner.querySelector('#phishguard-banner-details').addEventListener('click', () => {
      window.open('http://localhost:5000/url', '_blank');
    });
  }

  // ---- Context Menu Toast ---- //
  function showContextMenuToast(result, url) {
    // Remove existing toast
    const existing = document.getElementById('phishguard-toast');
    if (existing) existing.remove();

    const color = result.verdict === 'SAFE' ? '#2aff2a' : (result.verdict === 'PHISHING' ? '#ff003c' : '#ff9a00');
    const toast = document.createElement('div');
    toast.id = 'phishguard-toast';
    toast.innerHTML = `
      <div class="phishguard-toast-inner" style="border-left-color: ${color};">
        <div class="phishguard-toast-header">
          <span class="phishguard-toast-logo">🛡</span>
          <span class="phishguard-toast-title">PhishGuard Scan Result</span>
        </div>
        <div class="phishguard-toast-body">
          <span class="phishguard-toast-verdict" style="color: ${color};">${escapeHtml(result.verdict)}</span>
          <span class="phishguard-toast-score">Score: ${result.risk_score}/100</span>
        </div>
        <div class="phishguard-toast-url">${escapeHtml(extractDomain(url))}</div>
      </div>
    `;

    document.documentElement.appendChild(toast);

    // Auto-dismiss after 6 seconds
    setTimeout(() => {
      if (toast.parentNode) {
        toast.style.animation = 'phishguard-slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
      }
    }, 6000);
  }

  // ---- Helpers ---- //
  function dismissOverlay(overlay) {
    document.body.style.filter = '';
    document.body.style.pointerEvents = '';
    document.body.style.userSelect = '';
    overlay.remove();
    warningInjected = false;
  }

  function extractDomain(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return url.substring(0, 50);
    }
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
})();
