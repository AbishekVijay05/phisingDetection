# PhishGuard Browser Extension: Implementation Plan

The PhishGuard browser extension will serve as the "frontline" of defense, providing real-time analysis of URLs as users browse the web, without requiring them to manually copy-paste links into the dashboard.

## 1. Objective & Core Features
- **Real-Time URL Analysis:** Automatically scan the current tab's URL against the PhishGuard API.
- **On-Page Warnings:** Inject a warning banner if a site is flagged as **PHISHING** or **SUSPICIOUS**.
- **Context Menu Integration:** Allow users to right-click any link on a page and "Scan with PhishGuard."
- **Dashboard Popup:** A quick-view popup showing the current site's risk score and a breakdown of checks.

---

## 2. Technical Architecture

The extension will act as a client for the existing Flask backend:
1.  **Browser Extension (Frontend):** Manifest v3, HTML/CSS/JS.
2.  **PhishGuard API (Backend):** The existing `/analyze/url` endpoint in `app.py`.
3.  **Communication:** Secure AJAX/Fetch requests from the extension to the Flask server.

---

## 3. Key Components

### A. `manifest.json` (The Configuration)
- **Permissions:** `tabs`, `activeTab`, `contextMenus`, `storage`.
- **Host Permissions:** Access to the PhishGuard API domain and `*://*/*` (for URL scanning).

### B. `background.js` (The Service Worker)
- Listens for tab updates (`onUpdated`).
- Sends the new URL to the PhishGuard API for a "silent scan."
- Manages the extension's "badge" color (Green/Yellow/Red) based on the risk score.

### C. `popup.html` & `popup.js` (The UI)
- Displays a simplified version of the PhishGuard dashboard.
- Shows the **0-100 Risk Score** and the **Verdict**.
- Provides a button to "View Full Report" on the main PhishGuard web app.

### D. `content.js` (The Injector)
- Injects a DOM element (banner) at the top of the page if the site is malicious.
- Can blur the page content for high-risk phishing sites to prevent user interaction.

---

## 4. Development Phases

### Phase 1: Basic Extension Setup
- Create the `manifest.json` (v3).
- Implement a basic `popup.html` that displays "Scanning..." when opened.
- Connect the extension to the local Flask server (handling CORS).

### Phase 2: Manual Scan & Context Menu
- Add a "Scan Now" button in the popup.
- Implement the `contextMenus` API so users can right-click links.
- Capture the API response and display the verdict in the popup.

### Phase 3: Automatic Background Scanning
- Implement the `chrome.tabs.onUpdated` listener in `background.js`.
- Optimize to only scan on "complete" navigation to avoid redundant API calls.
- Update the extension icon badge (e.g., "75" in red for phishing).

### Phase 4: On-Page Warning System
- Develop the `content.js` logic to inject a warning overlay.
- Add a "Proceed anyway" vs. "Get me out of here" (redirect to safety) option.
- Ensure the overlay is styled to be un-ignorable.

### Phase 5: UI/UX & Refinement
- Match the extension's CSS with the `style.css` of the main web app.
- Implement "Trusted Sites" (Whitelist) locally in `chrome.storage` to reduce API load.
- Final testing against known phishing and safe URLs.

---

## 5. Security & Privacy Considerations
- **CORS Configuration:** Update `app.py` (using `flask-cors`) to allow requests from the extension's unique ID.
- **Data Minimization:** Only send the URL to the server; do not track user history.
- **API Authentication:** (Optional) Use an API key in the extension to prevent unauthorized use of your detection engine.
