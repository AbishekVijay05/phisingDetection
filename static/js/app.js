/* ========================================
   PhishGuard — EASE THE ERROR
   Frontend JavaScript (Red Theme)
   ======================================== */

function getVerdictLabel(verdict) {
    if (verdict === 'PHISHING') return 'CRITICAL: PHISHING DETECTED';
    if (verdict === 'SUSPICIOUS') return 'CAUTION: SUSPICIOUS CONTENT';
    return 'STATUS: VERIFIED SAFE';
}

function animateCircleMeter(circleId, scoreId, score) {
    const circle = document.getElementById(circleId);
    const scoreEl = document.getElementById(scoreId);
    if (!circle || !scoreEl) return;
    const pct = Math.round(score);
    circle.setAttribute('stroke-dasharray', `${pct}, 100`);
    let current = 0;
    const step = Math.max(1, Math.floor(pct / 25));
    const interval = setInterval(() => {
        current += step;
        if (current >= pct) { current = pct; clearInterval(interval); }
        scoreEl.textContent = current;
    }, 30);
}

function renderChecksTW(listId, checks) {
    const list = document.getElementById(listId);
    if (!list || !checks) return;
    list.innerHTML = checks.map(c => `
        <li class="flex items-center gap-3 p-3 bg-white/5 border border-white/5 hover:border-primary/50 transition-colors">
            <span class="material-symbols-outlined text-lg ${c.status === 'pass' ? 'text-green-500' : c.status === 'fail' ? 'text-primary' : 'text-yellow-500'}">${c.status === 'pass' ? 'check' : c.status === 'fail' ? 'close' : 'warning'}</span>
            <div>
                <span class="uppercase tracking-tighter font-bold">${c.name}</span>
                ${c.detail ? `<span class="text-slate-500 ml-2">${c.detail}</span>` : ''}
            </div>
        </li>
    `).join('');
}

function showEl(id) { const el = document.getElementById(id); if(el) el.style.display = 'block'; }
function hideEl(id) { const el = document.getElementById(id); if(el) el.style.display = 'none'; }

function showLoading(spinnerId, btnId) {
    const s = document.getElementById(spinnerId); if(s) s.style.display = 'block';
    const b = document.getElementById(btnId); if(b) b.disabled = true;
}
function hideLoading(spinnerId, btnId) {
    const s = document.getElementById(spinnerId); if(s) s.style.display = 'none';
    const b = document.getElementById(btnId); if(b) b.disabled = false;
}

function formatDate(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function animateCounter(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    let cur = 0;
    const step = Math.max(1, Math.floor(target / 20));
    const interval = setInterval(() => {
        cur += step;
        if (cur >= target) { cur = target; clearInterval(interval); }
        el.textContent = cur.toLocaleString();
    }, 40);
}

// ========================
// URL SCANNER
// ========================
async function scanURL() {
    const url = document.getElementById('url-input')?.value?.trim();
    if (!url) return;
    showLoading('url-spinner', 'url-scan-btn');
    hideEl('url-results');
    try {
        const res = await fetch('/analyze/url', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({url}) });
        const data = await res.json();
        if (data.error) { alert('Error: ' + data.error); return; }
        showEl('url-results');
        animateCircleMeter('url-meter-circle', 'url-score', data.risk_score);
        document.getElementById('url-verdict-badge').textContent = getVerdictLabel(data.verdict);
        document.getElementById('url-ml-prob').textContent = `${data.ml_probability ? (data.ml_probability*100).toFixed(1) : '0'}% PROB`;
        renderChecksTW('url-checks-list', data.checks);
        const g = document.getElementById('url-gemini-analysis');
        if(g) g.innerHTML = `"${data.gemini_analysis || 'Not available'}" — <span class="text-primary font-bold">GEMINI AI</span>`;
    } catch(e) { alert('Network error: ' + e.message); }
    finally { hideLoading('url-spinner', 'url-scan-btn'); }
}

// ========================
// EMAIL SCANNER
// ========================
function switchEmailTab(tab) {
    const u = document.getElementById('email-upload-section'), f = document.getElementById('email-form-section');
    const tu = document.getElementById('tab-upload'), tf = document.getElementById('tab-form');
    if (tab === 'upload') {
        u.style.display = 'block'; f.style.display = 'none';
        tu.className = 'px-6 py-3 bg-primary text-white font-black uppercase tracking-widest text-xs transition-all';
        tf.className = 'px-6 py-3 bg-white/5 border border-white/10 text-slate-400 font-black uppercase tracking-widest text-xs hover:text-primary transition-all';
    } else {
        u.style.display = 'none'; f.style.display = 'block';
        tf.className = 'px-6 py-3 bg-primary text-white font-black uppercase tracking-widest text-xs transition-all';
        tu.className = 'px-6 py-3 bg-white/5 border border-white/10 text-slate-400 font-black uppercase tracking-widest text-xs hover:text-primary transition-all';
    }
}

function handleEmailFile(input) {
    const file = input.files[0];
    const nameEl = document.getElementById('email-file-name');
    const btn = document.getElementById('email-upload-btn');
    if (file) { nameEl.textContent = file.name; nameEl.style.display = 'block'; btn.disabled = false; }
    else { nameEl.style.display = 'none'; btn.disabled = true; }
}

async function scanEmailFile() {
    const fi = document.getElementById('email-file-input');
    if (!fi.files[0]) return;
    const fd = new FormData(); fd.append('file', fi.files[0]);
    showLoading('email-spinner', 'email-upload-btn'); hideEl('email-results');
    try {
        const res = await fetch('/analyze/email', { method: 'POST', body: fd });
        displayEmailResults(await res.json());
    } catch(e) { alert('Network error: ' + e.message); }
    finally { hideLoading('email-spinner', 'email-upload-btn'); }
}

async function scanEmailForm() {
    const sender = document.getElementById('email-sender')?.value?.trim();
    const subject = document.getElementById('email-subject')?.value?.trim();
    const body = document.getElementById('email-body')?.value?.trim();
    if (!sender && !subject && !body) { alert('Please fill in at least one field'); return; }
    showLoading('email-spinner', 'email-form-btn'); hideEl('email-results');
    try {
        const res = await fetch('/analyze/email', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({sender, subject, body}) });
        displayEmailResults(await res.json());
    } catch(e) { alert('Network error: ' + e.message); }
    finally { hideLoading('email-spinner', 'email-form-btn'); }
}

function displayEmailResults(data) {
    if (data.error) { alert('Error: ' + data.error); return; }
    showEl('email-results');
    animateCircleMeter('email-meter-circle', 'email-score', data.risk_score);
    document.getElementById('email-verdict-badge').textContent = getVerdictLabel(data.verdict);
    renderChecksTW('email-checks-list', data.checks);
    const g = document.getElementById('email-gemini-analysis');
    if(g) g.innerHTML = `"${data.gemini_analysis || 'Not available'}" — <span class="text-primary font-bold">GEMINI AI</span>`;
}

// ========================
// SMS SCANNER
// ========================
async function scanSMS() {
    const message = document.getElementById('sms-message')?.value?.trim();
    const sender = document.getElementById('sms-sender')?.value?.trim();
    if (!message) { alert('Please enter an SMS message'); return; }
    showLoading('sms-spinner', 'sms-scan-btn'); hideEl('sms-results');
    try {
        const res = await fetch('/analyze/sms', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({message, sender}) });
        const data = await res.json();
        if (data.error) { alert('Error: ' + data.error); return; }
        showEl('sms-results');
        animateCircleMeter('sms-meter-circle', 'sms-score', data.risk_score);
        document.getElementById('sms-verdict-badge').textContent = getVerdictLabel(data.verdict);
        const preview = document.getElementById('sms-content-preview');
        if(preview) preview.textContent = `"${data.message_preview || message}"`;
        renderChecksTW('sms-checks-list', data.checks);
        const links = document.getElementById('sms-links-list');
        if(links && data.links_analyzed && data.links_analyzed.length > 0) {
            links.innerHTML = data.links_analyzed.map(l => `
                <li class="flex items-center gap-3 p-3 bg-white/5 border border-white/5">
                    <span class="material-symbols-outlined text-lg ${l.rule_score > 40 ? 'text-primary' : 'text-green-500'}">${l.rule_score > 40 ? 'close' : 'check'}</span>
                    <div><span class="text-slate-300 break-all">${l.url}</span> <span class="text-slate-500 ml-2">Score: ${l.rule_score}</span></div>
                </li>
            `).join('');
        }
        const g = document.getElementById('sms-gemini-analysis');
        if(g) g.innerHTML = `"${data.gemini_analysis || 'Not available'}" — <span class="text-primary font-bold">GEMINI AI</span>`;
        const rec = document.getElementById('sms-recommendation-text');
        if(rec) {
            if(data.verdict==='PHISHING') rec.textContent = 'Do not click any links. Block the sender and report as spam.';
            else if(data.verdict==='SUSPICIOUS') rec.textContent = 'Exercise caution. Verify through official channels before taking action.';
            else rec.textContent = 'This message appears safe, but always stay vigilant.';
        }
    } catch(e) { alert('Network error: ' + e.message); }
    finally { hideLoading('sms-spinner', 'sms-scan-btn'); }
}

// ========================
// DASHBOARD
// ========================
async function loadDashboardStats() {
    try {
        const res = await fetch('/api/stats'); const data = await res.json();
        animateCounter('stat-total', data.total_scans || 0);
        animateCounter('stat-phishing', data.phishing_caught || 0);
        animateCounter('stat-safe', data.safe_count || 0);
        animateCounter('stat-suspicious', data.suspicious_count || 0);
    } catch(e) { console.error('Stats error:', e); }
}

async function loadRecentOps() {
    try {
        const res = await fetch('/api/history?per_page=5'); const data = await res.json();
        const tbody = document.getElementById('recent-ops-body');
        if (!tbody || !data.scans || data.scans.length === 0) return;
        tbody.innerHTML = data.scans.map(s => `
            <tr class="hover:bg-primary/5 transition-colors">
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="px-2 py-0.5 rounded-sm ${s.scan_type==='url'?'bg-primary/20 text-primary':'bg-white/10 text-slate-400'} text-[10px] font-black uppercase">${s.scan_type}</span>
                </td>
                <td class="px-6 py-4 text-xs font-medium text-slate-300 max-w-[200px] truncate">${s.scan_summary}</td>
                <td class="px-6 py-4">
                    <div class="w-full bg-white/5 h-1 rounded-full">
                        <div class="bg-primary h-1 rounded-full" style="width:${s.risk_score}%;${s.risk_score>60?'box-shadow:0 0 8px #f20d20':''}"></div>
                    </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="${s.verdict==='PHISHING'?'text-primary':s.verdict==='SUSPICIOUS'?'text-primary/70':'text-slate-400'} text-[10px] font-black uppercase tracking-widest italic">${s.verdict}</span>
                </td>
                <td class="px-6 py-4 text-[10px] text-slate-500 whitespace-nowrap uppercase">${formatDate(s.created_at)}</td>
            </tr>
        `).join('');
    } catch(e) { console.error('Recent ops error:', e); }
}

// ========================
// HISTORY PAGE
// ========================
let currentHistPage = 1;
async function loadHistoryPage(page = 1) {
    currentHistPage = page;
    try {
        const res = await fetch(`/api/history?page=${page}&per_page=20`); const data = await res.json();
        const tbody = document.getElementById('history-table-body');
        const countEl = document.getElementById('history-count');
        if (!tbody) return;
        if (!data.scans || data.scans.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-12 text-center text-slate-500 text-xs uppercase tracking-widest">No scans yet</td></tr>`;
            return;
        }
        if(countEl) countEl.textContent = `${(page-1)*20+1}-${Math.min(page*20, data.total)} of ${data.total}`;
        tbody.innerHTML = data.scans.map(s => `
            <tr class="hover:bg-primary/5 transition-colors">
                <td class="px-6 py-4 text-slate-500 text-xs">#${s.id}</td>
                <td class="px-6 py-4"><span class="px-2 py-0.5 rounded-sm ${s.scan_type==='url'?'bg-primary/20 text-primary':s.scan_type==='sms'?'bg-primary/10 text-primary':'bg-white/10 text-slate-400'} text-[10px] font-black uppercase">${s.scan_type}</span></td>
                <td class="px-6 py-4 text-xs font-medium text-slate-300 max-w-[250px] truncate">${s.scan_summary}</td>
                <td class="px-6 py-4"><div class="w-full bg-white/5 h-1 rounded-full"><div class="bg-primary h-1 rounded-full" style="width:${s.risk_score}%"></div></div></td>
                <td class="px-6 py-4"><span class="${s.verdict==='PHISHING'?'text-primary':s.verdict==='SUSPICIOUS'?'text-primary/70':'text-slate-400'} text-[10px] font-black uppercase tracking-widest italic">${s.verdict}</span></td>
                <td class="px-6 py-4 text-[10px] text-slate-500 uppercase">${formatDate(s.created_at)}</td>
            </tr>
        `).join('');
        const pagEl = document.getElementById('history-pagination');
        if(pagEl && data.pages > 1) {
            let btns = '';
            for(let i=1;i<=data.pages;i++) btns += `<button class="${i===page?'bg-primary text-white':'bg-white/5 text-slate-400 hover:text-primary'} px-4 py-2 text-xs font-black uppercase" onclick="loadHistoryPage(${i})">${i}</button>`;
            pagEl.innerHTML = btns;
        }
    } catch(e) { console.error('History error:', e); }
}

async function loadHistoryStats() {
    try {
        const res = await fetch('/api/stats'); const data = await res.json();
        animateCounter('hist-total', data.total_scans || 0);
        animateCounter('hist-phishing', data.phishing_caught || 0);
        animateCounter('hist-suspicious', data.suspicious_count || 0);
        animateCounter('hist-safe', data.safe_count || 0);
    } catch(e) { console.error('History stats error:', e); }
}

function initHistoryCharts() {
    const actCtx = document.getElementById('activity-chart');
    if(actCtx) {
        new Chart(actCtx.getContext('2d'), {
            type: 'line',
            data: { labels: ['Week 1','Week 2','Week 3','Week 4'], datasets: [{ label: 'Scans', data: [0,0,0,0], borderColor: '#f20d20', backgroundColor: 'rgba(242,13,32,0.1)', fill: true, tension: 0.4, pointBackgroundColor: '#f20d20', pointBorderColor: '#f20d20', pointRadius: 4 }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#666', font: { family: 'Space Grotesk', size: 10 } } }, y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#666', font: { family: 'Space Grotesk', size: 10 } }, beginAtZero: true } } }
        });
    }
    const verCtx = document.getElementById('verdict-chart');
    if(verCtx) {
        fetch('/api/stats').then(r=>r.json()).then(data => {
            new Chart(verCtx.getContext('2d'), {
                type: 'doughnut',
                data: { labels: ['Safe','Suspicious','Phishing'], datasets: [{ data: [data.safe_count||0, data.suspicious_count||0, data.phishing_caught||0], backgroundColor: ['#333','rgba(242,13,32,0.4)','#f20d20'], borderColor: '#050505', borderWidth: 3 }] },
                options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'bottom', labels: { color: '#666', font: { family: 'Space Grotesk', size: 10 }, padding: 16, usePointStyle: true, pointStyle: 'circle' } } } }
            });
        });
    }
}
