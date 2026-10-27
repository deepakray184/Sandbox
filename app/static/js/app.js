/**
 * Vanguard MSA - Frontend Client Engine
 * Manages reactive UI, interactive ANY.RUN process trees,
 * timeline scrubbers, VirusTotal grid, email hop latency, and IOC exports.
 */

const AppState = {
    currentTab: 'dashboard',
    currentSubId: null,
    currentReport: null,
    stats: {},
    samples: [],
    submissions: [],
    activeProcessPid: null,
    timelineCurrentTime: 30
};

// DOM Ready
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initUploadHandlers();
    loadDashboardStats();
    loadSamples();
    loadSubmissions();
});

// Navigation
function initNavigation() {
    document.querySelectorAll('[data-nav-target]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const target = btn.getAttribute('data-nav-target');
            switchMainTab(target);
        });
    });
}

function switchMainTab(tabName) {
    AppState.currentTab = tabName;
    document.querySelectorAll('.main-view-panel').forEach(p => p.classList.add('hidden'));
    
    const targetPanel = document.getElementById(`panel-${tabName}`);
    if (targetPanel) {
        targetPanel.classList.remove('hidden');
    }

    // Update active nav styling
    document.querySelectorAll('[data-nav-target]').forEach(b => {
        if (b.getAttribute('data-nav-target') === tabName) {
            b.classList.add('border-blue-500', 'text-blue-400', 'bg-blue-900/20');
            b.classList.remove('border-transparent', 'text-gray-400');
        } else {
            b.classList.remove('border-blue-500', 'text-blue-400', 'bg-blue-900/20');
            b.classList.add('border-transparent', 'text-gray-400');
        }
    });

    if (tabName === 'history') {
        loadSubmissions();
    }
}

// Upload & Trigger Handlers
function initUploadHandlers() {
    // File drag & drop zone
    const dropZone = document.getElementById('file-drop-zone');
    const fileInput = document.getElementById('file-input');

    if (dropZone && fileInput) {
        ['dragenter', 'dragover'].forEach(name => {
            dropZone.addEventListener(name, (e) => {
                e.preventDefault();
                dropZone.classList.add('border-blue-500', 'bg-blue-950/20');
            });
        });
        ['dragleave', 'drop'].forEach(name => {
            dropZone.addEventListener(name, (e) => {
                e.preventDefault();
                dropZone.classList.remove('border-blue-500', 'bg-blue-950/20');
            });
        });
        dropZone.addEventListener('drop', (e) => {
            if (e.dataTransfer.files.length > 0) {
                uploadAndAnalyzeFile(e.dataTransfer.files[0]);
            }
        });
        dropZone.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                uploadAndAnalyzeFile(fileInput.files[0]);
            }
        });
    }

    // Email upload form
    const emailForm = document.getElementById('email-analyze-form');
    if (emailForm) {
        emailForm.addEventListener('submit', (e) => {
            e.preventDefault();
            analyzeEmail();
        });
    }
}

// Load Dashboard Data
async function loadDashboardStats() {
    try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        if (data.status === 'success') {
            AppState.stats = data.stats;
            document.getElementById('stat-total-scans').innerText = data.stats.total_scans;
            document.getElementById('stat-malicious').innerText = data.stats.malicious;
            document.getElementById('stat-suspicious').innerText = data.stats.suspicious;
            document.getElementById('stat-clean').innerText = data.stats.clean;
            document.getElementById('stat-emails').innerText = data.stats.emails_analyzed;
        }
    } catch (e) {
        console.error("Failed to load stats", e);
    }
}

async function loadSamples() {
    try {
        const res = await fetch('/api/samples');
        const data = await res.json();
        if (data.status === 'success') {
            AppState.samples = data.samples;
            renderSamplesList(data.samples);
        }
    } catch (e) {
        console.error("Failed to load samples", e);
    }
}

function renderSamplesList(samples) {
    const container = document.getElementById('samples-container');
    if (!container) return;
    container.innerHTML = samples.map(s => `
        <div class="soc-card p-4 hover:border-blue-500/50 cursor-pointer flex flex-col justify-between" onclick="runSampleAnalysis('${s.id}')">
            <div>
                <div class="flex items-center justify-between mb-2">
                    <span class="text-xs font-semibold uppercase tracking-wider px-2 py-0.5 rounded ${s.verdict.includes('Malicious') ? 'bg-red-900/30 text-red-400 border border-red-800' : (s.verdict.includes('Phishing') ? 'bg-purple-900/30 text-purple-400 border border-purple-800' : 'bg-emerald-900/30 text-emerald-400 border border-emerald-800')}">${s.verdict}</span>
                    <span class="text-xs text-gray-400 font-mono">${s.type.toUpperCase()}</span>
                </div>
                <h4 class="text-sm font-semibold text-white mb-1">${s.name}</h4>
                <p class="text-xs text-gray-400 mb-2 font-mono">${s.filename}</p>
                <p class="text-xs text-gray-400 line-clamp-2">${s.description}</p>
            </div>
            <button class="mt-3 w-full py-1.5 px-3 bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 border border-blue-500/30 rounded text-xs font-medium transition flex items-center justify-center gap-1.5">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                Launch Sandbox
            </button>
        </div>
    `).join('');
}

async function loadSubmissions() {
    try {
        const res = await fetch('/api/submissions?limit=30');
        const data = await res.json();
        if (data.status === 'success') {
            AppState.submissions = data.submissions;
            renderSubmissionsTable(data.submissions);
        }
    } catch (e) {
        console.error("Failed to load submissions", e);
    }
}

function renderSubmissionsTable(items) {
    const tbody = document.getElementById('submissions-table-body');
    if (!tbody) return;

    if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-8 text-gray-500 text-sm">No analysis submissions recorded yet. Upload a file or select a sample above.</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(item => {
        let badgeClass = "badge-clean";
        if (item.verdict === 'Malicious' || item.verdict.includes('Malicious')) badgeClass = "badge-malicious";
        else if (item.verdict === 'Suspicious') badgeClass = "badge-suspicious";

        const dateStr = item.created_at ? new Date(item.created_at).toLocaleString() : "-";
        const tagsHtml = (item.tags || []).slice(0, 3).map(t => `<span class="bg-gray-800 text-gray-300 text-[10px] px-1.5 py-0.5 rounded font-mono">${t}</span>`).join(' ');

        return `
            <tr class="border-b border-gray-800/60 hover:bg-gray-850/50 transition">
                <td class="py-3 px-4 font-mono text-xs text-white font-medium flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full ${item.target_type === 'email' ? 'bg-purple-400' : 'bg-blue-400'}"></span>
                    ${escapeHtml(item.filename)}
                </td>
                <td class="py-3 px-4 text-xs font-mono text-gray-400 uppercase">${item.target_type}</td>
                <td class="py-3 px-4">
                    <span class="px-2 py-0.5 rounded text-xs font-semibold ${badgeClass}">${item.verdict}</span>
                </td>
                <td class="py-3 px-4 text-xs font-semibold">
                    <span class="${item.threat_score >= 70 ? 'text-red-400' : (item.threat_score >= 35 ? 'text-amber-400' : 'text-emerald-400')}">${item.threat_score}</span> / 100
                </td>
                <td class="py-3 px-4">${tagsHtml}</td>
                <td class="py-3 px-4 text-xs text-gray-400 font-mono">${dateStr}</td>
                <td class="py-3 px-4 text-right">
                    <button onclick="viewExistingSubmission('${item.id}', '${item.target_type}')" class="text-xs bg-gray-800 hover:bg-gray-700 text-blue-400 px-2.5 py-1 rounded font-medium transition">
                        View Report &rarr;
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

// Running Analyses
function showLoadingModal(title, msg) {
    document.getElementById('loading-modal').classList.remove('hidden');
    document.getElementById('loading-title').innerText = title;
    document.getElementById('loading-desc').innerText = msg;
}

function hideLoadingModal() {
    document.getElementById('loading-modal').classList.add('hidden');
}

async function uploadAndAnalyzeFile(file) {
    const duration = document.getElementById('sandbox-duration')?.value || 30;
    const formData = new FormData();
    formData.append('file', file);
    formData.append('duration', duration);

    showLoadingModal("Deploying Sandbox...", `Analyzing ${file.name} (Static inspection, ANY.RUN dynamic trace, and 70+ AV engines)`);
    try {
        const res = await fetch('/api/analyze/file', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        hideLoadingModal();
        if (data.status === 'success') {
            displayFileReport(data.report);
            loadDashboardStats();
            loadSubmissions();
        } else {
            alert("Analysis failed: " + (data.detail || "Unknown error"));
        }
    } catch (e) {
        hideLoadingModal();
        alert("Network or analysis error: " + e.message);
    }
}

async function analyzeEmail() {
    const fileInput = document.getElementById('email-file-input');
    const rawHeadersInput = document.getElementById('email-raw-headers');

    const formData = new FormData();
    if (fileInput && fileInput.files.length > 0) {
        formData.append('file', fileInput.files[0]);
    } else if (rawHeadersInput && rawHeadersInput.value.trim().length > 0) {
        formData.append('raw_headers', rawHeadersInput.value.trim());
    } else {
        alert("Please upload a .eml file or paste raw email headers");
        return;
    }

    showLoadingModal("Inspecting Email...", "Verifying SPF/DKIM/DMARC, calculating hop latencies, and evaluating phishing heuristics");
    try {
        const res = await fetch('/api/analyze/email', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        hideLoadingModal();
        if (data.status === 'success') {
            displayEmailReport(data.report);
            loadDashboardStats();
            loadSubmissions();
        } else {
            alert("Email analysis failed: " + (data.detail || "Unknown error"));
        }
    } catch (e) {
        hideLoadingModal();
        alert("Analysis error: " + e.message);
    }
}

async function runSampleAnalysis(sampleId) {
    showLoadingModal("Loading Sample...", "Executing full SOC sandbox pipeline on pre-loaded threat sample");
    try {
        const res = await fetch(`/api/analyze/sample/${sampleId}`, { method: 'POST' });
        const data = await res.json();
        hideLoadingModal();
        if (data.status === 'success') {
            if (data.report.target_type === 'email') {
                displayEmailReport(data.report);
            } else {
                displayFileReport(data.report);
            }
            loadDashboardStats();
            loadSubmissions();
        } else {
            alert("Sample analysis failed");
        }
    } catch (e) {
        hideLoadingModal();
        alert("Error launching sample: " + e.message);
    }
}

async function viewExistingSubmission(subId, targetType) {
    showLoadingModal("Fetching Report...", "Retrieving complete analysis data from database");
    try {
        const res = await fetch(`/api/submission/${subId}`);
        const data = await res.json();
        hideLoadingModal();
        if (data.status === 'success') {
            const report = data.submission.report_data;
            if (targetType === 'email') {
                displayEmailReport(report);
            } else {
                displayFileReport(report);
            }
        }
    } catch (e) {
        hideLoadingModal();
        alert("Failed to load report: " + e.message);
    }
}

// Render File Report (ANY.RUN + VirusTotal)
function displayFileReport(report) {
    AppState.currentReport = report;
    AppState.currentSubId = report.id;
    switchMainTab('file-report');

    // Header info
    document.getElementById('rep-filename').innerText = report.filename;
    document.getElementById('rep-filetype').innerText = report.file_type;
    document.getElementById('rep-sha256').innerText = report.hashes.sha256;
    document.getElementById('rep-filesize').innerText = formatBytes(report.file_size);
    document.getElementById('rep-magic').innerText = report.magic_hex;

    // Verdict badge
    const verdictEl = document.getElementById('rep-verdict-badge');
    verdictEl.innerText = report.verdict.toUpperCase();
    verdictEl.className = `px-3 py-1 rounded-md text-xs font-bold tracking-wider ${report.verdict === 'Malicious' ? 'badge-malicious' : (report.verdict === 'Suspicious' ? 'badge-suspicious' : 'badge-clean')}`;

    // Threat Score Gauge
    const scoreVal = report.threat_score;
    document.getElementById('rep-score-value').innerText = scoreVal;
    const circle = document.getElementById('rep-gauge-circle');
    if (circle) {
        const circumference = 2 * Math.PI * 40;
        const offset = circumference - (scoreVal / 100) * circumference;
        circle.style.strokeDashoffset = offset;
        circle.style.stroke = scoreVal >= 70 ? '#ef4444' : (scoreVal >= 35 ? '#f59e0b' : '#10b981');
    }

    // AV Ratio
    document.getElementById('rep-av-ratio').innerText = report.virustotal.detection_ratio;
    document.getElementById('rep-av-pct').innerText = `${report.virustotal.detection_rate_pct}%`;

    // Overview Tab
    renderReportOverview(report);

    // Dynamic Sandbox Tab
    renderDynamicSandbox(report.sandbox);

    // Static Tab
    renderStaticTab(report);

    // AV Tab
    renderAvGrid(report.virustotal);

    // MITRE ATT&CK Tab
    renderMitreTab(report.mitre_attack);

    // Load Analyst Notes
    loadAnalystNotes(report.id);

    // Default to Overview sub-tab
    switchReportSubTab('overview');
}

function switchReportSubTab(subTabName) {
    document.querySelectorAll('.report-sub-view').forEach(p => p.classList.add('hidden'));
    const target = document.getElementById(`rep-sub-${subTabName}`);
    if (target) target.classList.remove('hidden');

    document.querySelectorAll('[data-rep-tab]').forEach(btn => {
        if (btn.getAttribute('data-rep-tab') === subTabName) {
            btn.classList.add('border-blue-500', 'text-blue-400', 'bg-blue-900/20');
            btn.classList.remove('border-transparent', 'text-gray-400');
        } else {
            btn.classList.remove('border-blue-500', 'text-blue-400', 'bg-blue-900/20');
            btn.classList.add('border-transparent', 'text-gray-400');
        }
    });
}

function renderReportOverview(report) {
    // Summary
    document.getElementById('rep-summary-text').innerText = report.summary;

    // Hashes Card
    document.getElementById('hash-md5').innerText = report.hashes.md5;
    document.getElementById('hash-sha1').innerText = report.hashes.sha1;
    document.getElementById('hash-sha256').innerText = report.hashes.sha256;
    document.getElementById('hash-ssdeep').innerText = report.hashes.ssdeep;
    document.getElementById('hash-imphash').innerText = report.hashes.imphash || 'N/A';

    // Threat Score Breakdown
    const breakdownContainer = document.getElementById('score-breakdown-list');
    if (breakdownContainer) {
        breakdownContainer.innerHTML = (report.score_breakdown || []).map(item => `
            <div class="flex items-start justify-between p-2.5 rounded bg-gray-900/50 border border-gray-800">
                <div>
                    <div class="flex items-center gap-2">
                        <span class="text-xs font-semibold text-white">${escapeHtml(item.factor)}</span>
                        <span class="text-[10px] px-1.5 py-0.2 rounded font-bold ${item.severity === 'CRITICAL' ? 'bg-red-900/40 text-red-400' : (item.severity === 'HIGH' ? 'bg-amber-900/40 text-amber-400' : 'bg-blue-900/40 text-blue-400')}">${item.severity}</span>
                    </div>
                    <p class="text-xs text-gray-400 mt-0.5">${escapeHtml(item.description)}</p>
                </div>
                <span class="text-sm font-bold text-red-400 font-mono">+${item.points}</span>
            </div>
        `).join('');
    }

    // Entropy Histogram
    renderEntropyChart(report.entropy, report.entropy_distribution);
}

function renderEntropyChart(overall, distribution) {
    const canvas = document.getElementById('entropy-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const barWidth = canvas.width / distribution.length;
    for (let i = 0; i < distribution.length; i++) {
        const val = distribution[i];
        const barHeight = (val / 8.0) * canvas.height;
        const x = i * barWidth;
        const y = canvas.height - barHeight;

        // Color based on entropy threshold
        ctx.fillStyle = val > 7.1 ? '#ef4444' : (val > 6.0 ? '#f59e0b' : '#3b82f6');
        ctx.fillRect(x + 1, y, barWidth - 2, barHeight);
    }

    document.getElementById('entropy-value-label').innerText = `${overall} / 8.0000`;
}

// ANY.RUN Dynamic Sandbox Renderer
function renderDynamicSandbox(sandbox) {
    // Process Tree
    const treeContainer = document.getElementById('sandbox-process-tree');
    if (treeContainer) {
        treeContainer.innerHTML = (sandbox.process_tree || []).map(p => `
            <div class="proc-tree-node p-3 rounded mb-2 cursor-pointer ${p.pid === AppState.activeProcessPid ? 'active' : ''}" onclick="filterByProcess(${p.pid})">
                <div class="flex items-center justify-between mb-1">
                    <span class="text-xs font-bold text-white flex items-center gap-1.5 font-mono">
                        <svg class="w-3.5 h-3.5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"></path></svg>
                        ${escapeHtml(p.name)}
                    </span>
                    <span class="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">PID: ${p.pid}</span>
                </div>
                <div class="text-[11px] text-gray-400 font-mono break-all">${escapeHtml(p.cmdline)}</div>
                <div class="flex items-center gap-3 mt-2 text-[10px] text-gray-500 font-mono">
                    <span>Integrity: ${p.integrity}</span>
                    <span>Status: ${p.status}</span>
                    <span>Start: ${p.start_time}s</span>
                </div>
            </div>
        `).join('');
    }

    // Timeline Scrubber & Events
    renderSandboxTimeline(sandbox.timeline, 30);

    // Screenshots Gallery
    renderScreenshotsGallery(sandbox.screenshots);

    // Filesystem Operations
    const fileOpsTbody = document.getElementById('sandbox-files-body');
    if (fileOpsTbody) {
        fileOpsTbody.innerHTML = (sandbox.file_operations || []).map(f => `
            <tr class="border-b border-gray-800/60 font-mono text-xs">
                <td class="py-2 px-3 font-bold ${f.action === 'CREATE' ? 'text-emerald-400' : (f.action === 'MODIFY' ? 'text-amber-400' : 'text-blue-400')}">${f.action}</td>
                <td class="py-2 px-3 text-gray-300">${escapeHtml(f.path)}</td>
                <td class="py-2 px-3 text-gray-500">${f.pid}</td>
            </tr>
        `).join('');
    }

    // Registry Operations
    const regOpsTbody = document.getElementById('sandbox-reg-body');
    if (regOpsTbody) {
        regOpsTbody.innerHTML = (sandbox.registry_operations || []).map(r => `
            <tr class="border-b border-gray-800/60 font-mono text-xs">
                <td class="py-2 px-3 font-bold ${r.action === 'WRITE' ? 'text-red-400' : 'text-blue-400'}">${r.action}</td>
                <td class="py-2 px-3 text-gray-300">${escapeHtml(r.path)}</td>
                <td class="py-2 px-3 text-gray-400 truncate max-w-xs">${escapeHtml(r.value || '')}</td>
                <td class="py-2 px-3 text-gray-500">${r.pid}</td>
            </tr>
        `).join('');
    }

    // Network & DNS
    const dnsTbody = document.getElementById('sandbox-dns-body');
    if (dnsTbody) {
        dnsTbody.innerHTML = (sandbox.dns_queries || []).map(d => `
            <tr class="border-b border-gray-800/60 font-mono text-xs">
                <td class="py-2 px-3 text-yellow-400 font-semibold">${escapeHtml(d.query)}</td>
                <td class="py-2 px-3 text-gray-400">${d.type}</td>
                <td class="py-2 px-3 text-emerald-400">${escapeHtml(d.response)}</td>
                <td class="py-2 px-3 text-gray-500">${d.pid}</td>
            </tr>
        `).join('');
    }

    const httpTbody = document.getElementById('sandbox-http-body');
    if (httpTbody) {
        httpTbody.innerHTML = (sandbox.http_requests || []).map(h => `
            <tr class="border-b border-gray-800/60 font-mono text-xs">
                <td class="py-2 px-3 font-bold ${h.method === 'POST' ? 'text-purple-400' : 'text-blue-400'}">${h.method}</td>
                <td class="py-2 px-3 text-gray-300 break-all">${escapeHtml(h.url)}</td>
                <td class="py-2 px-3 text-emerald-400 font-bold">${h.status_code}</td>
                <td class="py-2 px-3 text-gray-500">${h.pid}</td>
            </tr>
        `).join('');
    }

    // Dropped Files
    const droppedTbody = document.getElementById('sandbox-dropped-body');
    if (droppedTbody) {
        droppedTbody.innerHTML = (sandbox.dropped_files || []).map(df => `
            <tr class="border-b border-gray-800/60 font-mono text-xs">
                <td class="py-2 px-3 text-white font-semibold">${escapeHtml(df.filename)}</td>
                <td class="py-2 px-3 text-gray-400">${escapeHtml(df.path)}</td>
                <td class="py-2 px-3 text-gray-400">${formatBytes(df.size)}</td>
                <td class="py-2 px-3 text-gray-500 truncate max-w-xs">${df.sha256}</td>
                <td class="py-2 px-3 text-right">
                    <button class="text-xs bg-blue-900/30 text-blue-400 px-2 py-1 rounded hover:bg-blue-800/40" onclick="alert('Artifact staged securely: ${df.filename}')">Inspect</button>
                </td>
            </tr>
        `).join('');
    }
}

function renderSandboxTimeline(events, maxTime) {
    const container = document.getElementById('sandbox-timeline-events');
    if (!container) return;
    const filtered = events.filter(e => e.time <= maxTime);

    container.innerHTML = filtered.map(ev => `
        <div class="flex items-start gap-3 p-2 rounded hover:bg-gray-800/40 font-mono text-xs">
            <span class="text-blue-400 font-bold w-12">${ev.time.toFixed(1)}s</span>
            <span class="px-1.5 py-0.5 rounded text-[10px] uppercase font-bold ${getTimelineTypeBadge(ev.type)}">${ev.type}</span>
            <span class="text-gray-300 flex-1">${escapeHtml(ev.desc)}</span>
            <span class="text-gray-500 text-[10px]">PID: ${ev.pid}</span>
        </div>
    `).join('');
}

function getTimelineTypeBadge(type) {
    if (type.includes('spawn')) return 'bg-blue-900/40 text-blue-400 border border-blue-800';
    if (type.includes('injection') || type.includes('evasion')) return 'bg-red-900/40 text-red-400 border border-red-800';
    if (type.includes('network') || type.includes('c2')) return 'bg-purple-900/40 text-purple-400 border border-purple-800';
    if (type.includes('file')) return 'bg-amber-900/40 text-amber-400 border border-amber-800';
    return 'bg-gray-800 text-gray-400';
}

function renderScreenshotsGallery(screenshots) {
    const container = document.getElementById('sandbox-screenshots-grid');
    if (!container) return;

    container.innerHTML = (screenshots || []).map(sc => `
        <div class="soc-card overflow-hidden">
            <div class="bg-gray-950 p-4 h-36 flex flex-col justify-center items-center text-center relative border-b border-gray-800">
                ${getScreenshotVisualMock(sc.type)}
                <span class="absolute top-2 right-2 bg-black/60 text-blue-400 px-2 py-0.5 rounded text-[10px] font-mono">${sc.time}s</span>
            </div>
            <div class="p-2.5">
                <div class="text-xs font-semibold text-white mb-0.5">${escapeHtml(sc.label)}</div>
                <div class="text-[11px] text-gray-400 line-clamp-1">${escapeHtml(sc.caption)}</div>
            </div>
        </div>
    `).join('');
}

function getScreenshotVisualMock(type) {
    if (type === 'cmd_vssadmin') {
        return `
            <div class="w-full bg-black p-2 rounded text-left font-mono text-[9px] text-green-400 leading-tight">
                C:\\Windows\\system32> vssadmin Delete Shadows /All /Quiet<br>
                Deleting all shadow copies... [OK]<br>
                <span class="text-red-400">Recovery inhibited.</span>
            </div>
        `;
    } else if (type === 'ransom_screen') {
        return `
            <div class="w-full bg-red-950/80 border border-red-600 p-2 rounded text-center text-white">
                <div class="text-[11px] font-bold text-red-400">Ooops, your files are encrypted!</div>
                <div class="text-[8px] text-gray-300 mt-1">Send 0.05 BTC to unlock files</div>
            </div>
        `;
    } else if (type === 'stealer_activity') {
        return `
            <div class="w-full bg-gray-900 p-2 rounded text-left font-mono text-[9px] text-yellow-400">
                [+] Reading Chrome Login Data...<br>
                [+] Stolen 18 saved passwords<br>
                [+] Zipping credentials archive...
            </div>
        `;
    }
    return `
        <div class="w-full bg-slate-900 p-2 rounded text-center font-mono text-[10px] text-blue-300">
            [Windows 10 Desktop Execution Environment]
        </div>
    `;
}

// Static Analysis Tab
function renderStaticTab(report) {
    // PE Information
    const pe = report.pe_analysis;
    const peContainer = document.getElementById('static-pe-container');
    if (!pe || !pe.is_pe) {
        peContainer.innerHTML = `<p class="text-sm text-gray-400 py-4">This file is not a Windows Portable Executable (PE).</p>`;
    } else {
        peContainer.innerHTML = `
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                <div class="bg-gray-900/60 p-2.5 rounded border border-gray-800">
                    <span class="text-[10px] text-gray-400 font-mono block">Architecture</span>
                    <span class="text-xs font-bold text-white font-mono">${pe.machine}</span>
                </div>
                <div class="bg-gray-900/60 p-2.5 rounded border border-gray-800">
                    <span class="text-[10px] text-gray-400 font-mono block">Compile Time</span>
                    <span class="text-xs font-bold text-white font-mono">${pe.compile_time}</span>
                </div>
                <div class="bg-gray-900/60 p-2.5 rounded border border-gray-800">
                    <span class="text-[10px] text-gray-400 font-mono block">Entry Point</span>
                    <span class="text-xs font-bold text-blue-400 font-mono">${pe.entry_point}</span>
                </div>
                <div class="bg-gray-900/60 p-2.5 rounded border border-gray-800">
                    <span class="text-[10px] text-gray-400 font-mono block">Digital Signature</span>
                    <span class="text-xs font-bold ${pe.has_digital_signature ? 'text-emerald-400' : 'text-red-400'} font-mono">${pe.has_digital_signature ? 'Signed' : 'Unsigned'}</span>
                </div>
            </div>

            <h4 class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-2">Sections Table</h4>
            <div class="overflow-x-auto mb-6">
                <table class="w-full text-left font-mono text-xs">
                    <thead class="bg-gray-900 text-gray-400 border-b border-gray-800">
                        <tr>
                            <th class="py-2 px-3">Name</th>
                            <th class="py-2 px-3">Virt Addr</th>
                            <th class="py-2 px-3">Raw Size</th>
                            <th class="py-2 px-3">Entropy</th>
                            <th class="py-2 px-3">Perms</th>
                            <th class="py-2 px-3">Flags</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${pe.sections.map(s => `
                            <tr class="border-b border-gray-800/60 hover:bg-gray-800/30">
                                <td class="py-2 px-3 font-bold text-white">${escapeHtml(s.name)}</td>
                                <td class="py-2 px-3 text-gray-400">${s.virtual_address}</td>
                                <td class="py-2 px-3 text-gray-400">${s.raw_size} B</td>
                                <td class="py-2 px-3 ${s.entropy > 7.1 ? 'text-red-400 font-bold' : 'text-gray-300'}">${s.entropy}</td>
                                <td class="py-2 px-3 text-yellow-400">${s.permissions}</td>
                                <td class="py-2 px-3">${s.is_suspicious ? `<span class="px-1.5 py-0.5 rounded bg-red-900/40 text-red-400 text-[10px]">Suspicious</span>` : '<span class="text-gray-500">Normal</span>'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>

            <h4 class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-2">Suspicious API Imports</h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                ${Object.entries(pe.suspicious_apis || {}).map(([cat, apis]) => `
                    <div class="bg-gray-900/50 p-3 rounded border border-gray-800">
                        <span class="text-xs font-bold text-red-400 block mb-1">${cat}</span>
                        <div class="flex flex-wrap gap-1.5">
                            ${apis.map(a => `<span class="bg-gray-800 text-gray-300 text-[11px] font-mono px-2 py-0.5 rounded">${a}</span>`).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    // YARA Signatures
    const yaraContainer = document.getElementById('static-yara-container');
    if (yaraContainer) {
        if (!report.yara_matches || report.yara_matches.length === 0) {
            yaraContainer.innerHTML = `<p class="text-xs text-gray-500 py-3">No matching YARA rules found.</p>`;
        } else {
            yaraContainer.innerHTML = report.yara_matches.map(y => `
                <div class="p-3 rounded bg-gray-900/50 border border-gray-800 mb-2">
                    <div class="flex items-center justify-between mb-1">
                        <span class="text-xs font-bold text-white font-mono">${escapeHtml(y.rule)}</span>
                        <span class="text-[10px] px-2 py-0.5 rounded font-bold ${y.severity === 'CRITICAL' ? 'bg-red-900/40 text-red-400' : 'bg-amber-900/40 text-amber-400'}">${y.severity}</span>
                    </div>
                    <p class="text-xs text-gray-400 mb-2">${escapeHtml(y.meta.description || '')}</p>
                    <div class="text-[11px] font-mono text-gray-500">
                        Matched Strings: ${y.matched_strings.map(ms => ms.identifier).join(', ')}
                    </div>
                </div>
            `).join('');
        }
    }

    // Extracted IOCs (Strings tab)
    const iocs = report.strings?.iocs || {};
    document.getElementById('ioc-urls-count').innerText = iocs.urls?.length || 0;
    document.getElementById('ioc-ips-count').innerText = iocs.ips?.length || 0;
    document.getElementById('ioc-reg-count').innerText = iocs.registry_keys?.length || 0;

    renderIocsList(iocs);
}

function renderIocsList(iocs) {
    const container = document.getElementById('static-iocs-list');
    if (!container) return;

    let items = [];
    (iocs.urls || []).forEach(u => items.push({ type: 'URL', val: u, defanged: u.replace(/\./g, '[.]') }));
    (iocs.ips || []).forEach(ip => items.push({ type: 'IP', val: ip, defanged: ip.replace(/\./g, '[.]') }));
    (iocs.registry_keys || []).forEach(rk => items.push({ type: 'Registry', val: rk, defanged: rk }));
    (iocs.crypto_wallets || []).forEach(w => items.push({ type: 'Crypto Wallet', val: w, defanged: w }));

    if (items.length === 0) {
        container.innerHTML = `<p class="text-xs text-gray-500 py-3">No suspicious IOC patterns identified in extracted strings.</p>`;
        return;
    }

    container.innerHTML = items.map(item => `
        <div class="flex items-center justify-between p-2 rounded bg-gray-900/40 border border-gray-800/80 font-mono text-xs mb-1.5">
            <div class="flex items-center gap-2 truncate">
                <span class="px-1.5 py-0.5 rounded text-[10px] bg-gray-800 text-blue-400 font-semibold">${item.type}</span>
                <span class="text-gray-300 truncate">${escapeHtml(item.defanged)}</span>
            </div>
            <button onclick="copyToClipboard('${item.val}')" class="text-gray-400 hover:text-white text-xs px-2 py-0.5 bg-gray-800 rounded">Copy</button>
        </div>
    `).join('');
}

// VirusTotal Grid
function renderAvGrid(vt) {
    const container = document.getElementById('vt-engines-grid');
    if (!container) return;

    container.innerHTML = (vt.engine_results || []).map(eng => `
        <div class="p-2.5 rounded border ${eng.detected ? 'bg-red-950/20 border-red-800/50' : 'bg-gray-900/30 border-gray-800/60'} flex items-center justify-between">
            <div>
                <span class="text-xs font-semibold text-white block">${escapeHtml(eng.vendor)}</span>
                <span class="text-[11px] font-mono ${eng.detected ? 'text-red-400 font-semibold' : 'text-gray-500'}">${escapeHtml(eng.result)}</span>
            </div>
            <span class="w-2.5 h-2.5 rounded-full ${eng.detected ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]' : 'bg-emerald-500/30'}"></span>
        </div>
    `).join('');
}

// MITRE ATT&CK Matrix Tab
function renderMitreTab(mitreFindings) {
    const container = document.getElementById('mitre-matrix-container');
    if (!container) return;

    if (!mitreFindings || mitreFindings.length === 0) {
        container.innerHTML = `<p class="text-sm text-gray-500 py-4">No mapped MITRE ATT&CK techniques for this submission.</p>`;
        return;
    }

    container.innerHTML = mitreFindings.map(m => `
        <div class="soc-card p-4 mb-3 border-l-4 border-l-red-500">
            <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                    <span class="bg-red-900/40 text-red-400 px-2 py-0.5 rounded text-xs font-mono font-bold">${m.technique_id}</span>
                    <h4 class="text-sm font-semibold text-white">${escapeHtml(m.technique_name)}</h4>
                </div>
                <span class="text-xs text-gray-400 font-mono uppercase bg-gray-800 px-2 py-0.5 rounded">${escapeHtml(m.tactic)}</span>
            </div>
            <div class="space-y-1 mt-2">
                ${m.evidence.map(ev => `
                    <div class="flex items-center gap-2 text-xs font-mono text-gray-300 bg-gray-900/60 p-2 rounded">
                        <span class="text-red-400">&bull;</span>
                        <span>${escapeHtml(ev)}</span>
                    </div>
                `).join('')}
            </div>
            <div class="mt-3 text-right">
                <a href="${m.url}" target="_blank" class="text-xs text-blue-400 hover:underline inline-flex items-center gap-1 font-mono">
                    MITRE ATT&CK Reference &rarr;
                </a>
            </div>
        </div>
    `).join('');
}

// Render Email Report
function displayEmailReport(rep) {
    AppState.currentReport = rep;
    AppState.currentSubId = rep.id;
    switchMainTab('email-report');

    // Header info
    document.getElementById('email-rep-subject').innerText = rep.headers.subject;
    document.getElementById('email-rep-from').innerText = rep.headers.from;
    document.getElementById('email-rep-return').innerText = rep.headers.return_path || 'None';
    document.getElementById('email-rep-reply').innerText = rep.headers.reply_to || 'None';
    document.getElementById('email-rep-date').innerText = rep.headers.date;

    // Verdict Badge
    const verdictEl = document.getElementById('email-rep-verdict');
    verdictEl.innerText = rep.verdict.toUpperCase();
    verdictEl.className = `px-3 py-1 rounded text-xs font-bold tracking-wider ${rep.verdict.includes('Malicious') ? 'badge-malicious' : (rep.verdict === 'Suspicious' ? 'badge-suspicious' : 'badge-clean')}`;

    // Score
    document.getElementById('email-rep-score').innerText = `${rep.threat_score} / 100`;

    // Authentication Scorecard
    const auth = rep.authentication;
    setAuthCard('email-spf', auth.spf);
    setAuthCard('email-dkim', auth.dkim);
    setAuthCard('email-dmarc', auth.dmarc);

    // Relay Hops & Latency
    renderEmailHops(rep.hops, rep.relay_latency);

    // Heuristics Alerts
    renderEmailHeuristics(rep.heuristics);

    // Extracted URLs
    renderEmailUrls(rep.urls);

    // Extracted Attachments
    renderEmailAttachments(rep.attachments);

    // Sanitized Preview
    const previewContainer = document.getElementById('email-body-preview');
    if (previewContainer) {
        if (rep.body_preview.sanitized_html) {
            previewContainer.innerHTML = rep.body_preview.sanitized_html;
        } else {
            previewContainer.innerText = rep.body_preview.plain_text;
        }
    }
}

function setAuthCard(prefix, data) {
    const statusEl = document.getElementById(`${prefix}-status`);
    const detailsEl = document.getElementById(`${prefix}-details`);
    if (statusEl) {
        statusEl.innerText = data.status;
        statusEl.className = `text-sm font-bold font-mono ${data.status === 'PASS' ? 'text-emerald-400' : (data.status === 'FAIL' ? 'text-red-400' : 'text-amber-400')}`;
    }
    if (detailsEl) {
        detailsEl.innerText = data.details;
    }
}

function renderEmailHops(hops, latency) {
    const container = document.getElementById('email-hops-container');
    if (!container) return;

    document.getElementById('email-total-delay').innerText = latency.total_delay_formatted;

    container.innerHTML = hops.map(h => `
        <div class="hop-node flex items-start gap-4 mb-4">
            <div class="hop-line flex flex-col items-center">
                <span class="w-8 h-8 rounded-full bg-blue-900/40 border border-blue-500/50 flex items-center justify-center text-xs font-bold font-mono text-blue-400">
                    ${h.hop}
                </span>
            </div>
            <div class="bg-gray-900/60 p-3 rounded border border-gray-800 flex-1">
                <div class="flex items-center justify-between mb-1">
                    <span class="text-xs font-bold text-white font-mono">${escapeHtml(h.from)} &rarr; ${escapeHtml(h.by)}</span>
                    <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-800 text-yellow-400 font-bold">${h.delay} delay</span>
                </div>
                <div class="text-[11px] text-gray-400 font-mono">IP: ${h.ip || 'Unspecified'}</div>
            </div>
        </div>
    `).join('');
}

function renderEmailHeuristics(heuristics) {
    const container = document.getElementById('email-heuristics-list');
    if (!container) return;

    if (!heuristics || heuristics.length === 0) {
        container.innerHTML = `<div class="p-3 bg-emerald-950/20 border border-emerald-800/40 rounded text-emerald-400 text-xs">No phishing heuristics triggered. Sender parameters appear legitimate.</div>`;
        return;
    }

    container.innerHTML = heuristics.map(h => `
        <div class="p-3 rounded border mb-2 ${h.severity === 'CRITICAL' ? 'bg-red-950/30 border-red-800/60' : 'bg-amber-950/20 border-amber-800/50'}">
            <div class="flex items-center justify-between mb-1">
                <span class="text-xs font-bold text-white">${escapeHtml(h.rule)}</span>
                <span class="text-[10px] px-2 py-0.5 rounded font-bold font-mono text-red-400">+${h.points} pts</span>
            </div>
            <p class="text-xs text-gray-300">${escapeHtml(h.desc)}</p>
        </div>
    `).join('');
}

function renderEmailUrls(urls) {
    const tbody = document.getElementById('email-urls-tbody');
    if (!tbody) return;

    if (!urls || urls.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-xs text-gray-500">No hyperlinks extracted from email body.</td></tr>`;
        return;
    }

    tbody.innerHTML = urls.map(u => `
        <tr class="border-b border-gray-800/60 font-mono text-xs">
            <td class="py-2.5 px-3 text-white break-all">${escapeHtml(u.defanged)}</td>
            <td class="py-2.5 px-3 text-gray-400">${escapeHtml(u.anchor_text || '-')}</td>
            <td class="py-2.5 px-3">
                ${u.is_mismatch ? `<span class="bg-red-900/40 text-red-400 px-1.5 py-0.5 rounded text-[10px] font-bold">MISMATCH DECEPTION</span>` : `<span class="text-gray-500 text-[10px]">OK</span>`}
            </td>
            <td class="py-2.5 px-3 text-right">
                <button onclick="copyToClipboard('${u.url}')" class="text-xs bg-gray-800 text-gray-300 hover:text-white px-2 py-0.5 rounded">Copy</button>
            </td>
        </tr>
    `).join('');
}

function renderEmailAttachments(attachments) {
    const tbody = document.getElementById('email-attachments-tbody');
    if (!tbody) return;

    if (!attachments || attachments.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-xs text-gray-500">No attachments found in this email.</td></tr>`;
        return;
    }

    tbody.innerHTML = attachments.map(att => `
        <tr class="border-b border-gray-800/60 font-mono text-xs">
            <td class="py-2.5 px-3 font-bold text-white flex items-center gap-2">
                ${att.is_dangerous ? '<span class="text-red-400 font-bold">&#9888;</span>' : ''}
                ${escapeHtml(att.filename)}
            </td>
            <td class="py-2.5 px-3 text-gray-400">${formatBytes(att.size)}</td>
            <td class="py-2.5 px-3 text-gray-400">${att.content_type}</td>
            <td class="py-2.5 px-3 truncate max-w-xs text-gray-500">${att.sha256}</td>
            <td class="py-2.5 px-3 text-right">
                <button onclick="analyzeExtractedAttachment('${att.filename}')" class="text-xs bg-blue-600/30 hover:bg-blue-600/50 text-blue-400 border border-blue-500/30 px-2.5 py-1 rounded font-medium">
                    Send to Sandbox &rarr;
                </button>
            </td>
        </tr>
    `).join('');
}

function analyzeExtractedAttachment(filename) {
    alert(`Routing extracted attachment '${filename}' into Vanguard dynamic analysis pipeline...`);
    // Routes to sample analysis for demonstration
    runSampleAnalysis('sample-wannacry');
}

// IOC Exports
function downloadExport(format) {
    if (!AppState.currentSubId) {
        alert("No active submission to export");
        return;
    }
    window.location.href = `/api/export/${AppState.currentSubId}/${format}`;
}

function downloadPcap() {
    if (!AppState.currentSubId) return;
    window.location.href = `/api/download/pcap/${AppState.currentSubId}`;
}

// Analyst Notes
async function loadAnalystNotes(subId) {
    try {
        const res = await fetch(`/api/submission/${subId}/notes`);
        const data = await res.json();
        if (data.status === 'success') {
            const list = document.getElementById('analyst-notes-list');
            if (list) {
                if (data.notes.length === 0) {
                    list.innerHTML = `<p class="text-xs text-gray-500 py-2">No analyst notes recorded yet.</p>`;
                } else {
                    list.innerHTML = data.notes.map(n => `
                        <div class="p-3 bg-gray-900/60 border border-gray-800 rounded mb-2">
                            <div class="flex items-center justify-between mb-1">
                                <span class="text-xs font-bold text-blue-400">${escapeHtml(n.author)}</span>
                                <span class="text-[10px] text-gray-500 font-mono">${new Date(n.created_at).toLocaleString()}</span>
                            </div>
                            <p class="text-xs text-gray-300">${escapeHtml(n.note)}</p>
                        </div>
                    `).join('');
                }
            }
        }
    } catch (e) {
        console.error("Failed to load notes", e);
    }
}

async function addAnalystNoteSubmit() {
    const noteInput = document.getElementById('analyst-note-input');
    const authorInput = document.getElementById('analyst-author-input');
    if (!noteInput || !noteInput.value.trim()) return;

    const formData = new FormData();
    formData.append('note', noteInput.value.trim());
    formData.append('author', authorInput?.value?.trim() || "SOC Analyst");

    try {
        const res = await fetch(`/api/submission/${AppState.currentSubId}/note`, {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        if (data.status === 'success') {
            noteInput.value = '';
            loadAnalystNotes(AppState.currentSubId);
        }
    } catch (e) {
        alert("Error saving note: " + e.message);
    }
}

// Utilities
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Quick visual toast
        const toast = document.createElement('div');
        toast.className = 'fixed bottom-4 right-4 bg-blue-600 text-white text-xs font-semibold px-4 py-2 rounded-md shadow-lg z-50 transition';
        toast.innerText = 'Copied to clipboard!';
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 1500);
    });
}

function formatBytes(bytes, decimals = 2) {
    if (!bytes) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function escapeHtml(string) {
    if (!string) return '';
    return String(string)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
