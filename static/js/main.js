let uploadedFile = null;
let currentCode = '';
let analysisAbortController = null;

function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
    document.getElementById(`tab-${tab}`).classList.add('active');
}

const dropZone = document.getElementById('dropZone');
if (dropZone) {
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            document.getElementById('fileInput').files = files;
            uploadedFile = files[0];
            document.getElementById('fileInfo').textContent = uploadedFile.name + ' (' + (uploadedFile.size / 1024).toFixed(1) + ' KB)';
            document.getElementById('fileInfo').classList.remove('hidden');
        }
    });
    dropZone.addEventListener('click', () => document.getElementById('fileInput').click());
}

function updateStep(step, status) {
    const el = document.querySelector(`[data-step="${step}"]`);
    if (!el) return;
    el.className = 'step';
    if (status === 'active') el.classList.add('step-active');
    if (status === 'done') el.classList.add('step-done');
}

function renderReport(markdown) {
    if (typeof marked !== 'undefined') {
        return marked.parse(markdown);
    }
    let html = markdown
        .replace(/### (.*)/g, '<h3>$1</h3>')
        .replace(/## (.*)/g, '<h2>$1</h2>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\n/g, '<br>');
    return html;
}

function renderChart(severityCounts) {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;
    if (typeof Chart === 'undefined') return;
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [
                    severityCounts.critical || 0,
                    severityCounts.high || 0,
                    severityCounts.medium || 0,
                    severityCounts.low || 0,
                    severityCounts.info || 0
                ],
                backgroundColor: ['#da3633', '#d29922', '#58a6ff', '#8b949e', '#238636'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#c9d1d9' } }
            }
        }
    });
}

function downloadMarkdown(text) {
    const blob = new Blob([text], { type: 'text/markdown' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'audit_report.md';
    a.click();
    URL.revokeObjectURL(a.href);
}

function downloadSarif(report, code) {
    fetch('/api/sarif', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ report, code })
    }).then(r => r.blob()).then(blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'audit.sarif';
        a.click();
        URL.revokeObjectURL(a.href);
    });
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copyBtn');
        if (btn) { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = 'Copy to Clipboard'; }, 2000); }
    });
}

function countSeverities(text) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const lower = text.toLowerCase();
    const lines = lower.split('\n');
    for (const line of lines) {
        for (const key of Object.keys(counts)) {
            if (line.includes('### ' + key) || line.includes('## ' + key) || line.includes('**' + key) || line.includes(key + ' severity')) {
                counts[key]++;
                break;
            }
        }
    }
    return counts;
}

function startAnalysis(code) {
    if (analysisAbortController) analysisAbortController.abort();
    analysisAbortController = new AbortController();
    currentCode = '';
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    if (loading) loading.classList.remove('hidden');
    if (results) results.classList.add('hidden');
    updateStep(1, 'active');

    fetch('/api/analyze/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
        signal: analysisAbortController.signal
    }).then(async (response) => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';
            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    let data;
                    try { data = JSON.parse(line.slice(6)); } catch (e) { console.warn('SSE parse error:', line.slice(0, 80)); continue; }
                    if (data.type === 'meta' && data.message) {
                        document.getElementById('loadingText').textContent = data.message;
                    }
                    if (data.type === 'step') {
                        updateStep(data.step, data.status);
                    }
                    if (data.type === 'token') {
                        currentCode += data.text;
                        document.getElementById('reportContent').innerHTML = renderReport(currentCode);
                    }
                    if (data.type === 'final') {
                        currentCode = data.report;
                        document.getElementById('reportContent').innerHTML = renderReport(currentCode);
                        const sev = countSeverities(currentCode);
                        renderChart(sev);
                        document.getElementById('severityCounts').textContent =
                            'Critical: ' + sev.critical + ' | High: ' + sev.high + ' | Medium: ' + sev.medium + ' | Low: ' + sev.low + ' | Info: ' + sev.info;
                    }
                }
            }
        }
        if (loading) loading.classList.add('hidden');
        if (results) results.classList.remove('hidden');
    }).catch(err => {
        if (err.name !== 'AbortError') {
            console.error('Stream error:', err);
            document.getElementById('loadingText').textContent = 'Error: ' + err.message;
        }
    });
}
