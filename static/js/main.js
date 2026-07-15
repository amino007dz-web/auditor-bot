let abortController = null;
let currentReportText = '';
let chartInstance = null;

function $(id) { return document.getElementById(id); }

function qs(sel) { return document.querySelector(sel); }

function qsa(sel) { return document.querySelectorAll(sel); }

const el = {
  resultsBody: $('resultsBody'),
  resultsTitle: $('resultsTitle'),
  resultsActions: $('resultsActions'),
  resultsTabs: $('resultsTabs'),
  analyzeBtn: $('analyzeBtn'),
  fileInput: $('fileInput'),
  browseBtn: $('browseBtn'),
  fileInfo: $('fileInfo'),
  analysisType: $('analysisType'),
  themeToggle: $('themeToggle'),
  historyBtn: $('historyBtn'),
  historyPanel: $('historyPanel'),
  historyClose: $('historyClose'),
  historyList: $('historyList'),
  chartModal: $('chartModal'),
  chartClose: $('chartClose'),
  severityChart: $('severityChart'),
  codePane: $('codePane'),
  pasteSection: $('pasteSection'),
  uploadSection: $('uploadSection'),
  diffSection: $('diffSection'),
  diffOriginal: $('diffOriginal'),
  diffModified: $('diffModified'),
  downloadMd: $('downloadMd'),
  downloadSarif: $('downloadSarif'),
  toggleChart: $('toggleChart'),
  exportGithub: $('exportGithub'),
};

document.addEventListener('DOMContentLoaded', function () {
  const savedTheme = localStorage.getItem('auditor-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  el.themeToggle.innerHTML = savedTheme === 'dark' ? '<i class="fas fa-moon"></i>' : '<i class="fas fa-sun"></i>';

  el.themeToggle.addEventListener('click', function () {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('auditor-theme', next);
    el.themeToggle.innerHTML = next === 'dark' ? '<i class="fas fa-moon"></i>' : '<i class="fas fa-sun"></i>';
  });

  el.historyBtn.addEventListener('click', function () { el.historyPanel.style.display = 'block'; });
  el.historyClose.addEventListener('click', function () { el.historyPanel.style.display = 'none'; });

  el.chartClose.addEventListener('click', function () { el.chartModal.style.display = 'none'; });
  el.chartModal.addEventListener('click', function (e) { if (e.target === el.chartModal) el.chartModal.style.display = 'none'; });

  el.analyzeBtn.addEventListener('click', startAnalysis);

  qsa('[data-tab]').forEach(function (tab) {
    tab.addEventListener('click', function () {
      const t = tab.dataset.tab;
      if (t === 'paste' || t === 'upload' || t === 'diff') switchCodeTab(t);
      else if (t === 'report' || t === 'chart') switchResultTab(t);
    });
  });

  el.browseBtn.addEventListener('click', function () { el.fileInput.click(); });
  el.fileInput.addEventListener('change', handleFileUpload);

  el.codePane.addEventListener('dragover', function (e) { e.preventDefault(); el.codePane.classList.add('dragover'); });
  el.codePane.addEventListener('dragleave', function () { el.codePane.classList.remove('dragover'); });
  el.codePane.addEventListener('drop', function (e) {
    e.preventDefault();
    el.codePane.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      el.fileInput.files = e.dataTransfer.files;
      handleFileUpload();
    }
  });

  el.downloadMd.addEventListener('click', function () { downloadReport('md'); });
  el.downloadSarif.addEventListener('click', function () { downloadReport('sarif'); });
  el.toggleChart.addEventListener('click', function () { showChart(); });
  el.exportGithub.addEventListener('click', exportToGithub);

  loadHistory();
});

function switchCodeTab(tab) {
  qsa('[data-tab^="paste"],[data-tab^="upload"],[data-tab^="diff"]').forEach(function (t) {
    if (t.dataset.tab === tab) t.style.background = 'var(--accent)'; else t.style.background = '';
  });
  ['pasteSection', 'uploadSection', 'diffSection'].forEach(function (id) {
    el[id].style.display = id.replace('Section', '') === tab ? 'flex' : 'none';
  });
  if (tab === 'paste') window.editor.refresh();
}

function switchResultTab(tab) {
  qsa('.results-tab').forEach(function (t) {
    t.classList.toggle('active', t.dataset.tab === tab);
  });
  if (tab === 'chart') { showChart(); el.resultsBody.style.display = 'none'; } else { el.resultsBody.style.display = 'block'; el.chartModal.style.display = 'none'; }
}

function handleFileUpload() {
  const file = el.fileInput.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function (e) {
    window.editor.setValue(e.target.result);
    switchCodeTab('paste');
  };
  reader.readAsText(file);
}

function getCode() {
  const active = document.querySelector('[data-tab].active-tab');
  if (el.uploadSection && el.uploadSection.style.display !== 'none') return null;
  if (el.diffSection && el.diffSection.style.display !== 'none') {
    return JSON.stringify({ original: el.diffOriginal.value, modified: el.diffModified.value });
  }
  return window.editor.getValue();
}

function startAnalysis() {
  if (abortController) { abortController.abort(); abortController = null; }

  const activeTab = document.querySelector('[data-tab]:not(.results-tab)');
  const tab = activeTab ? activeTab.dataset.tab : 'paste';

  let code;
  let endpoint = '/api/analyze/stream';
  let body;

  if (tab === 'diff') {
    code = getCode();
    endpoint = '/api/analyze/diff';
    body = JSON.stringify({ old_code: el.diffOriginal.value, new_code: el.diffModified.value });
  } else {
    code = window.editor.getValue();
    body = JSON.stringify({ code: code, type: el.analysisType.value });
  }

  if (!code || (tab !== 'diff' && !code.trim())) {
    el.resultsBody.innerHTML = '<p style="color:var(--accent-red);">Please enter or upload code first.</p>';
    return;
  }

  abortController = new AbortController();
  el.resultsActions.style.display = 'none';
  el.resultsTabs.style.display = 'none';
  el.resultsTitle.textContent = 'Analyzing...';
  el.resultsBody.innerHTML = renderSkeleton();
  el.analyzeBtn.disabled = true;
  el.analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
  currentReportText = '';

  fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body,
    signal: abortController.signal
  }).then(function (resp) {
    if (!resp.ok) throw new Error('Analysis failed: ' + resp.status);
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    function read() {
      reader.read().then(function (result) {
        if (result.done) { finalizeAnalysis(); return; }
        buffer += decoder.decode(result.value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop();
        parts.forEach(function (part) {
          if (part.startsWith('data: ')) {
            const data = part.slice(6).trim();
            if (data === '[DONE]') { finalizeAnalysis(); return; }
            try {
              const parsed = JSON.parse(data);
              if (parsed.error) throw new Error(parsed.error);
              if (parsed.step) { updateStep(parsed.step); }
              if (parsed.type === 'token' && parsed.text) {
                currentReportText += parsed.text;
                renderStreamingReport(currentReportText);
              }
              if (parsed.type === 'final' && parsed.report) {
                currentReportText = parsed.report;
                renderFinalReport(parsed.report);
              }
            } catch (e) { if (e.message !== 'Unexpected end of JSON input') throw e; }
          }
        });
        read();
      }).catch(function (err) {
        if (err.name !== 'AbortError') { el.resultsBody.innerHTML = '<p style="color:var(--accent-red);">Error: ' + err.message + '</p>'; }
        el.analyzeBtn.disabled = false;
        el.analyzeBtn.innerHTML = '<i class="fas fa-play"></i> Analyze';
      });
    }
    read();
  }).catch(function (err) {
    if (err.name !== 'AbortError') { el.resultsBody.innerHTML = '<p style="color:var(--accent-red);">Error: ' + err.message + '</p>'; }
    el.analyzeBtn.disabled = false;
    el.analyzeBtn.innerHTML = '<i class="fas fa-play"></i> Analyze';
  });
}

function renderSkeleton() {
  return '<div class="skeleton w-75"></div><div class="skeleton w-50"></div><div class="skeleton w-90"></div><div class="skeleton w-75"></div><div class="skeleton w-50"></div>';
}

function updateStep(step) {
  el.resultsTitle.textContent = step;
}

let typewriterTimer = null;

function renderStreamingReport(text) {
  if (typewriterTimer) { clearTimeout(typewriterTimer); }
  typewriterTimer = setTimeout(function () {
    const rendered = marked.parse(text);
    const sanitized = DOMPurify.sanitize(rendered);
    el.resultsBody.innerHTML = buildAccordion(sanitized);
    el.resultsBody.scrollTop = el.resultsBody.scrollHeight;
  }, 50);
}

function renderFinalReport(report) {
  const rendered = marked.parse(report);
  const sanitized = DOMPurify.sanitize(rendered);
  el.resultsBody.innerHTML = buildAccordion(sanitized);
  el.resultsActions.style.display = 'flex';
  el.resultsTabs.style.display = 'flex';
  el.resultsTitle.textContent = 'Report - ' + countSeverities(report);
  showChart();
  saveToHistory(report);
}

function buildAccordion(html) {
  const severityMap = {
    'critical': { icon: '🔴', color: 'var(--accent-red)' },
    'high': { icon: '🟠', color: '#d29922' },
    'medium': { icon: '🔵', color: 'var(--accent)' },
    'low': { icon: '🟢', color: 'var(--accent-green)' },
    'info': { icon: 'ℹ️', color: 'var(--text-secondary)' }
  };

  const sections = html.split(/<h[23][^>]*>/gi);
  if (sections.length < 2) return html;

  let result = '';
  for (let i = 0; i < sections.length; i++) {
    const section = sections[i];
    const tagStart = section.indexOf('<');
    const afterClose = tagStart >= 0 ? section.slice(tagStart) : section;
    const headingText = tagStart >= 0 ? section.slice(0, tagStart).trim() : '';

    let severity = 'info';
    const lower = (headingText || section).toLowerCase();
    for (const key in severityMap) {
      if (lower.includes(key)) { severity = key; break; }
    }

    const sev = severityMap[severity];

    if (i === 0) {
      result += '<div class="finding-card">';
      result += '<div class="finding-header" onclick="this.nextElementSibling.classList.toggle(\'open\')">';
      result += '<div><span class="severity-icon">📋</span><span class="finding-title">Summary</span></div>';
      result += '<span class="chevron">▼</span></div>';
      result += '<div class="finding-body open">' + section + '</div></div>';
    } else {
      result += '<div class="finding-card" style="border-left:3px solid ' + sev.color + ';">';
      result += '<div class="finding-header" onclick="this.nextElementSibling.classList.toggle(\'open\')">';
      result += '<div><span class="severity-icon">' + sev.icon + '</span><span class="finding-title">' + headingText + '</span></div>';
      result += '<span class="chevron">▼</span></div>';
      result += '<div class="finding-body open">' + afterClose + '</div></div>';
    }
  }
  return result;
}

function finalizeAnalysis() {
  el.analyzeBtn.disabled = false;
  el.analyzeBtn.innerHTML = '<i class="fas fa-play"></i> Analyze';
  abortController = null;
}

function countSeverities(text) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  const lines = text.split('\n');
  for (const key in counts) {
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith(key + ' ') || trimmed.startsWith(key + ':')) counts[key]++;
    }
  }
  const total = counts.Critical + counts.High + counts.Medium + counts.Low + counts.Info;
  if (total === 0) return '';
  return counts.Critical + 'C ' + counts.High + 'H ' + counts.Medium + 'M ' + counts.Low + 'L ' + counts.Info + 'I';
}

function showChart() {
  el.chartModal.style.display = 'flex';
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  const lines = currentReportText.split('\n');
  for (const key in counts) {
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith(key + ' ') || trimmed.startsWith(key + ':')) counts[key]++;
    }
  }
  if (chartInstance) { chartInstance.destroy(); chartInstance = null; }
  chartInstance = new Chart(el.severityChart, {
    type: 'bar',
    data: {
      labels: Object.keys(counts),
      datasets: [{
        label: 'Findings',
        data: Object.values(counts),
        backgroundColor: ['#da3633', '#d29922', '#58a6ff', '#3fb950', '#8b949e'],
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, ticks: { stepSize: 1, color: '#8b949e' }, grid: { color: '#30363d' } },
        x: { ticks: { color: '#8b949e' } }
      }
    }
  });
}

function saveToHistory(report) {
  let history = [];
  try { history = JSON.parse(localStorage.getItem('auditor-history') || '[]'); } catch (e) {}
  const snippet = report.slice(0, 500);
  history.unshift({ snippet: snippet, date: new Date().toISOString(), full: report });
  if (history.length > 5) history = history.slice(0, 5);
  localStorage.setItem('auditor-history', JSON.stringify(history.map(function (h) { return { snippet: h.snippet, date: h.date }; })));
  loadHistory();
}

function loadHistory() {
  let history = [];
  try { history = JSON.parse(localStorage.getItem('auditor-history') || '[]'); } catch (e) {}
  el.historyList.innerHTML = history.length === 0
    ? '<p style="color:var(--text-secondary);font-size:0.8rem;">No previous audits.</p>'
    : history.map(function (h, i) {
        return '<div class="history-item" data-idx="' + i + '" style="padding:0.6rem;border:1px solid var(--border);border-radius:6px;margin-bottom:0.5rem;cursor:pointer;font-size:0.8rem;">' +
          '<div style="color:var(--text-primary);margin-bottom:0.25rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + h.snippet.slice(0, 80) + '...</div>' +
          '<div style="color:var(--text-secondary);font-size:0.7rem;">' + new Date(h.date).toLocaleString() + '</div></div>';
      }).join('');
  el.historyList.querySelectorAll('.history-item').forEach(function (item) {
    item.addEventListener('click', function () { loadHistoryItem(parseInt(item.dataset.idx)); });
  });
}

function loadHistoryItem(idx) {
  let history = [];
  try { history = JSON.parse(localStorage.getItem('auditor-history') || '[]'); } catch (e) {}
  if (history[idx]) {
    el.historyPanel.style.display = 'none';
    el.resultsBody.innerHTML = DOMPurify.sanitize(marked.parse(history[idx].snippet));
    el.resultsActions.style.display = 'flex';
    el.resultsTabs.style.display = 'flex';
    el.resultsTitle.textContent = 'History - ' + new Date(history[idx].date).toLocaleString();
  }
}

function downloadReport(format) {
  if (!currentReportText) return;
  const blob = new Blob([currentReportText], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'audit-report.' + format;
  a.click();
  URL.revokeObjectURL(url);
}

function exportToGithub() {
  if (!currentReportText) return;
  const formatted = formatGithubDiscussion(currentReportText);
  navigator.clipboard.writeText(formatted).then(function () {
    alert('GitHub Discussion format copied to clipboard!');
  });
}

function formatGithubDiscussion(text) {
  return '# Smart Contract Audit Report\n\n' +
    '## Summary\n\n' + text.split('\n').slice(0, 20).join('\n') + '\n\n' +
    '## Finding Details\n\n' + text + '\n\n' +
    '## Severity Distribution\n\n' + countSeverities(text) + '\n\n' +
    '---\n*Generated by Smart Contract Auditor*';
}
