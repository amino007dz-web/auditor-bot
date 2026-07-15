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
  knowledgeBtn: $('knowledgeBtn'),
  knowledgeModal: $('knowledgeModal'),
  knowledgeClose: $('knowledgeClose'),
  knowledgeInput: $('knowledgeInput'),
  browseKnowledgeBtn: $('browseKnowledgeBtn'),
  knowledgeFileInfo: $('knowledgeFileInfo'),
  knowledgeResult: $('knowledgeResult'),
  uploadKnowledgeBtn: $('uploadKnowledgeBtn'),
  gasBtn: $('gasBtn'),
  fixBtn: $('fixBtn'),
  entryContract: $('entryContract'),
  langSelect: $('langSelect'),
  githubSection: $('githubSection'),
  githubUrl: $('githubUrl'),
  githubFileInfo: $('githubFileInfo'),
  codePane: $('codePane'),
  pasteSection: $('pasteSection'),
  uploadSection: $('uploadSection'),
  diffSection: $('diffSection'),
  diffOriginal: $('diffOriginal'),
  diffModified: $('diffModified'),
  downloadMd: $('downloadMd'),
  downloadSarif: $('downloadSarif'),
  downloadPdf: $('downloadPdf'),
  toggleChart: $('toggleChart'),
  exportGithub: $('exportGithub'),
  projectInput: $('projectInput'),
  browseProjectBtn: $('browseProjectBtn'),
  projectFileInfo: $('projectFileInfo'),
  projectSection: $('projectSection'),
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

  el.knowledgeBtn.addEventListener('click', function () { el.knowledgeModal.style.display = 'flex'; });
  el.knowledgeClose.addEventListener('click', function () { el.knowledgeModal.style.display = 'none'; });
  el.knowledgeModal.addEventListener('click', function (e) { if (e.target === el.knowledgeModal) el.knowledgeModal.style.display = 'none'; });
  el.browseKnowledgeBtn.addEventListener('click', function () { el.knowledgeInput.click(); });
  el.knowledgeInput.addEventListener('change', handleKnowledgeFile);
  el.uploadKnowledgeBtn.addEventListener('click', uploadKnowledge);

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

  el.browseProjectBtn.addEventListener('click', function () { el.projectInput.click(); });
  el.projectInput.addEventListener('change', handleProjectUpload);

  el.downloadMd.addEventListener('click', function () { downloadReport('md'); });
  el.downloadSarif.addEventListener('click', function () { downloadReport('sarif'); });
  el.downloadPdf.addEventListener('click', function () { downloadReport('pdf'); });
  el.gasBtn.addEventListener('click', fetchGasReport);
  el.fixBtn.addEventListener('click', suggestFix);
  el.langSelect.addEventListener('change', function () { applyLang(el.langSelect.value); });
  el.toggleChart.addEventListener('click', function () { showChart(); });
  el.exportGithub.addEventListener('click', exportToGithub);
  el.githubUrl.addEventListener('keydown', function (e) { if (e.key === 'Enter') startAnalysis(); });

  loadHistory();
  loadQuota();
});

function switchCodeTab(tab) {
  qsa('[data-tab^="paste"],[data-tab^="upload"],[data-tab^="project"],[data-tab^="github"],[data-tab^="diff"]').forEach(function (t) {
    if (t.dataset.tab === tab) t.style.background = 'var(--accent)'; else t.style.background = '';
  });
  ['pasteSection', 'uploadSection', 'projectSection', 'githubSection', 'diffSection'].forEach(function (id) {
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

function handleProjectUpload() {
  const file = el.projectInput.files[0];
  if (!file) return;
  el.projectFileInfo.textContent = file.name + ' (' + (file.size / 1024).toFixed(1) + ' KB)';
  // Read ZIP and list .sol files for entry contract selector
  const reader = new FileReader();
  reader.onload = function (e) {
    try {
      var zipData = new Uint8Array(e.target.result);
      // Simplified: just show the dropdown with an "auto" option
      el.entryContract.style.display = 'inline-block';
      // Try to list files using a simple heuristic from the filename
      el.entryContract.innerHTML = '<option value="">Auto-detect entry contract</option>';
    } catch (err) { /* ZIP parsing in browser needs JSZip lib; skip */ }
  };
  reader.readAsArrayBuffer(file);
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

  if (tab === 'github') {
    const url = el.githubUrl.value.trim();
    if (!url) {
      el.resultsBody.innerHTML = '<p style="color:var(--accent-red);">Enter a GitHub repository URL first.</p>';
      return;
    }
    endpoint = '/api/analyze/github';
    body = JSON.stringify({ url: url });
  } else if (tab === 'project') {
    const file = el.projectInput.files[0];
    if (!file) {
      el.resultsBody.innerHTML = '<p style="color:var(--accent-red);">Select a ZIP project file first.</p>';
      return;
    }
    endpoint = '/api/analyze/project';
    body = new FormData();
    body.append('project', file);
    var entry = el.entryContract.value;
    if (entry) body.append('entry_contract', entry);
    doProjectAnalysis(endpoint, body);
    return;
  } else if (tab === 'diff') {
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

function handleKnowledgeFile() {
  const file = el.knowledgeInput.files[0];
  if (!file) return;
  el.knowledgeFileInfo.textContent = file.name + ' (' + (file.size / 1024).toFixed(1) + ' KB)';
  el.knowledgeResult.innerHTML = '';
}

function uploadKnowledge() {
  const file = el.knowledgeInput.files[0];
  if (!file) { el.knowledgeResult.innerHTML = '<span style="color:var(--red);">Select a PDF file first.</span>'; return; }
  el.uploadKnowledgeBtn.disabled = true;
  el.uploadKnowledgeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Uploading...';
  const fd = new FormData();
  fd.append('file', file);
  fetch('/api/knowledge/ingest', {
    method: 'POST',
    body: fd,
  }).then(function (r) { return r.json(); }).then(function (data) {
    el.uploadKnowledgeBtn.disabled = false;
    el.uploadKnowledgeBtn.innerHTML = '<i class="fas fa-upload"></i> Ingest to Knowledge Base';
    if (data.success) {
      el.knowledgeResult.innerHTML = '<span style="color:var(--green);">Ingested: ' + data.pages + ' pages, ' + data.chars + ' chars.</span>';
    } else {
      el.knowledgeResult.innerHTML = '<span style="color:var(--red);">Error: ' + (data.error || 'Unknown') + '</span>';
    }
  }).catch(function () {
    el.uploadKnowledgeBtn.disabled = false;
    el.uploadKnowledgeBtn.innerHTML = '<i class="fas fa-upload"></i> Ingest to Knowledge Base';
    el.knowledgeResult.innerHTML = '<span style="color:var(--red);">Network error.</span>';
  });
}

function fetchGasReport() {
  if (!currentReportText) return;
  const code = window.editor.getValue();
  if (!code) { el.resultsBody.innerHTML = '<p style="color:var(--red);">No code to analyze for gas.</p>'; return; }
  el.resultsBody.innerHTML = '<div class="skeleton w-75"></div><div class="skeleton w-50"></div>';
  el.resultsTitle.textContent = 'Gas Report...';
  fetch('/api/gas', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: code }),
  }).then(function (r) { return r.json(); }).then(function (data) {
    var md = '# Gas Report\n\n';
    if (data.gas_report) md += data.gas_report + '\n\n';
    if (data.static_analysis) {
      md += '## Static Pattern Analysis\n\n' + data.static_analysis.map(function (p) { return '- **' + p.pattern + '**: ' + p.msg; }).join('\n') + '\n\n';
    }
    if (data.savings_usd) md += '**Estimated Savings**: $' + data.savings_usd + '\n';
    currentReportText = md;
    renderFinalReport(md);
  }).catch(function (err) {
    el.resultsBody.innerHTML = '<p style="color:var(--red);">Error: ' + err.message + '</p>';
  });
}

function suggestFix() {
  if (!currentReportText) return;
  var code = window.editor.getValue();
  if (!code) { el.resultsBody.innerHTML = '<p style="color:var(--red);">No code to fix.</p>'; return; }
  el.resultsTitle.textContent = 'Generating fix...';
  el.resultsBody.innerHTML = '<div class="skeleton w-75"></div><div class="skeleton w-50"></div>';
  fetch('/api/analyze/fix', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: code, report: currentReportText.slice(0, 3000) })
  }).then(function (r) { return r.json(); }).then(function (data) {
    if (data.fix) {
      var md = '# Suggested Fix\n\n' + data.fix;
      currentReportText = md;
      renderFinalReport(md);
    } else { el.resultsBody.innerHTML = '<p style="color:var(--red);">Error: ' + (data.error || 'No fix generated') + '</p>'; }
  }).catch(function (err) {
    el.resultsBody.innerHTML = '<p style="color:var(--red);">Error: ' + err.message + '</p>';
  });
}

function applyLang(lang) {
  // Simple i18n: update data-i18n elements
  document.querySelectorAll('[data-i18n]').forEach(function (el2) {
    var key = el2.dataset.i18n;
    var texts = {
      'app.title': { en: 'Smart Contract Auditor', ar: 'مدقق العقود الذكية', zh: '智能合约审计器' },
      'tab.paste': { en: 'Paste', ar: 'لصق', zh: '粘贴' },
      'tab.upload': { en: 'Upload', ar: 'رفع', zh: '上传' },
      'tab.project': { en: 'Project', ar: 'مشروع', zh: '项目' },
      'tab.github': { en: 'GitHub', ar: 'جيت هاب', zh: 'GitHub' },
      'tab.diff': { en: 'Diff', ar: 'مقارنة', zh: '差异' },
      'btn.analyze': { en: 'Analyze', ar: 'تحليل', zh: '分析' },
      'results.title': { en: 'Results', ar: 'النتائج', zh: '结果' },
      'quota.label': { en: 'Quota', ar: 'الحصة', zh: '配额' },
    };
    var t = texts[key];
    if (t && t[lang]) { el2.textContent = t[lang]; }
  });
}

function doProjectAnalysis(endpoint, formData) {
  if (abortController) { abortController.abort(); abortController = null; }
  abortController = new AbortController();
  el.resultsActions.style.display = 'none';
  el.resultsTabs.style.display = 'none';
  el.resultsTitle.textContent = 'Analyzing project...';
  el.resultsBody.innerHTML = renderSkeleton();
  el.analyzeBtn.disabled = true;
  el.analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
  currentReportText = '';

  fetch(endpoint, {
    method: 'POST',
    body: formData,
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
let _streamingMd = '';

function renderStreamingReport(text) {
  if (typewriterTimer) { clearTimeout(typewriterTimer); }
  typewriterTimer = setTimeout(function () {
    _streamingMd = text;
    el.resultsBody.innerHTML = DOMPurify.sanitize(marked.parse(text));
    el.resultsBody.scrollTop = el.resultsBody.scrollHeight;
  }, 50);
}

function renderFinalReport(report) {
  _streamingMd = report;
  el.resultsBody.innerHTML = buildAccordion(report);
  el.resultsActions.style.display = 'flex';
  el.resultsTabs.style.display = 'flex';
  el.resultsTitle.textContent = 'Report - ' + countSeverities(report);
  showChart();
  saveToHistory(report);
}

function buildAccordion(md) {
  const severityMap = {
    'critical': { icon: '🔴', color: 'var(--accent-red)' },
    'high': { icon: '🟠', color: '#d29922' },
    'medium': { icon: '🔵', color: 'var(--accent)' },
    'low': { icon: '🟢', color: 'var(--accent-green)' },
    'info': { icon: 'ℹ️', color: 'var(--text-secondary)' }
  };

  var sev = /^(#{2,4}|##\s*\*\*)\s*(Critical|High|Medium|Low|Info)/gim;
  var lines = md.split('\n');
  var sections = [];
  var current = { heading: '', lines: [] };

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var m = sev.exec(line);
    sev.lastIndex = 0;
    if (m && m[2]) {
      if (current.lines.length > 0) { sections.push(current); }
      current = { heading: m[2], lines: [] };
    }
    current.lines.push(line);
  }
  if (current.lines.length > 0) { sections.push(current); }

  if (sections.length < 2) {
    return '<div class="finding-card"><div class="finding-body open">' +
      DOMPurify.sanitize(marked.parse(md)) + '</div></div>';
  }

  var result = '';
  for (var j = 0; j < sections.length; j++) {
    var s = sections[j];
    var sevKey = s.heading ? s.heading.toLowerCase() : 'info';
    if (!severityMap[sevKey]) sevKey = 'info';
    var sevObj = severityMap[sevKey];
    var bodyHtml = DOMPurify.sanitize(marked.parse(s.lines.join('\n')));
    if (j === 0) {
      result += '<div class="finding-card">';
      result += '<div class="finding-header" onclick="this.nextElementSibling.classList.toggle(\'open\')">';
      result += '<div><span class="severity-icon">📋</span><span class="finding-title">Summary / Overview</span></div>';
      result += '<span class="chevron">▼</span></div>';
      result += '<div class="finding-body open">' + bodyHtml + '</div></div>';
    } else {
      result += '<div class="finding-card" style="border-left:3px solid ' + sevObj.color + ';">';
      result += '<div class="finding-header" onclick="this.nextElementSibling.classList.toggle(\'open\')">';
      result += '<div><span class="severity-icon">' + sevObj.icon + '</span><span class="finding-title">' + s.heading + '</span></div>';
      result += '<span class="chevron">▼</span></div>';
      result += '<div class="finding-body open">' + bodyHtml + '</div></div>';
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
  fetch('/api/history', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ report: report, title: 'Audit ' + new Date().toLocaleString(), severity_counts: countSeverities(report) })
  }).then(function () { loadHistory(); });
}

function loadHistory() {
  fetch('/api/history').then(function (r) { return r.json(); }).then(function (data) {
    var items = data.items || [];
    el.historyList.innerHTML = items.length === 0
      ? '<p style="color:var(--text-secondary);font-size:0.8rem;">No previous audits.</p>'
      : items.map(function (h, i) {
          var date = new Date(h.created_at * 1000).toLocaleString();
          return '<div class="history-item" data-id="' + h.id + '" style="padding:0.6rem;border:1px solid var(--border);border-radius:6px;margin-bottom:0.5rem;cursor:pointer;font-size:0.8rem;">' +
            '<div style="color:var(--text-primary);margin-bottom:0.25rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + (h.title || h.snippet.slice(0, 80)) + '...</div>' +
            '<div style="color:var(--text-secondary);font-size:0.7rem;">' + date + '</div></div>';
        }).join('');
    el.historyList.querySelectorAll('.history-item').forEach(function (item) {
      item.addEventListener('click', function () { loadHistoryItem(parseInt(item.dataset.id)); });
    });
  });
}

function loadHistoryItem(id) {
  fetch('/api/history/' + id).then(function (r) { return r.json(); }).then(function (item) {
    if (!item) return;
    el.historyPanel.style.display = 'none';
    el.resultsBody.innerHTML = buildAccordion(item.full_report || item.snippet);
    el.resultsActions.style.display = 'flex';
    el.resultsTabs.style.display = 'flex';
    el.resultsTitle.textContent = 'History - ' + new Date(item.created_at * 1000).toLocaleString();
  });
}

function loadQuota() {
  fetch('/api/quota').then(function (r) { return r.json(); }).then(function (data) {
    var el2 = document.getElementById('quotaDisplay');
    if (el2 && data) {
      el2.textContent = 'Quota: ' + data.used + '/' + data.allowed;
      if (data.remaining <= 5) el2.style.color = 'var(--red)';
    }
  });
}

function downloadReport(format) {
  if (!currentReportText) return;
  if (format === 'pdf') {
    const el = document.createElement('div');
    el.innerHTML = DOMPurify.sanitize(marked.parse(currentReportText));
    el.style.padding = '20px'; el.style.fontFamily = 'system-ui'; el.style.fontSize = '12px';
    document.body.appendChild(el);
    html2pdf().set({ margin: 10, filename: 'audit-report.pdf', html2canvas: { scale: 2 }, jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' } }).from(el).save().then(function () { document.body.removeChild(el); });
    return;
  }
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
