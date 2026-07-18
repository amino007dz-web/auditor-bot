let abortController = null;
let currentReportText = '';
let chartInstance = null;
let typewriterTimer = null;

const $ = (id) => document.getElementById(id);
const qs = (sel) => document.querySelector(sel);
const qsa = (sel) => document.querySelectorAll(sel);

function escapeHtml(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(str));
  return d.innerHTML;
}

const el = {};

document.addEventListener('DOMContentLoaded', function () {
  const ids = [
    'resultsBody','resultsTitle','resultsActions','analyzeBtn','fileInput','browseBtn','fileInfo',
    'analysisType','themeToggle','historyBtn','historyPanel','historyClose','historyList',
    'chartModal','chartClose','severityChart','knowledgeBtn','knowledgeModal','knowledgeClose',
    'knowledgeInput','browseKnowledgeBtn','knowledgeFileInfo','knowledgeResult','uploadKnowledgeBtn',
    'gasBtn','fixBtn','malwareBtn','fuzzBtn','hackeroneBtn','entryContract',
    'githubUrl','githubFileInfo','editorBody','diffOriginal','diffModified',
    'downloadMd','downloadSarif','downloadPdf','toggleChart','exportGithub',
    'projectInput','browseProjectBtn','projectFileInfo','dropZone','quotaDisplay',
    'featuresShowcase',
  ];
  ids.forEach(function (id) { el[id] = $(id); });

  // Theme
  const savedTheme = localStorage.getItem('auditor-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  el.themeToggle.innerHTML = savedTheme === 'dark' ? '<i class="fas fa-moon"></i>' : '<i class="fas fa-sun"></i>';
  el.themeToggle.addEventListener('click', function () {
    const cur = document.documentElement.getAttribute('data-theme');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('auditor-theme', next);
    el.themeToggle.innerHTML = next === 'dark' ? '<i class="fas fa-moon"></i>' : '<i class="fas fa-sun"></i>';
  });

  // CodeMirror
  const ta = $('codeEditor');
  if (typeof CodeMirror !== 'undefined') {
    window.editor = CodeMirror.fromTextArea(ta, {
      lineNumbers: true,
      mode: 'javascript',
      theme: 'dracula',
      matchBrackets: true,
      styleActiveLine: true,
      indentUnit: 2,
      tabSize: 2,
      autoCloseBrackets: true,
    });
    window.editor.on('change', function () {
      const val = window.editor.getValue();
      const cc = val.length;
      const ct = (val.match(/contract\s+\w+|library\s+\w+|interface\s+\w+|module\s+\w+/g) || []).length;
      el.fileInfo.textContent = cc > 0 ? cc.toLocaleString() + ' chars | ' + ct + ' contract' + (ct !== 1 ? 's' : '') : '';
    });
  } else {
    ta.style.display = 'block';
    ta.style.width = '100%';
    ta.style.height = '100%';
    window.editor = { getValue: function () { return ta.value; }, setValue: function (v) { ta.value = v; }, refresh: function () {} };
  }

  // Tab switching
  qsa('.sidebar-tab').forEach(function (tab) {
    tab.addEventListener('click', function () {
      qsa('.sidebar-tab').forEach(function (t) { t.classList.remove('active'); });
      tab.classList.add('active');
      qsa('.tab-content').forEach(function (c) { c.classList.remove('active'); });
      var target = $('tab-' + tab.dataset.tab);
      if (target) target.classList.add('active');
      if (tab.dataset.tab === 'paste') window.editor.refresh();
    });
  });

  // Sidebar buttons
  el.browseBtn.addEventListener('click', function () { el.fileInput.click(); });
  el.fileInput.addEventListener('change', handleFileUpload);

  el.browseProjectBtn.addEventListener('click', function () { el.projectInput.click(); });
  el.projectInput.addEventListener('change', handleProjectUpload);

  el.analyzeBtn.addEventListener('click', startAnalysis);
  el.githubUrl.addEventListener('keydown', function (e) { if (e.key === 'Enter') startAnalysis(); });

  // History
  el.historyBtn.addEventListener('click', function () { el.historyPanel.classList.add('open'); });
  el.historyClose.addEventListener('click', function () { el.historyPanel.classList.remove('open'); });
  el.historyPanel.addEventListener('click', function (e) { if (e.target === el.historyPanel) el.historyPanel.classList.remove('open'); });

  // Chart
  el.chartClose.addEventListener('click', closeChart);
  el.chartModal.addEventListener('click', function (e) { if (e.target === el.chartModal) closeChart(); });

  // Knowledge
  el.knowledgeBtn.addEventListener('click', function () { el.knowledgeModal.classList.add('open'); });
  el.knowledgeClose.addEventListener('click', function () { el.knowledgeModal.classList.remove('open'); });
  el.knowledgeModal.addEventListener('click', function (e) { if (e.target === el.knowledgeModal) el.knowledgeModal.classList.remove('open'); });
  el.browseKnowledgeBtn.addEventListener('click', function () { el.knowledgeInput.click(); });
  el.knowledgeInput.addEventListener('change', handleKnowledgeFile);
  el.uploadKnowledgeBtn.addEventListener('click', uploadKnowledge);

  // Results actions
  el.downloadMd.addEventListener('click', function () { downloadReport('md'); });
  el.downloadSarif.addEventListener('click', function () { downloadReport('sarif'); });
  el.downloadPdf.addEventListener('click', function () { downloadReport('pdf'); });
  el.gasBtn.addEventListener('click', fetchGasReport);
  el.fixBtn.addEventListener('click', suggestFix);
  el.malwareBtn.addEventListener('click', scanMalware);
  el.fuzzBtn.addEventListener('click', generateFuzzTest);
  el.hackeroneBtn.addEventListener('click', exportHackerone);
  el.toggleChart.addEventListener('click', showChart);
  el.exportGithub.addEventListener('click', exportToGithub);

  // Drag and drop
  el.editorBody.addEventListener('dragover', function (e) { e.preventDefault(); el.editorBody.classList.add('dragover'); });
  el.editorBody.addEventListener('dragleave', function () { el.editorBody.classList.remove('dragover'); });
  el.editorBody.addEventListener('drop', function (e) {
    e.preventDefault();
    el.editorBody.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      const reader = new FileReader();
      reader.onload = function (ev) { window.editor.setValue(ev.target.result); switchTab('paste'); };
      reader.readAsText(file);
    }
  });

  loadHistory();
  loadQuota();
});

function switchTab(tab) {
  qsa('.sidebar-tab').forEach(function (t) { t.classList.remove('active'); if (t.dataset.tab === tab) t.classList.add('active'); });
  qsa('.tab-content').forEach(function (c) { c.classList.remove('active'); });
  var target = $('tab-' + tab);
  if (target) target.classList.add('active');
  if (tab === 'paste') window.editor.refresh();
}

function handleFileUpload() {
  const file = el.fileInput.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function (e) { window.editor.setValue(e.target.result); switchTab('paste'); };
  reader.readAsText(file);
}

function handleProjectUpload() {
  const file = el.projectInput.files[0];
  if (!file) return;
  el.projectFileInfo.textContent = file.name + ' (' + (file.size / 1024).toFixed(1) + ' KB)';
}

function getCode() { return window.editor.getValue(); }

function renderSkeleton() {
  return '<div class="skeleton w-75 h-24"></div><div class="skeleton w-50"></div><div class="skeleton w-90"></div><div class="skeleton w-75"></div><div class="skeleton w-50"></div>';
}

function updateStep(step) { el.resultsTitle.textContent = step; }

function renderStreamingReport(text) {
  if (typewriterTimer) clearTimeout(typewriterTimer);
  typewriterTimer = setTimeout(function () {
    if (typeof DOMPurify !== 'undefined' && typeof marked !== 'undefined') {
      el.resultsBody.innerHTML = DOMPurify.sanitize(marked.parse(text));
    } else {
      el.resultsBody.textContent = text;
    }
    el.resultsBody.scrollTop = el.resultsBody.scrollHeight;
  }, 50);
}

function renderFinalReport(report) {
  el.resultsBody.innerHTML = buildAccordion(report);
  el.resultsActions.style.display = 'flex';
  el.resultsTitle.textContent = 'Report - ' + countSeverities(report);
  saveToHistory(report);
}

function buildAccordion(md) {
  const sevMap = {
    critical: { icon: '<span style="color:var(--red)">&#9679;</span>', color: 'var(--red)' },
    high: { icon: '<span style="color:var(--orange)">&#9679;</span>', color: 'var(--orange)' },
    medium: { icon: '<span style="color:var(--accent)">&#9679;</span>', color: 'var(--accent)' },
    low: { icon: '<span style="color:var(--green)">&#9679;</span>', color: 'var(--green)' },
    info: { icon: '<span style="color:var(--text-dim)">&#9432;</span>', color: 'var(--text-dim)' }
  };

  var re = /^#{2,4}\s*(\*\*)?\s*(Critical|High|Medium|Low|Info)/gim;
  var lines = md.split('\n');
  var sections = [];
  var current = { heading: '', lines: [] };

  for (var i = 0; i < lines.length; i++) {
    var m = re.exec(lines[i]);
    re.lastIndex = 0;
    if (m && m[2]) {
      if (current.lines.length > 0) sections.push(current);
      current = { heading: m[2], lines: [] };
    }
    current.lines.push(lines[i]);
  }
  if (current.lines.length > 0) sections.push(current);

  if (sections.length < 2) {
    var safe = (typeof DOMPurify !== 'undefined' && typeof marked !== 'undefined')
      ? DOMPurify.sanitize(marked.parse(md)) : escapeHtml(md);
    return '<div class="finding-card open"><div class="finding-body">' + safe + '</div></div>';
  }

  var result = '';
  for (var j = 0; j < sections.length; j++) {
    var s = sections[j];
    var key = s.heading ? s.heading.toLowerCase() : 'info';
    if (!sevMap[key]) key = 'info';
    var info = sevMap[key];
    var bodyLines = s.lines.slice();
    var headingRe = /^#{2,4}\s*(\*\*)?\s*(Critical|High|Medium|Low|Info)/i;
    if (bodyLines.length > 0 && headingRe.test(bodyLines[0])) bodyLines.shift();
    var bodyHtml = (typeof DOMPurify !== 'undefined' && typeof marked !== 'undefined')
      ? DOMPurify.sanitize(marked.parse(bodyLines.join('\n'))) : escapeHtml(bodyLines.join('\n'));
    var safeH = escapeHtml(s.heading);

    if (j === 0) {
      result += '<div class="finding-card open">';
      result += '<div class="finding-header" onclick="toggleFinding(this)">';
      result += '<div class="finding-header-left"><span class="finding-icon">&#128203;</span><span class="finding-title">Summary / Overview</span></div>';
      result += '<span class="finding-chevron">&#9660;</span></div>';
      result += '<div class="finding-body">' + bodyHtml + '</div></div>';
    } else {
      result += '<div class="finding-card open" style="border-left:3px solid ' + info.color + ';">';
      result += '<div class="finding-header" onclick="toggleFinding(this)">';
      result += '<div class="finding-header-left"><span class="finding-icon">' + info.icon + '</span><span class="finding-title">' + safeH + '</span></div>';
      result += '<span class="finding-chevron">&#9660;</span></div>';
      result += '<div class="finding-body">' + bodyHtml + '</div></div>';
    }
  }
  return result;
}

function toggleFinding(header) {
  header.parentElement.classList.toggle('open');
}

function finalizeAnalysis() {
  el.analyzeBtn.disabled = false;
  el.analyzeBtn.innerHTML = '<i class="fas fa-play"></i> Analyze';
  abortController = null;
}

function closeChart() {
  el.chartModal.classList.remove('open');
}
