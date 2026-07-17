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
  malwareBtn: $('malwareBtn'),
  fuzzBtn: $('fuzzBtn'),
  hackeroneBtn: $('hackeroneBtn'),
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

  el.chartClose.addEventListener('click', function () { el.chartModal.style.display = 'none'; el.resultsBody.style.display = 'block'; });
  el.chartModal.addEventListener('click', function (e) { if (e.target === el.chartModal) { el.chartModal.style.display = 'none'; el.resultsBody.style.display = 'block'; } });

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
      if (t === 'report' || t === 'chart') switchResultTab(t);
      else switchCodeTab(t);
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
      const file = e.dataTransfer.files[0];
      const reader = new FileReader();
      reader.onload = function (ev) { window.editor.setValue(ev.target.result); switchCodeTab('paste'); };
      reader.readAsText(file);
    }
  });

  el.browseProjectBtn.addEventListener('click', function () { el.projectInput.click(); });
  el.projectInput.addEventListener('change', handleProjectUpload);

  el.downloadMd.addEventListener('click', function () { downloadReport('md'); });
  el.downloadSarif.addEventListener('click', function () { downloadReport('sarif'); });
  el.downloadPdf.addEventListener('click', function () { downloadReport('pdf'); });
  el.gasBtn.addEventListener('click', fetchGasReport);
  el.fixBtn.addEventListener('click', suggestFix);
  el.malwareBtn.addEventListener('click', scanMalware);
  el.fuzzBtn.addEventListener('click', generateFuzzTest);
  el.hackeroneBtn.addEventListener('click', exportHackerone);
  el.langSelect.addEventListener('change', function () { applyLang(el.langSelect.value); });
  el.toggleChart.addEventListener('click', function () { showChart(); });
  el.exportGithub.addEventListener('click', exportToGithub);
  el.githubUrl.addEventListener('keydown', function (e) { if (e.key === 'Enter') startAnalysis(); });

  loadHistory();
  loadQuota();
});

function switchCodeTab(tab) {
  qsa('[data-tab^="paste"],[data-tab^="upload"],[data-tab^="project"],[data-tab^="github"],[data-tab^="diff"]').forEach(function (t) {
    if (t.dataset.tab === tab) { t.style.background = 'var(--accent)'; t.classList.add('active-tab'); } else { t.style.background = ''; t.classList.remove('active-tab'); }
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
}

function getCode() {
  return window.editor.getValue();
}

var i18nTexts = {
  'app.title': { en: 'Smart Contract Auditor' },
  'tab.paste': { en: 'Paste' },
  'tab.upload': { en: 'Upload' },
  'tab.project': { en: 'Project' },
  'tab.github': { en: 'GitHub' },
  'tab.diff': { en: 'Diff' },
  'btn.analyze': { en: 'Analyze' },
  'results.title': { en: 'Results' },
  'quota.label': { en: 'Quota' },
};

function applyLang(lang) {
  document.querySelectorAll('[data-i18n]').forEach(function (el2) {
    var key = el2.dataset.i18n;
    var t = i18nTexts[key];
    if (t && t[lang]) { el2.textContent = t[lang]; }
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
    el.resultsBody.innerHTML = typeof DOMPurify !== 'undefined' && typeof marked !== 'undefined' ? DOMPurify.sanitize(marked.parse(text)) : text;
    el.resultsBody.scrollTop = el.resultsBody.scrollHeight;
  }, 50);
}

function renderFinalReport(report) {
  el.resultsBody.innerHTML = buildAccordion(report);
  el.resultsActions.style.display = 'flex';
  el.resultsTabs.style.display = 'flex';
  el.resultsTitle.textContent = 'Report - ' + countSeverities(report);
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
      (DOMPurify && marked ? DOMPurify.sanitize(marked.parse(md)) : md) + '</div></div>';
  }

  var result = '';
  for (var j = 0; j < sections.length; j++) {
    var s = sections[j];
    var sevKey = s.heading ? s.heading.toLowerCase() : 'info';
    if (!severityMap[sevKey]) sevKey = 'info';
    var sevObj = severityMap[sevKey];
    var bodyLines = s.lines.slice();
    if (bodyLines.length > 0) {
      var headingRe = /^#{2,4}\s*(\*\*)?\s*(Critical|High|Medium|Low|Info)/i;
      if (headingRe.test(bodyLines[0])) { bodyLines.shift(); }
    }
    var bodyHtml = DOMPurify && marked ? DOMPurify.sanitize(marked.parse(bodyLines.join('\n'))) : bodyLines.join('\n');
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
