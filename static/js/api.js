function authHeaders(extra) {
  var h = extra || {};
  var token = localStorage.getItem('auth_token');
  if (token) h['Authorization'] = 'Bearer ' + token;
  return h;
}

function processStream(resp) {
  if (!resp.ok) throw new Error('Analysis failed: ' + resp.status);
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let done = false;
  return new Promise(function (resolve, reject) {
    function read() {
      if (done) return;
      reader.read().then(function (result) {
        if (done) return;
        if (result.done) { done = true; finalizeAnalysis(); resolve(); return; }
        buffer += decoder.decode(result.value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop();
        for (var i = 0; i < parts.length; i++) {
          var part = parts[i];
          if (part.startsWith('data: ')) {
            const data = part.slice(6).trim();
            if (data === '[DONE]') { done = true; finalizeAnalysis(); resolve(); return; }
            try {
              const parsed = JSON.parse(data);
              if (parsed.error) { done = true; reject(new Error(parsed.error)); return; }
              if (parsed.step) { updateStep(parsed.step); }
              if (parsed.type === 'token' && parsed.text) {
                currentReportText += parsed.text;
                renderStreamingReport(currentReportText);
              }
              if (parsed.type === 'final' && parsed.report) {
                currentReportText = parsed.report;
                renderFinalReport(parsed.report);
              }
            } catch (e) { if (e.message !== 'Unexpected end of JSON input') { done = true; reject(e); return; } }
          }
        }
        read();
      }).catch(function (err) {
        if (typewriterTimer) { clearTimeout(typewriterTimer); typewriterTimer = null; }
        done = true;
        reject(err);
      });
    }
    read();
  });
}

function handleFetchError(err) {
  if (typewriterTimer) { clearTimeout(typewriterTimer); typewriterTimer = null; }
  finalizeAnalysis();
  if (err.name !== 'AbortError') {
    var isModelError = err.message.indexOf('image') !== -1 || err.message.indexOf('Cannot read') !== -1 || err.message.indexOf('not support') !== -1;
    var hint = isModelError
      ? 'The AI model returned an error. This may be a temporary issue — please try again.'
      : 'Try pasting shorter or simpler code, or switch to a different analysis mode.';
    el.resultsBody.innerHTML = '<p style="color:var(--accent-red);">Error: ' + err.message + '</p><p style="margin-top:1rem;font-size:0.85rem;">' + hint + ' <a href="#" onclick="location.reload()" style="color:var(--accent);">Reload page</a></p>';
    el.resultsActions.style.display = 'flex';
    el.resultsTabs.style.display = 'flex';
  }
}

function handleJsonResponse(resp) {
  if (!resp.ok) throw new Error('Analysis failed: ' + resp.status);
  return resp.json().then(function (data) {
    if (data.error) throw new Error(data.error);
    var md = '';
    if (data.report) md = data.report;
    else if (data.analysis) md = data.analysis;
    else if (data.summary) md = '## Diff Summary\n\n' + data.summary + '\n\n## Analysis\n\n' + (data.analysis || '');
    else md = JSON.stringify(data, null, 2);
    if (md) {
      currentReportText = md;
      renderFinalReport(md);
    } else {
      el.resultsBody.innerHTML = '<p style="color:var(--text-secondary);">No results returned.</p>';
    }
    finalizeAnalysis();
  });
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

  if (tab === 'diff') {
    fetch(endpoint, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: body,
      signal: abortController.signal
    }).then(handleJsonResponse).catch(handleFetchError);
  } else {
    fetch(endpoint, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: body,
      signal: abortController.signal
    }).then(processStream).catch(handleFetchError);
  }
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
    headers: authHeaders(),
    body: formData,
    signal: abortController.signal
  }).then(processStream).catch(handleFetchError);
}

function fetchGasReport() {
  if (!currentReportText) return;
  const code = window.editor.getValue();
  if (!code) { el.resultsBody.innerHTML = '<p style="color:var(--red);">No code to analyze for gas.</p>'; return; }
  el.resultsBody.innerHTML = '<div class="skeleton w-75"></div><div class="skeleton w-50"></div>';
  el.resultsTitle.textContent = 'Gas Report...';
  fetch('/api/gas', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
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
    headers: authHeaders({ 'Content-Type': 'application/json' }),
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

function scanMalware() {
  var code = window.editor.getValue();
  if (!code) { el.resultsBody.innerHTML = '<p style="color:var(--red);">No code to scan.</p>'; return; }
  el.resultsTitle.textContent = 'Scanning for malware...';
  el.resultsBody.innerHTML = '<div class="skeleton w-75"></div>';
  fetch('/api/analyze/malware', {
    method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ code: code })
  }).then(function (r) { return r.json(); }).then(function (data) {
    var findings = (data.source_findings || []).concat(data.bytecode_findings || []);
    var md = '# Malware Scan Report\n\n**Risk Score**: ' + data.risk_score + '/10\n\n';
    if (findings.length === 0) { md += '*No malicious patterns detected.*\n'; }
    else {
      findings.forEach(function (f) {
        md += '### ' + (f.severity || 'Info') + ': ' + (f.name || f.type || 'Suspicious') + '\n';
        md += '- ' + (f.description || f.pattern || '') + '\n';
        if (f.count) md += '- Matches: ' + f.count + '\n';
        md += '\n';
      });
    }
    currentReportText = md; renderFinalReport(md);
  }).catch(function (err) { el.resultsBody.innerHTML = '<p style="color:var(--red);">Error: ' + err.message + '</p>'; });
}

function generateFuzzTest() {
  var code = window.editor.getValue();
  if (!code) { el.resultsBody.innerHTML = '<p style="color:var(--red);">No code to fuzz.</p>'; return; }
  el.resultsTitle.textContent = 'Generating fuzz test...';
  el.resultsBody.innerHTML = '<div class="skeleton w-75"></div>';
  fetch('/api/analyze/fuzz', {
    method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ code: code })
  }).then(function (r) { return r.json(); }).then(function (data) {
    var md = '# Generated Foundry Fuzz Test\n\n```solidity\n' + (data.fuzz_test || 'Error generating test') + '\n```';
    currentReportText = md; renderFinalReport(md);
  }).catch(function (err) { el.resultsBody.innerHTML = '<p style="color:var(--red);">Error: ' + err.message + '</p>'; });
}

function exportHackerone() {
  if (!currentReportText) return;
  var code = window.editor.getValue();
  fetch('/api/hackerone', {
    method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ report: currentReportText, code: code, label: 'Smart Contract' })
  }).then(function (r) { return r.json(); }).then(function (data) {
    if (data.report) {
      navigator.clipboard.writeText(data.report).then(function () {
        alert('HackerOne report copied to clipboard!');
      });
    }
  }).catch(function (err) { alert('Error: ' + err.message); });
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
    headers: authHeaders(),
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

function handleKnowledgeFile() {
  const file = el.knowledgeInput.files[0];
  if (!file) return;
  el.knowledgeFileInfo.textContent = file.name + ' (' + (file.size / 1024).toFixed(1) + ' KB)';
  el.knowledgeResult.innerHTML = '';
}

function saveToHistory(report) {
  fetch('/api/history', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ report: report, title: 'Audit ' + new Date().toLocaleString(), severity_counts: countSeverities(report) })
  }).then(function () { loadHistory(); });
}

function loadHistory() {
  fetch('/api/history', { headers: authHeaders() }).then(function (r) { return r.json(); }).then(function (data) {
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
  fetch('/api/history/' + id, { headers: authHeaders() }).then(function (r) { return r.json(); }).then(function (item) {
    if (!item) return;
    el.historyPanel.style.display = 'none';
    el.resultsBody.innerHTML = buildAccordion(item.full_report || item.snippet);
    el.resultsActions.style.display = 'flex';
    el.resultsTabs.style.display = 'flex';
    el.resultsTitle.textContent = 'History - ' + new Date(item.created_at * 1000).toLocaleString();
  });
}

function loadQuota() {
  fetch('/api/quota', { headers: authHeaders() }).then(function (r) { return r.json(); }).then(function (data) {
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
    const el2 = document.createElement('div');
    el2.innerHTML = DOMPurify.sanitize(marked.parse(currentReportText));
    el2.style.padding = '20px'; el2.style.fontFamily = 'system-ui'; el2.style.fontSize = '12px';
    document.body.appendChild(el2);
    html2pdf().set({ margin: 10, filename: 'audit-report.pdf', html2canvas: { scale: 2 }, jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' } }).from(el2).save().then(function () { document.body.removeChild(el2); });
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
