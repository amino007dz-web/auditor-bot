function authHeaders(extra) {
  var h = extra || {};
  var token = localStorage.getItem('auth_token');
  if (token) h['Authorization'] = 'Bearer ' + token;
  return h;
}

function processStream(resp) {
  if (!resp.ok) {
    return resp.json().then(function (errData) {
      var msg = errData.error || ('Server error: ' + resp.status);
      if (resp.status === 402 && typeof loadQuota === 'function') loadQuota();
      throw new Error(msg);
    }).catch(function (e) {
      if (e.message.indexOf('Server error') >= 0) throw e;
      throw new Error(e.message || ('Server error: ' + resp.status));
    });
  }
  if (!resp.body) throw new Error('Response has no body stream');
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let done = false;
  return new Promise(function (resolve, reject) {
    function read() {
      if (done) return;
      reader.read().then(function (result) {
        if (done) return;
        if (result.done) {
          done = true; finalizeAnalysis();
          if (!currentReportText) {
            el.resultsBody.innerHTML = '<p style="color:var(--text-muted);">No results returned.</p>';
            el.resultsActions.style.display = 'flex';
          }
          resolve(); return;
        }
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
              if (parsed.type === 'progress' && parsed.text) updateStep(parsed.text);
              else if (parsed.step) updateStep(parsed.step);
              if (parsed.type === 'token' && parsed.text) {
                currentReportText += parsed.text;
                renderStreamingReport(currentReportText);
              }
              if (parsed.type === 'final' && parsed.report) {
                currentReportText = parsed.report;
                renderFinalReport(parsed.report);
                done = true; finalizeAnalysis(); resolve(); return;
              }
            } catch (e) {
              if (e.message !== 'Unexpected end of JSON input') { done = true; reject(e); return; }
            }
          }
        }
        read();
      }).catch(function (err) {
        if (typewriterTimer) { clearTimeout(typewriterTimer); typewriterTimer = null; }
        done = true; reject(err);
      });
    }
    read();
  });
}

function handleFetchError(err) {
  if (typewriterTimer) { clearTimeout(typewriterTimer); typewriterTimer = null; }
  finalizeAnalysis();
  if (err.name !== 'AbortError') {
    var isModelErr = err.message.indexOf('image') !== -1 || err.message.indexOf('Cannot read') !== -1 || err.message.indexOf('not support') !== -1;
    var hint = isModelErr
      ? 'The AI model returned an error. This may be a temporary issue — please try again.'
      : 'Try pasting shorter or simpler code, or switch to a different analysis mode.';
    el.resultsBody.innerHTML = '<p style="color:var(--red);"><strong>Error:</strong> ' + escapeHtml(err.message) + '</p>'
      + '<p style="margin-top:12px;font-size:13px;">' + hint + ' <a href="#" onclick="location.reload()" style="color:var(--accent);">Reload page</a></p>';
    el.resultsActions.style.display = 'flex';
  }
}

function handleJsonResponse(resp) {
  if (!resp.ok) {
    return resp.json().then(function (errData) {
      throw new Error(errData.error || ('Server error: ' + resp.status));
    });
  }
  return resp.json().then(function (data) {
    if (data.error) throw new Error(data.error);
    var md = '';
    if (data.report) md = data.report;
    else if (data.analysis) md = data.analysis;
    else if (data.summary) md = '## Diff Summary\n\n' + (data.summary || '') + '\n\n## Analysis\n\n' + (data.analysis || '');
    else md = JSON.stringify(data, null, 2);
    if (md) { currentReportText = md; renderFinalReport(md); }
    else { el.resultsBody.innerHTML = '<p style="color:var(--text-muted);">No results returned.</p>'; }
    finalizeAnalysis();
  });
}

function getActiveTab() {
  var active = qs('.sidebar-tab.active');
  return active ? active.dataset.tab : 'paste';
}

function startAnalysis() {
  if (abortController) { abortController.abort(); abortController = null; }
  const tab = getActiveTab();
  let code, endpoint = '/api/analyze/stream', body;

  if (tab === 'github') {
    const url = el.githubUrl.value.trim();
    if (!url) {
      el.resultsBody.innerHTML = '<p style="color:var(--red);">Enter a GitHub repository URL first.</p>';
      return;
    }
    endpoint = '/api/analyze/github';
    body = JSON.stringify({ url: url });
  } else if (tab === 'project') {
    const file = el.projectInput.files[0];
    if (!file) {
      el.resultsBody.innerHTML = '<p style="color:var(--red);">Select a ZIP project file first.</p>';
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
    if (!el.diffOriginal.value.trim() && !el.diffModified.value.trim()) {
      el.resultsBody.innerHTML = '<p style="color:var(--red);">Enter original and modified code for diff analysis.</p>';
      return;
    }
  } else {
    code = getCode();
    body = JSON.stringify({ code: code, type: el.analysisType.value });
  }

  if (tab !== 'diff' && tab !== 'github' && !code.trim()) {
    el.resultsBody.innerHTML = '<p style="color:var(--red);">Please enter or upload code first.</p>';
    return;
  }

  abortController = new AbortController();
  el.resultsActions.style.display = 'none';
  el.resultsTitle.textContent = 'Analyzing...';
  el.resultsBody.innerHTML = renderSkeleton();
  el.analyzeBtn.disabled = true;
  el.analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
  el.stopBtn.style.display = 'inline-block';
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
  el.resultsTitle.textContent = 'Analyzing project...';
  el.resultsBody.innerHTML = renderSkeleton();
  el.analyzeBtn.disabled = true;
  el.analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
  el.stopBtn.style.display = 'inline-block';
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
  var code = getCode();
  if (!code) { el.resultsBody.innerHTML = '<p style="color:var(--red);">No code to analyze for gas.</p>'; return; }
  el.resultsBody.innerHTML = renderSkeleton();
  el.resultsTitle.textContent = 'Gas Report...';
  fetch('/api/gas', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ code: code }),
  }).then(function (r) { if (!r.ok) throw new Error('Server error: ' + r.status); return r.json(); }).then(function (data) {
    var md = '# Gas Report\n\n';
    if (data.gas_report) md += data.gas_report + '\n\n';
    if (data.static_analysis) {
      md += '## Static Pattern Analysis\n\n' + (Array.isArray(data.static_analysis)
        ? data.static_analysis.map(function (p) { return '- **' + escapeHtml(p.pattern) + '**: ' + escapeHtml(p.msg); }).join('\n')
        : data.static_analysis) + '\n\n';
    }
    if (data.savings_usd) md += '**Estimated Savings**: $' + data.savings_usd + '\n';
    currentReportText = md;
    renderFinalReport(md);
  }).catch(function (err) {
    el.resultsBody.innerHTML = '<p style="color:var(--red);">Error: ' + escapeHtml(err.message) + '</p>';
  });
}

function suggestFix() {
  if (!currentReportText) return;
  var code = getCode();
  if (!code) { el.resultsBody.innerHTML = '<p style="color:var(--red);">No code to fix.</p>'; return; }
  el.resultsTitle.textContent = 'Generating fix...';
  el.resultsBody.innerHTML = renderSkeleton();
  fetch('/api/analyze/fix', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ code: code, report: currentReportText.slice(0, 3000) })
  }).then(function (r) { if (!r.ok) throw new Error('Server error: ' + r.status); return r.json(); }).then(function (data) {
    if (data.fix) { var md = '# Suggested Fix\n\n' + data.fix; currentReportText = md; renderFinalReport(md); }
    else { el.resultsBody.innerHTML = '<p style="color:var(--red);">Error: ' + escapeHtml(data.error || 'No fix generated') + '</p>'; }
  }).catch(function (err) {
    el.resultsBody.innerHTML = '<p style="color:var(--red);">Error: ' + escapeHtml(err.message) + '</p>';
  });
}

function scanMalware() {
  var code = getCode();
  if (!code) { el.resultsBody.innerHTML = '<p style="color:var(--red);">No code to scan.</p>'; return; }
  el.resultsTitle.textContent = 'Scanning for malware...';
  el.resultsBody.innerHTML = '<div class="skeleton w-75 h-24"></div>';
  fetch('/api/analyze/malware', {
    method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ code: code })
  }).then(function (r) { if (!r.ok) throw new Error('Server error: ' + r.status); return r.json(); }).then(function (data) {
    var md = '# Malware Scan Report\n\n**Risk Score**: ' + data.risk_score + '/10\n\n';
    var findings = (data.source_findings || []).concat(data.bytecode_findings || []);
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
  }).catch(function (err) { el.resultsBody.innerHTML = '<p style="color:var(--red);">Error: ' + escapeHtml(err.message) + '</p>'; });
}

function generateFuzzTest() {
  var code = getCode();
  if (!code) { el.resultsBody.innerHTML = '<p style="color:var(--red);">No code to fuzz.</p>'; return; }
  el.resultsTitle.textContent = 'Generating fuzz test...';
  el.resultsBody.innerHTML = '<div class="skeleton w-75 h-24"></div>';
  fetch('/api/analyze/fuzz', {
    method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ code: code })
  }).then(function (r) { if (!r.ok) throw new Error('Server error: ' + r.status); return r.json(); }).then(function (data) {
    var md = '# Generated Foundry Fuzz Test\n\n```solidity\n' + (data.fuzz_test || 'Error generating test') + '\n```';
    currentReportText = md; renderFinalReport(md);
  }).catch(function (err) { el.resultsBody.innerHTML = '<p style="color:var(--red);">Error: ' + escapeHtml(err.message) + '</p>'; });
}

function generatePoc() {
  if (!currentReportText) return;
  var code = getCode();
  el.resultsTitle.textContent = 'Generating PoC exploit...';
  el.resultsBody.innerHTML = '<div class="skeleton w-75 h-24"></div>';
  fetch('/api/analyze/poc', {
    method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ report: currentReportText, code: code })
  }).then(function (r) { if (!r.ok) throw new Error('Server error: ' + r.status); return r.json(); }).then(function (data) {
    var md = '# Generated Proof of Concept\n\n```solidity\n' + (data.poc || 'Error generating PoC') + '\n```';
    if (data.filename) md += '\n\n**File**: `' + data.filename + '`';
    currentReportText = md; renderFinalReport(md);
  }).catch(function (err) { el.resultsBody.innerHTML = '<p style="color:var(--red);">Error: ' + escapeHtml(err.message) + '</p>'; });
}

function exportHackerone() {
  if (!currentReportText) return;
  var code = getCode();
  var hubModal = document.getElementById('exportHubModal');
  if (hubModal) hubModal.classList.remove('open');
  fetch('/api/hackerone', {
    method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ report: currentReportText, code: code, label: 'Smart Contract' })
  }).then(function (r) { if (!r.ok) throw new Error('Server error: ' + r.status); return r.json(); }).then(function (data) {
    if (data.report && navigator.clipboard) {
      navigator.clipboard.writeText(data.report).then(function () { alert('HackerOne report copied to clipboard!'); });
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
    method: 'POST', headers: authHeaders(), body: fd,
  }).then(function (r) { if (!r.ok) throw new Error('Server error: ' + r.status); return r.json(); }).then(function (data) {
    el.uploadKnowledgeBtn.disabled = false;
    el.uploadKnowledgeBtn.innerHTML = '<i class="fas fa-upload"></i> Ingest to Knowledge Base';
    if (data.success) { el.knowledgeResult.innerHTML = '<span style="color:var(--green);">Ingested: ' + escapeHtml(data.pages) + ' pages, ' + escapeHtml(data.chars) + ' chars.</span>'; }
    else { el.knowledgeResult.innerHTML = '<span style="color:var(--red);">Error: ' + escapeHtml(data.error || 'Unknown') + '</span>'; }
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
  }).then(function (r) { if (r.ok) loadHistory(); });
}

function loadHistory() {
  fetch('/api/history', { headers: authHeaders() }).then(function (r) { if (!r.ok) throw new Error('Server error: ' + r.status); return r.json(); }).then(function (data) {
    var items = Array.isArray(data.items) ? data.items : [];
    el.historyList.innerHTML = items.length === 0
      ? '<p style="color:var(--text-muted);font-size:13px;">No previous audits.</p>'
      : items.map(function (h) {
          var date = new Date(h.created_at * 1000).toLocaleString();
          var title = h.title || (h.snippet ? h.snippet.slice(0, 80) : 'Untitled');
          return '<div class="history-item" data-id="' + escapeHtml(h.id) + '">'
            + '<div class="history-item-title">' + escapeHtml(title) + '</div>'
            + '<div class="history-item-date">' + escapeHtml(date) + '</div></div>';
        }).join('');
    el.historyList.querySelectorAll('.history-item').forEach(function (item) {
      item.addEventListener('click', function () { loadHistoryItem(parseInt(item.dataset.id)); });
    });
  });
}

function loadHistoryItem(id) {
  fetch('/api/history/' + id, { headers: authHeaders() }).then(function (r) { if (!r.ok) throw new Error('Server error: ' + r.status); return r.json(); }).then(function (item) {
    if (!item) return;
    el.historyPanel.classList.remove('open');
    el.resultsBody.innerHTML = buildAccordion(item.full_report || item.snippet);
    el.resultsActions.style.display = 'flex';
    el.resultsTitle.textContent = 'History - ' + new Date(item.created_at * 1000).toLocaleString();
  });
}

function loadQuota() {
  fetch('/api/quota', { headers: authHeaders() }).then(function (r) { if (!r.ok) throw new Error('Server error: ' + r.status); return r.json(); }).then(function (data) {
    if (el.quotaDisplay && data) {
      if (data.plan === 'pro') {
        el.quotaDisplay.innerHTML = '<i class="fas fa-gem" style="color:var(--accent);font-size:11px;"></i> Pro';
      } else if (data.allowed === 'monthly') {
        var pct = data.remaining / 5 * 100;
        var color = pct < 25 ? 'var(--red)' : pct < 60 ? 'var(--orange)' : 'var(--green)';
        el.quotaDisplay.innerHTML = '<i class="fas fa-gem" style="color:' + color + ';font-size:11px;"></i> ' + data.remaining + '/' + 5;
      } else {
        el.quotaDisplay.textContent = 'Quota: ' + data.used + '/' + data.allowed;
      }
      if (data.remaining <= 1) el.quotaDisplay.style.color = 'var(--red)';
    }
  });
}

function convertToSARIF(report) {
  var sev = /^#{2,4}\s*(\*\*)?\s*(Critical|High|Medium|Low|Info)/gim;
  var lines = report.split('\n');
  var results = [];
  var currentFinding = null;
  for (var i = 0; i < lines.length; i++) {
    var m = sev.exec(lines[i]);
    sev.lastIndex = 0;
    if (m) {
      if (currentFinding) results.push(currentFinding);
      currentFinding = { severity: m[2].toUpperCase(), name: lines[i].replace(/[#*]/g, '').trim(), lines: [] };
    } else if (currentFinding) { currentFinding.lines.push(lines[i]); }
  }
  if (currentFinding) results.push(currentFinding);
  if (results.length === 0) results.push({ severity: 'NOTE', name: 'Audit Report', lines: lines.slice(0, 5) });
  var rules = [], sarifResults = [], seenRules = {};
  results.forEach(function (f) {
    var ruleId = f.name.slice(0, 50).replace(/[^a-zA-Z0-9 ]/g, '_') || 'finding';
    if (!seenRules[ruleId]) { seenRules[ruleId] = true; rules.push({ id: ruleId, name: f.name, shortDescription: { text: f.name }, properties: { severity: f.severity } }); }
    var level = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : f.severity === 'MEDIUM' ? 'warning' : 'note';
    sarifResults.push({ ruleId: ruleId, level: level, message: { text: f.lines.join('\n').slice(0, 500) || f.name }, locations: [{ physicalLocation: { artifactLocation: { uri: 'contract.sol' }, region: { startLine: 1 } } }] });
  });
  return { version: '2.1.0', $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json', runs: [{ tool: { driver: { name: 'Smart Contract Auditor', version: '1.0', rules: rules } }, results: sarifResults }] };
}

function downloadReport(format) {
  if (!currentReportText) return;
  if (format === 'pdf') {
    if (typeof html2pdf === 'undefined' || typeof marked === 'undefined' || typeof DOMPurify === 'undefined') { alert('PDF export not available'); return; }
    const el2 = document.createElement('div');
    el2.innerHTML = DOMPurify.sanitize(marked.parse(currentReportText));
    el2.style.cssText = 'position:fixed;left:-10000px;top:0;padding:20px;font-family:system-ui;font-size:12px;';
    document.body.appendChild(el2);
    html2pdf().set({ margin: 10, filename: 'audit-report.pdf', html2canvas: { scale: 2 }, jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' } }).from(el2).save().then(function () { if (el2.parentNode) document.body.removeChild(el2); }).catch(function () { if (el2.parentNode) document.body.removeChild(el2); });
    return;
  }
  if (format === 'sarif') {
    var sarif = convertToSARIF(currentReportText);
    var blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a'); a.href = url; a.download = 'audit-report.sarif'; a.click();
    URL.revokeObjectURL(url);
    return;
  }
  const mdBlob = new Blob([currentReportText], { type: 'text/markdown' });
  const dlUrl = URL.createObjectURL(mdBlob);
  const dlLink = document.createElement('a');
  dlLink.href = dlUrl;
  dlLink.download = 'audit-report.' + format;
  dlLink.click();
  URL.revokeObjectURL(dlUrl);
}

function exportToGithub() {
  if (!currentReportText) return;
  var hubModal = document.getElementById('exportHubModal');
  if (hubModal) hubModal.classList.remove('open');
  var text = '# Smart Contract Audit Report\n\n## Summary\n\n' + currentReportText.split('\n').slice(0, 20).join('\n') + '\n\n## Finding Details\n\n' + currentReportText + '\n\n## Severity Distribution\n\n' + countSeverities(currentReportText) + '\n\n---\n*Generated by Smart Contract Auditor*';
  if (navigator.clipboard) { navigator.clipboard.writeText(text).then(function () { alert('GitHub Discussion format copied to clipboard!'); }); }
}
