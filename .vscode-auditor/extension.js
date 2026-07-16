const vscode = require("vscode");

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function activate(context) {
  const disposable = vscode.commands.registerCommand("sca.auditFile", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage("Open a Solidity/Vyper file first");
      return;
    }

    const code = editor.document.getText();
    const config = vscode.workspace.getConfiguration("sca");
    const apiUrl = config.get("apiUrl", "https://auditor-bot.onrender.com");
    const apiKey = config.get("apiKey", "");

    const sendLength = code.length;
    if (sendLength > 4000) {
      const choice = await vscode.window.showWarningMessage(
        `Contract is ${sendLength} chars. Only first 4000 will be analyzed. Consider using the Web UI for full analysis.`,
        { modal: true },
        "Continue anyway",
        "Cancel"
      );
      if (choice !== "Continue anyway") return;
    }

    const consent = await vscode.window.showInformationMessage(
      `Send ${sendLength > 4000 ? "4000 chars of " : ""}your source code to ${apiUrl} for security analysis?`,
      { modal: true },
      "Yes, analyze",
      "Cancel"
    );
    if (consent !== "Yes, analyze") return;

    const panel = vscode.window.createWebviewPanel(
      "auditReport",
      "Audit Report",
      vscode.ViewColumn.Beside,
      { enableScripts: true }
    );

    panel.webview.html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<style>
body { font-family: system-ui; padding: 1rem; background: #0d1117; color: #c9d1d9; }
h1 { color: #58a6ff; font-size: 1.2rem; }
pre { background: #161b22; padding: 1rem; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
.status { color: #8b949e; font-size: 0.85rem; margin: 0.5rem 0; }
.critical { border-left: 4px solid #da3633; padding-left: 1rem; margin: 0.5rem 0; }
.high { border-left: 4px solid #d29922; padding-left: 1rem; margin: 0.5rem 0; }
.medium { border-left: 4px solid #58a6ff; padding-left: 1rem; margin: 0.5rem 0; }
.low { border-left: 4px solid #3fb950; padding-left: 1rem; margin: 0.5rem 0; }
</style></head><body>
<h1>Audit Report</h1>
<p class="status" id="status">Analyzing...</p>
<pre id="report"><i>Waiting for results...</i></pre>
<script>
(async function() {
  const reportEl = document.getElementById('report');
  const statusEl = document.getElementById('status');
  try {
    const resp = await fetch('${apiUrl}/api/analyze/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json'${apiKey ? ", 'Authorization': 'Bearer " + apiKey + "'" : ""} },
      signal: AbortSignal.timeout(30000),
      body: JSON.stringify({ code: ${JSON.stringify(escapeHtml(code.slice(0, 4000)))}, type: 'audit' })
    });
    if (!resp.ok) { reportEl.textContent = 'Error: ' + resp.status; statusEl.textContent = 'Failed'; return; }
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split('\\n\\n');
      buffer = parts.pop();
      for (const part of parts) {
        if (!part.startsWith('data: ')) continue;
        const data = JSON.parse(part.slice(6).trim());
        if (data.type === 'progress') {
          statusEl.textContent = data.text || 'Analyzing...';
        } else if (data.type === 'token') {
          reportEl.textContent += data.text || '';
        } else if (data.type === 'final') {
          reportEl.textContent = data.report || data.text || '';
          statusEl.textContent = 'Analysis complete.';
        } else if (data.type === 'error') {
          reportEl.textContent = 'Error: ' + (data.text || 'Unknown');
          statusEl.textContent = 'Failed';
        }
      }
    }
  } catch(e) {
    reportEl.textContent = 'Error: ' + e.message;
    statusEl.textContent = 'Connection failed';
  }
})();
<\/script>
</body></html>`;
  });

  context.subscriptions.push(disposable);
}

function deactivate() {}

module.exports = { activate, deactivate };
