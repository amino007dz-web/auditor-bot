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
const evtSource = new EventSource('${apiUrl}/api/analyze/stream?key=${apiKey}&code=${encodeURIComponent(code.slice(0, 4000))}');
const reportEl = document.getElementById('report');
const statusEl = document.getElementById('status');
evtSource.onmessage = function(e) {
  try {
    const data = JSON.parse(e.data);
    if (data.type === 'progress') {
      statusEl.textContent = data.text || 'Analyzing...';
    } else if (data.type === 'final') {
      reportEl.textContent = data.text || data.report || '';
      statusEl.textContent = 'Analysis complete. ' + (data.cvss_summary || '');
      evtSource.close();
    } else if (data.type === 'error') {
      reportEl.textContent = 'Error: ' + (data.text || 'Unknown error');
      statusEl.textContent = 'Failed';
      evtSource.close();
    }
  } catch(e) { reportEl.textContent += e.data; }
};
evtSource.onerror = function() {
  statusEl.textContent = 'Connection closed';
  evtSource.close();
};
<\/script>
</body></html>`;
  });

  context.subscriptions.push(disposable);
}

function deactivate() {}

module.exports = { activate, deactivate };
