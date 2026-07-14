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

    vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "Auditing contract..." },
      async () => {
        try {
          const headers = { "Content-Type": "application/json" };
          if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
          const resp = await fetch(`${apiUrl}/analyze`, {
            method: "POST",
            headers,
            body: JSON.stringify({ code: code.slice(0, 4000), type: "audit" }),
          });
          const data = await resp.json();
          const panel = vscode.window.createWebviewPanel(
            "auditReport",
            "Audit Report",
            vscode.ViewColumn.Beside,
            {}
          );
          const safeReport = escapeHtml(data.report || data.result || JSON.stringify(data, null, 2));
          panel.webview.html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<style>
body { font-family: system-ui; padding: 1rem; background: #0d1117; color: #c9d1d9; }
h1 { color: #58a6ff; }
pre { background: #161b22; padding: 1rem; border-radius: 6px; overflow-x: auto; }
.critical { border-left: 4px solid #da3633; padding-left: 1rem; margin: 0.5rem 0; }
.high { border-left: 4px solid #d29922; padding-left: 1rem; margin: 0.5rem 0; }
.medium { border-left: 4px solid #58a6ff; padding-left: 1rem; margin: 0.5rem 0; }
.low { border-left: 4px solid #3fb950; padding-left: 1rem; margin: 0.5rem 0; }
</style></head><body>
<h1>Audit Report</h1>
<pre>${safeReport}</pre>
</body></html>`;
        } catch (err) {
          vscode.window.showErrorMessage(`Audit failed: ${err.message}`);
        }
      }
    );
  });

  context.subscriptions.push(disposable);
}

function deactivate() {}

module.exports = { activate, deactivate };