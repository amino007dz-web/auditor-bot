const vscode = require("vscode");

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
    const lang = config.get("lang", "english");

    vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "Auditing contract..." },
      async () => {
        try {
          const resp = await fetch(`${apiUrl}/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: code.slice(0, 4000), type: "audit", lang }),
          });
          const data = await resp.json();
          const panel = vscode.window.createWebviewPanel(
            "auditReport",
            "Audit Report",
            vscode.ViewColumn.Beside,
            {}
          );
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
<pre>${data.report || data.result || JSON.stringify(data, null, 2)}</pre>
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