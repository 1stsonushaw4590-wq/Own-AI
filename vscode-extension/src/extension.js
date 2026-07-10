const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

let diagnosticCollection;
let statusBarItem;
let apiClient;

// ─── API Client ──────────────────────────────────────────────

class CyberLLMAPI {
    constructor(baseUrl, apiKey) {
        this.baseUrl = baseUrl || 'http://localhost:8000';
        this.apiKey = apiKey || '';
    }

    async request(endpoint, body) {
        const headers = { 'Content-Type': 'application/json' };
        if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;

        try {
            const response = await fetch(`${this.baseUrl}/v1${endpoint}`, {
                method: 'POST',
                headers,
                body: JSON.stringify(body),
                signal: AbortSignal.timeout(30000),
            });
            if (!response.ok) throw new Error(`API error: ${response.status}`);
            return await response.json();
        } catch (err) {
            if (err.name === 'AbortError') {
                throw new Error('Request timed out. Is the API server running?');
            }
            throw err;
        }
    }

    async analyzeCode(code, language) {
        return this.request('/code/review', { code, language });
    }

    async chat(messages) {
        return this.request('/chat/completions', {
            model: vscode.workspace.getConfiguration('cyber-llm').get('model') || 'cyber-llm',
            messages,
            temperature: 0.6,
            max_tokens: 1024,
        });
    }

    async health() {
        try {
            const response = await fetch(`${this.baseUrl}/v1/health`, {
                signal: AbortSignal.timeout(5000),
            });
            return response.ok;
        } catch {
            return false;
        }
    }
}

// ─── Security Patterns (offline fallback) ────────────────────

const SECURITY_PATTERNS = {
    python: [
        { pattern: /eval\s*\(/g, severity: 'error', message: 'Avoid eval() - can execute arbitrary code' },
        { pattern: /exec\s*\(/g, severity: 'error', message: 'Avoid exec() - can execute arbitrary code' },
        { pattern: /os\.system\s*\(/g, severity: 'warning', message: 'Use subprocess instead of os.system()' },
        { pattern: /subprocess\.call\(.*shell\s*=\s*True/g, severity: 'error', message: 'Avoid shell=True - command injection risk' },
        { pattern: /pickle\.loads/g, severity: 'warning', message: 'Pickle can execute arbitrary code during deserialization' },
        { pattern: /(?:SELECT|INSERT|UPDATE|DELETE).*\{.*[fF]ormat|%.*[srd]|f['"]/g, severity: 'error', message: 'Possible SQL injection - use parameterized queries' },
        { pattern: /md5\s*\(/g, severity: 'warning', message: 'MD5 is cryptographically broken - use SHA-256 or better' },
        { pattern: /sha1\s*\(/g, severity: 'warning', message: 'SHA-1 is cryptographically broken - use SHA-256 or better' },
        { pattern: /(?:password|secret|key|token|credential)\s*=\s*['\"][^'\"]+['\"]/gi, severity: 'information', message: 'Hardcoded credential detected' },
    ],
    javascript: [
        { pattern: /eval\s*\(/g, severity: 'error', message: 'Avoid eval() - can execute arbitrary code' },
        { pattern: /innerHTML\s*=/g, severity: 'warning', message: 'Potential XSS - use textContent instead of innerHTML' },
        { pattern: /document\.write/g, severity: 'warning', message: 'Potential XSS - avoid document.write()' },
        { pattern: /(?:password|secret|api[_-]?key|token)\s*:\s*['\"][^'\"]+['\"]/gi, severity: 'information', message: 'Hardcoded credential detected' },
    ],
};

// ─── Extension Activation ────────────────────────────────────

function activate(context) {
    console.log('Cyber-LLM: Activating extension...');

    diagnosticCollection = vscode.languages.createDiagnosticCollection('cyber-llm');
    context.subscriptions.push(diagnosticCollection);

    // Status bar
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = '$(shield) Cyber-LLM';
    statusBarItem.command = 'cyber-llm.chat';
    context.subscriptions.push(statusBarItem);

    // Initialize API client
    const config = vscode.workspace.getConfiguration('cyber-llm');
    apiClient = new CyberLLMAPI(config.get('apiUrl'), config.get('apiKey'));
    updateConnectionStatus();

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('cyber-llm.analyzeFile', analyzeFile),
        vscode.commands.registerCommand('cyber-llm.analyzeSelection', analyzeSelection),
        vscode.commands.registerCommand('cyber-llm.fixVulnerability', fixVulnerability),
        vscode.commands.registerCommand('cyber-llm.explainCode', explainCode),
        vscode.commands.registerCommand('cyber-llm.generateSecureCode', generateSecureCode),
        vscode.commands.registerCommand('cyber-llm.lookupCVE', lookupCVE),
        vscode.commands.registerCommand('cyber-llm.chat', openChat),
    );

    // Real-time diagnostics (offline pattern matching)
    if (config.get('enableDiagnostics')) {
        context.subscriptions.push(
            vscode.workspace.onDidChangeTextDocument(debounce(runLocalDiagnostics, 1000)),
            vscode.workspace.onDidOpenTextDocument(runLocalDiagnostics),
        );
    }

    // Watch config changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('cyber-llm')) {
                const config = vscode.workspace.getConfiguration('cyber-llm');
                apiClient = new CyberLLMAPI(config.get('apiUrl'), config.get('apiKey'));
            }
        })
    );

    statusBarItem.show();
    console.log('Cyber-LLM: Extension activated successfully');
}

function deactivate() {
    if (diagnosticCollection) diagnosticCollection.clear();
}

// ─── Diagnostics (offline pattern matching) ──────────────────

function runLocalDiagnostics(document) {
    if (!document || document.isUntitled) return;

    const languageId = document.languageId;
    const patterns = SECURITY_PATTERNS[languageId];
    if (!patterns) return;

    const diagnostics = [];
    const text = document.getText();

    for (const { pattern, severity, message } of patterns) {
        let match;
        while ((match = pattern.exec(text)) !== null) {
            const startPos = document.positionAt(match.index);
            const endPos = document.positionAt(match.index + match[0].length);
            const range = new vscode.Range(startPos, endPos);
            const diagnostic = new vscode.Diagnostic(
                range, message,
                severityMap(severity)
            );
            diagnostic.source = 'cyber-llm';
            diagnostics.push(diagnostic);
        }
    }

    diagnosticCollection.set(document.uri, diagnostics);
}

function severityMap(severity) {
    switch (severity) {
        case 'error': return vscode.DiagnosticSeverity.Error;
        case 'warning': return vscode.DiagnosticSeverity.Warning;
        default: return vscode.DiagnosticSeverity.Information;
    }
}

// ─── Commands ────────────────────────────────────────────────

async function analyzeFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const document = editor.document;
    const code = document.getText();
    const language = document.languageId;

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Cyber-LLM: Analyzing file...',
    }, async () => {
        try {
            const result = await apiClient.analyzeCode(code, language);
            showAnalysisPanel(result, document.fileName, code, language);
        } catch (err) {
            vscode.window.showErrorMessage(`Cyber-LLM: ${err.message}`);
        }
    });
}

async function analyzeSelection() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const selection = editor.selection;
    const code = editor.document.getText(selection);
    const language = editor.document.languageId;

    if (!code) {
        vscode.window.showWarningMessage('No code selected');
        return;
    }

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Cyber-LLM: Analyzing code...',
    }, async () => {
        try {
            const result = await apiClient.analyzeCode(code, language);
            showAnalysisPanel(result, 'Selected Code', code, language);
        } catch (err) {
            vscode.window.showErrorMessage(`Cyber-LLM: ${err.message}`);
        }
    });
}

async function fixVulnerability() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const selection = editor.selection;
    const code = editor.document.getText(selection);

    if (!code) {
        vscode.window.showWarningMessage('Select code to fix');
        return;
    }

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Cyber-LLM: Generating fix...',
    }, async () => {
        try {
            const result = await apiClient.chat([
                { role: 'user', content: `Fix security vulnerabilities in this code. Return ONLY the fixed code:\n\`\`\`\n${code}\n\`\`\`` }
            ]);
            const fixedCode = result.choices?.[0]?.message?.content || '';
            if (fixedCode) {
                const doc = await vscode.workspace.openTextDocument({
                    content: fixedCode,
                    language: editor.document.languageId,
                });
                vscode.window.showTextDocument(doc);
            }
        } catch (err) {
            vscode.window.showErrorMessage(`Cyber-LLM: ${err.message}`);
        }
    });
}

async function explainCode() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const selection = editor.selection;
    const code = editor.document.getText(selection) || editor.document.getText();

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Cyber-LLM: Explaining...',
    }, async () => {
        try {
            const result = await apiClient.chat([
                { role: 'user', content: `Explain what this code does from a security perspective:\n\`\`\`\n${code}\n\`\`\`` }
            ]);
            const explanation = result.choices?.[0]?.message?.content || '';
            vscode.window.showInformationMessage('Explanation generated (see output panel)');
            showOutput(explanation);
        } catch (err) {
            vscode.window.showErrorMessage(`Cyber-LLM: ${err.message}`);
        }
    });
}

async function generateSecureCode() {
    const language = vscode.window.activeTextEditor?.document.languageId || 'python';
    const prompt = await vscode.window.showInputBox({
        prompt: 'Describe the secure code to generate',
        placeHolder: 'e.g., "hash passwords with bcrypt"',
    });
    if (!prompt) return;

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Cyber-LLM: Generating code...',
    }, async () => {
        try {
            const result = await apiClient.chat([
                { role: 'user', content: `Generate secure ${language} code for: ${prompt}. Include comments explaining security decisions.` }
            ]);
            const code = result.choices?.[0]?.message?.content || '';
            const doc = await vscode.workspace.openTextDocument({
                content: code,
                language: language,
            });
            vscode.window.showTextDocument(doc);
        } catch (err) {
            vscode.window.showErrorMessage(`Cyber-LLM: ${err.message}`);
        }
    });
}

async function lookupCVE() {
    const cveId = await vscode.window.showInputBox({
        prompt: 'Enter CVE ID',
        placeHolder: 'e.g., CVE-2021-44228',
        validateInput: (val) => val && /^CVE-\d{4}-\d{4,}$/i.test(val) ? null : 'Enter a valid CVE ID',
    });
    if (!cveId) return;

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `Cyber-LLM: Looking up ${cveId}...`,
    }, async () => {
        try {
            const result = await apiClient.chat([
                { role: 'user', content: `Explain ${cveId}: impact, affected versions, exploitation details, and remediation steps.` }
            ]);
            const explanation = result.choices?.[0]?.message?.content || '';
            showOutput(`# ${cveId}\n\n${explanation}`);
        } catch (err) {
            vscode.window.showErrorMessage(`Cyber-LLM: ${err.message}`);
        }
    });
}

async function openChat() {
    const panel = vscode.window.createWebviewPanel(
        'cyber-llm-chat',
        'Cyber-LLM Security Chat',
        vscode.ViewColumn.Beside,
        { enableScripts: true }
    );

    panel.webview.html = getChatWebviewHtml();
    panel.webview.onDidReceiveMessage(async (message) => {
        if (message.type === 'chat') {
            try {
                const result = await apiClient.chat([
                    { role: 'user', content: message.text }
                ]);
                const response = result.choices?.[0]?.message?.content || '';
                panel.webview.postMessage({ type: 'response', text: response });
            } catch (err) {
                panel.webview.postMessage({ type: 'response', text: `Error: ${err.message}` });
            }
        }
    });
}

// ─── UI Helpers ──────────────────────────────────────────────

function showAnalysisPanel(result, fileName, code, language) {
    const panel = vscode.window.createWebviewPanel(
        'cyber-llm-analysis',
        `Cyber-LLM: ${path.basename(fileName)}`,
        vscode.ViewColumn.Beside,
        { enableScripts: true }
    );

    const issues = result.issues || [];
    const suggestions = result.suggestions || [];

    let issuesHtml = issues.map((issue, i) => `
        <div class="issue">
            <div class="issue-header">
                <span class="severity ${issue.severity}">${issue.severity.toUpperCase()}</span>
                <span class="issue-title">${issue.description}</span>
            </div>
        </div>
    `).join('');

    panel.webview.html = `<!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: -apple-system, sans-serif; padding: 16px; color: var(--vscode-editor-foreground); }
            h1 { font-size: 18px; margin-bottom: 8px; }
            .issue { background: var(--vscode-editor-background); padding: 8px; margin: 8px 0; border-left: 3px solid #888; border-radius: 4px; }
            .severity { font-weight: bold; font-size: 11px; padding: 2px 6px; border-radius: 3px; }
            .severity.error { background: #c33; color: white; }
            .severity.warning { background: #c90; color: white; }
            .severity.information { background: #369; color: white; }
            .score { font-size: 24px; font-weight: bold; margin: 16px 0; }
            .score.low { color: #c33; }
            .score.medium { color: #c90; }
            .score.high { color: #3c3; }
        </style>
    </head>
    <body>
        <h1>🔍 Security Analysis: ${path.basename(fileName)}</h1>
        <div class="score ${result.secure_score > 70 ? 'high' : result.secure_score > 40 ? 'medium' : 'low'}">
            Secure Score: ${result.secure_score}/100
        </div>
        <h2>Issues (${issues.length})</h2>
        ${issuesHtml || '<p>No issues found</p>'}
        <h2>Suggestions</h2>
        ${suggestions.map(s => `<p>${s}</p>`).join('') || '<p>No suggestions</p>'}
    </body>
    </html>`;
}

function showOutput(text) {
    const channel = vscode.window.createOutputChannel('Cyber-LLM');
    channel.clear();
    channel.appendLine(text);
    channel.show();
}

function getChatWebviewHtml() {
    return `<!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: -apple-system, sans-serif; padding: 12px; }
            #messages { height: calc(100vh - 120px); overflow-y: auto; margin-bottom: 8px; }
            .msg { padding: 8px; margin: 4px 0; border-radius: 6px; }
            .user { background: var(--vscode-textBlockQuote-background); }
            .assistant { background: var(--vscode-editor-background); }
            #input { width: 100%; padding: 8px; box-sizing: border-box; }
        </style>
    </head>
    <body>
        <div id="messages"></div>
        <textarea id="input" rows="3" placeholder="Ask a cybersecurity question..."></textarea>
        <script>
            const vscode = acquireVsCodeApi();
            const messages = document.getElementById('messages');
            const input = document.getElementById('input');

            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    const text = input.value;
                    if (!text.trim()) return;
                    messages.innerHTML += '<div class="msg user"><strong>You:</strong> ' + text + '</div>';
                    vscode.postMessage({ type: 'chat', text });
                    input.value = '';
                }
            });

            window.addEventListener('message', (event) => {
                const msg = event.data;
                if (msg.type === 'response') {
                    messages.innerHTML += '<div class="msg assistant"><strong>Cyber-LLM:</strong> ' + msg.text + '</div>';
                    messages.scrollTop = messages.scrollHeight;
                }
            });
        </script>
    </body>
    </html>`;
}

// ─── Connection Status ───────────────────────────────────────

async function updateConnectionStatus() {
    const isConnected = await apiClient.health();
    statusBarItem.text = isConnected
        ? '$(shield) Cyber-LLM: Connected'
        : '$(shield) Cyber-LLM: Disconnected';
    statusBarItem.tooltip = isConnected
        ? 'API server connected'
        : 'Click to start API: make api';
}

// ─── Utility ─────────────────────────────────────────────────

function debounce(fn, delay) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}

module.exports = { activate, deactivate };
