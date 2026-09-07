import * as vscode from 'vscode';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { parseCargoAuditReport, CargoAuditParseError, Vulnerability } from './auditReport';

const execFileAsync = promisify(execFile);

let diagnostics: vscode.DiagnosticCollection;

function lineOfCrate(cargoTomlText: string, crateName: string): number {
  const lines = cargoTomlText.split('\n');
  const pattern = new RegExp(`^\\s*${crateName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=`);
  const index = lines.findIndex((line) => pattern.test(line));
  return index === -1 ? 0 : index;
}

async function runAudit(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    void vscode.window.showErrorMessage('Cargo Audit Companion: open a folder/workspace first.');
    return;
  }
  const root = folders[0].uri;
  const cargoTomlUri = vscode.Uri.joinPath(root, 'Cargo.toml');

  let cargoTomlText: string;
  try {
    cargoTomlText = Buffer.from(await vscode.workspace.fs.readFile(cargoTomlUri)).toString('utf8');
  } catch {
    void vscode.window.showErrorMessage('Cargo Audit Companion: no Cargo.toml found at the workspace root.');
    return;
  }

  let stdout: string;
  try {
    const result = await execFileAsync('cargo', ['audit', '--json'], { cwd: root.fsPath, maxBuffer: 20_000_000 });
    stdout = result.stdout;
  } catch (error) {
    // cargo-audit exits non-zero when vulnerabilities are found -- that's
    // still valid JSON on stdout, not a real failure. A genuine failure
    // (cargo-audit not installed, no network for the advisory DB fetch)
    // has no usable stdout to parse.
    const execError = error as { stdout?: string; message?: string };
    if (execError.stdout) {
      stdout = execError.stdout;
    } else {
      void vscode.window.showErrorMessage(
        `Cargo Audit Companion: couldn't run "cargo audit --json" -- is cargo-audit installed (cargo install cargo-audit)? (${execError.message ?? 'unknown error'})`,
      );
      return;
    }
  }

  let vulnerabilities: Vulnerability[];
  try {
    vulnerabilities = parseCargoAuditReport(stdout);
  } catch (error) {
    const message = error instanceof CargoAuditParseError ? error.message : String(error);
    void vscode.window.showErrorMessage(`Cargo Audit Companion: ${message}`);
    return;
  }

  diagnostics.clear();
  if (vulnerabilities.length === 0) {
    void vscode.window.showInformationMessage('Cargo Audit Companion: no known vulnerabilities found.');
    return;
  }

  const diags = vulnerabilities.map((vuln) => {
    const line = lineOfCrate(cargoTomlText, vuln.crateName);
    const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
    const patch = vuln.patchedVersions.length > 0 ? ` Patched: ${vuln.patchedVersions.join(', ')}.` : '';
    const diagnostic = new vscode.Diagnostic(
      range,
      `${vuln.id}: ${vuln.title} (${vuln.crateName} ${vuln.version}).${patch}`,
      vscode.DiagnosticSeverity.Warning,
    );
    diagnostic.source = 'Cargo Audit Companion';
    diagnostic.code = vuln.url ? { value: vuln.id, target: vscode.Uri.parse(vuln.url) } : vuln.id;
    return diagnostic;
  });
  diagnostics.set(cargoTomlUri, diags);
}

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection('cargoAuditCompanion');
  context.subscriptions.push(diagnostics);

  context.subscriptions.push(vscode.commands.registerCommand('cargoAuditCompanion.run', () => void runAudit()));
}

export function deactivate(): void {
  diagnostics?.dispose();
}
