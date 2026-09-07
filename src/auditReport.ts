/**
 * Pure logic -- no `vscode` dependency. New niche (not a port from
 * the Kotlin catalog). Evidence: `cargo-audit` is confirmed CLI-only
 * (the one related extension found, "Cargo Scan" by PLSysSec, is an
 * academic manual-audit project, not a RustSec wrapper) -- the same
 * gap `npm audit` inline extensions already fill for JS, unfilled for
 * Rust.
 *
 * Schema verified against a real captured `cargo audit --json`
 * output (DefectDojo's own test fixture for their cargo-audit parser,
 * not guessed from a paraphrased example) -- the real shape nests
 * under `vulnerabilities.list[].advisory`/`.package`, not the flatter
 * shape a first-pass web search suggested.
 */

export interface Vulnerability {
  id: string;
  crateName: string;
  version: string;
  title: string;
  url: string | null;
  patchedVersions: string[];
}

interface RawCargoAuditReport {
  vulnerabilities?: {
    found?: boolean;
    count?: number;
    list?: RawVulnerabilityEntry[];
  };
}

interface RawVulnerabilityEntry {
  advisory?: { id?: string; title?: string; url?: string | null };
  package?: { name?: string; version?: string };
  versions?: { patched?: string[] };
}

export class CargoAuditParseError extends Error {}

export function parseCargoAuditReport(jsonText: string): Vulnerability[] {
  let parsed: RawCargoAuditReport;
  try {
    parsed = JSON.parse(jsonText);
  } catch (error) {
    throw new CargoAuditParseError(`cargo audit output is not valid JSON: ${(error as Error).message}`);
  }

  const list = parsed.vulnerabilities?.list;
  if (!Array.isArray(list)) return [];

  return list
    .filter((entry): entry is RawVulnerabilityEntry => typeof entry === 'object' && entry !== null)
    .map((entry) => ({
      id: entry.advisory?.id ?? 'UNKNOWN',
      crateName: entry.package?.name ?? 'unknown',
      version: entry.package?.version ?? 'unknown',
      title: entry.advisory?.title ?? '(no title)',
      url: entry.advisory?.url ?? null,
      patchedVersions: entry.versions?.patched ?? [],
    }));
}
