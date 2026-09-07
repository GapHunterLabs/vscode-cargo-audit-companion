import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCargoAuditReport, CargoAuditParseError } from '../auditReport';

// Trimmed down from a real captured `cargo audit --json` output
// (verified against DefectDojo's own cargo-audit parser test fixture,
// not guessed) -- the real schema nests under
// vulnerabilities.list[].advisory/.package, not a flat shape.
const REAL_SHAPE_REPORT = JSON.stringify({
  database: { 'advisory-count': 1098 },
  lockfile: { 'dependency-count': 176 },
  vulnerabilities: {
    found: true,
    count: 2,
    list: [
      {
        advisory: {
          id: 'RUSTSEC-2026-0047',
          package: 'aws-lc-sys',
          title: 'PKCS7_verify Signature Validation Bypass in AWS-LC',
          url: 'https://aws.amazon.com/security/security-bulletins/2026-005-AWS',
        },
        versions: { patched: ['>=0.38.0'], unaffected: ['<0.24.0'] },
        package: { name: 'aws-lc-sys', version: '0.36.0' },
      },
      {
        advisory: { id: 'RUSTSEC-2018-0003', package: 'smallvec', title: 'Possible double free', url: null },
        versions: { patched: ['>=0.6.3'] },
        package: { name: 'smallvec', version: '0.2.1' },
      },
    ],
  },
});

test('parseCargoAuditReport reads every vulnerability from the real nested schema', () => {
  const vulns = parseCargoAuditReport(REAL_SHAPE_REPORT);
  assert.equal(vulns.length, 2);
  assert.equal(vulns[0].id, 'RUSTSEC-2026-0047');
  assert.equal(vulns[0].crateName, 'aws-lc-sys');
  assert.equal(vulns[0].version, '0.36.0');
  assert.deepEqual(vulns[0].patchedVersions, ['>=0.38.0']);
});

test('parseCargoAuditReport handles a null advisory URL', () => {
  const vulns = parseCargoAuditReport(REAL_SHAPE_REPORT);
  assert.equal(vulns[1].url, null);
});

test('parseCargoAuditReport returns empty for a report with no vulnerabilities found', () => {
  const clean = JSON.stringify({ vulnerabilities: { found: false, count: 0, list: [] } });
  assert.deepEqual(parseCargoAuditReport(clean), []);
});

test('parseCargoAuditReport returns empty when the vulnerabilities key is entirely absent', () => {
  assert.deepEqual(parseCargoAuditReport(JSON.stringify({ database: {} })), []);
});

test('parseCargoAuditReport throws CargoAuditParseError on invalid JSON', () => {
  assert.throws(() => parseCargoAuditReport('not json at all'), CargoAuditParseError);
});

test('parseCargoAuditReport falls back gracefully when a field is missing from one entry', () => {
  const partial = JSON.stringify({
    vulnerabilities: { found: true, count: 1, list: [{ advisory: { id: 'RUSTSEC-2020-0001' } }] },
  });
  const vulns = parseCargoAuditReport(partial);
  assert.equal(vulns.length, 1);
  assert.equal(vulns[0].crateName, 'unknown');
  assert.deepEqual(vulns[0].patchedVersions, []);
});
