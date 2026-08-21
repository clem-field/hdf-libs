import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertSemgrepToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { ResultStatus } from '@mitre/hdf-schema';
import type { HDFResults, EvaluatedRequirement } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

async function convert(name: string): Promise<HDFResults> {
  return JSON.parse(await convertSemgrepToHdf(loadFixture(name))) as HDFResults;
}

function findReq(hdf: HDFResults, idFragment: string): EvaluatedRequirement | undefined {
  return hdf.baselines[0]!.requirements.find((r) => r.id.includes(idFragment));
}

runConverterContractTests({
  converterName: 'semgrep-to-hdf',
  convertFn: convertSemgrepToHdf,
  minimalFixture: 'minimal.json',
});

describe('semgrep to HDF converter', () => {
  it('rejects input that is not a Semgrep report', async () => {
    await expect(convertSemgrepToHdf('{"foo":1}')).rejects.toThrow(
      'does not look like a Semgrep report',
    );
  });

  describe('real fixture', () => {
    it('produces a schema-valid, correctly-shaped document', async () => {
      const hdf = await convert('real.json');
      expectValidResults(hdf);

      const bl = hdf.baselines[0]!;
      expect(bl.name).toBe('Semgrep Scan');
      expect(hdf.tool?.name).toBe('Semgrep');
      expect(hdf.tool?.version).toBe('1.174.0');
      expect(hdf.generator?.name).toBe('semgrep-to-hdf');
    });

    it('groups findings into one requirement per rule', async () => {
      const hdf = await convert('real.json');
      const ids = hdf.baselines[0]!.requirements.map((r) => r.id);
      expect(new Set(ids).size).toBe(ids.length);
      expect(ids).toHaveLength(2);
    });

    it('maps semgrep severity onto impact', async () => {
      const hdf = await convert('real.json');
      // ERROR severity
      expect(findReq(hdf, 'subprocess-shell-true')?.impact).toBe(0.7);
      // WARNING severity
      expect(findReq(hdf, 'dynamic-urllib-use-detected')?.impact).toBe(0.5);
    });

    it('resolves NIST tags from the rule CWE', async () => {
      const hdf = await convert('real.json');
      const req = findReq(hdf, 'subprocess-shell-true');
      expect(req?.tags?.nist).toBeDefined();
      expect(Array.isArray(req?.tags?.nist)).toBe(true);
      expect((req?.tags?.nist as string[]).length).toBeGreaterThan(0);
    });

    it('derives CCI tags from the resolved NIST controls', async () => {
      const hdf = await convert('real.json');
      const req = findReq(hdf, 'subprocess-shell-true')!;
      expect(Array.isArray(req.tags?.cci)).toBe(true);
      expect((req.tags?.cci as string[]).length).toBeGreaterThan(0);
      for (const cci of req.tags?.cci as string[]) {
        expect(cci).toMatch(/^CCI-\d+$/);
      }
    });

    it('normalizes owasp whether the rule supplies a string or an array', async () => {
      const hdf = await convert('real.json');
      for (const req of hdf.baselines[0]!.requirements) {
        expect(Array.isArray(req.tags?.owasp)).toBe(true);
      }
      // real.json deliberately carries one of each form
      expect((findReq(hdf, 'subprocess-shell-true')?.tags?.owasp as string[]).length).toBe(3);
      expect((findReq(hdf, 'dynamic-urllib-use-detected')?.tags?.owasp as string[]).length).toBe(1);
    });

    it('does not let semgrep metadata impact shadow the HDF impact float', async () => {
      const hdf = await convert('real.json');
      const req = findReq(hdf, 'subprocess-shell-true')!;
      expect(typeof req.impact).toBe('number');
      expect(req.tags?.impact).toBeUndefined();
      expect(req.tags?.semgrepImpact).toBe('LOW');
    });

    it('preserves the cross-framework metadata SARIF drops', async () => {
      const hdf = await convert('real.json');
      const req = findReq(hdf, 'dynamic-urllib-use-detected')!;
      expect(req.tags?.likelihood).toBe('LOW');
      expect(req.tags?.confidence).toBe('LOW');
      expect(req.tags?.asvs).toBeDefined();
      expect(req.tags?.vulnerabilityClass).toBeDefined();
    });

    it('reports every finding as failed, since semgrep omits suppressed findings', async () => {
      const hdf = await convert('real.json');
      for (const req of hdf.baselines[0]!.requirements) {
        for (const result of req.results) {
          expect(result.status).toBe(ResultStatus.Failed);
        }
      }
    });

    it('never emits the redacted placeholder semgrep uses in unauthenticated scans', async () => {
      const hdf = await convert('real.json');
      expect(JSON.stringify(hdf)).not.toContain('requires login');
    });

    it('records the finding location in codeDesc', async () => {
      const hdf = await convert('real.json');
      const result = findReq(hdf, 'subprocess-shell-true')!.results[0]!;
      expect(result.codeDesc).toContain('app/handlers.py');
      expect(result.codeDesc).toContain('7');
    });
  });

  describe('empty fixture', () => {
    it('produces a no-findings requirement rather than an empty baseline', async () => {
      const hdf = await convert('empty.json');
      expectValidResults(hdf);
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0);
    });
  });

  describe('errors fixture', () => {
    it('surfaces scan errors as their own requirement with error status', async () => {
      const hdf = await convert('errors.json');
      expectValidResults(hdf);
      const req = findReq(hdf, 'semgrep-scan-errors');
      expect(req).toBeDefined();
      expect(req!.results.length).toBe(2);
      for (const result of req!.results) {
        expect(result.status).toBe(ResultStatus.Error);
      }
    });

    it('omits the scan-errors requirement when the scan reported none', async () => {
      const hdf = await convert('real.json');
      expect(findReq(hdf, 'semgrep-scan-errors')).toBeUndefined();
    });
  });
});

describe('sparse and malformed rules', () => {
  function scan(results: unknown[], extra: Record<string, unknown> = {}): string {
    return JSON.stringify({
      version: '1.174.0',
      results,
      errors: [],
      paths: { scanned: ['a.py'] },
      engine_requested: 'OSS',
      ...extra,
    });
  }

  it('converts a rule that declares no metadata at all', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(scan([{ check_id: 'bare.rule', path: 'a.py' }])),
    ) as HDFResults;
    const req = hdf.baselines[0]!.requirements[0]!;
    // Falls back to the static-analysis default tags.
    expect(req.tags?.nist).toEqual(['SA-11', 'RA-5']);
    expect(req.tags?.owasp).toBeUndefined();
    expect(req.tags?.confidence).toBeUndefined();
    expect(req.tags?.likelihood).toBeUndefined();
    expect(req.tags?.semgrepImpact).toBeUndefined();
    expect(req.tags?.category).toBeUndefined();
    expect(req.tags?.banditCode).toBeUndefined();
    expect(req.tags?.asvs).toBeUndefined();
    expect(req.tags?.references).toBeUndefined();
    expect(req.tags?.subcategory).toBeUndefined();
    expect(req.tags?.technology).toBeUndefined();
    expect(req.tags?.vulnerabilityClass).toBeUndefined();
    // No location fields at all.
    expect(req.results[0]!.codeDesc).toBe('Path: a.py');
    expect(req.results[0]!.message).toBe('');
  });

  it('falls back to moderate impact for an unknown or absent severity', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'a', extra: { severity: 'NOVEL' } },
          { check_id: 'b' },
          { check_id: 'c', extra: { severity: 'CRITICAL' } },
        ]),
      ),
    ) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs.find((r) => r.id === 'a')!.impact).toBe(0.5);
    expect(reqs.find((r) => r.id === 'b')!.impact).toBe(0.5);
    expect(reqs.find((r) => r.id === 'c')!.impact).toBe(0.9);
  });

  it('renders a multi-line span and a path-only location', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'span', path: 'a.py', start: { line: 4 }, end: { line: 9 } },
          { check_id: 'single', path: 'a.py', start: { line: 4 }, end: { line: 4 } },
          { check_id: 'nopath' },
        ]),
      ),
    ) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs.find((r) => r.id === 'span')!.results[0]!.codeDesc).toBe('Path: a.py, lines 4-9');
    expect(reqs.find((r) => r.id === 'single')!.results[0]!.codeDesc).toBe('Path: a.py, line 4');
    expect(reqs.find((r) => r.id === 'nopath')!.results[0]!.codeDesc).toBe('Path: unknown');
  });

  it('drops redacted fields but keeps real ones', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'redacted', extra: { lines: 'requires login', fingerprint: 'requires login' } },
          { check_id: 'real', extra: { lines: 'x = 1' } },
        ]),
      ),
    ) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs.find((r) => r.id === 'redacted')!.results[0]!.message).toBe('');
    expect(reqs.find((r) => r.id === 'real')!.results[0]!.message).toContain('Matched code:');
  });

  it('skips findings with no check_id and falls back to the no-findings placeholder', async () => {
    const hdf = JSON.parse(await convertSemgrepToHdf(scan([{ path: 'a.py' }]))) as HDFResults;
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('semgrep-no-findings');
  });

  it('collapses repeated occurrences of one rule into a single requirement', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'dup', path: 'a.py', start: { line: 1 }, end: { line: 1 } },
          { check_id: 'dup', path: 'b.py', start: { line: 2 }, end: { line: 2 } },
        ]),
      ),
    ) as HDFResults;
    expect(hdf.baselines[0]!.requirements).toHaveLength(1);
    expect(hdf.baselines[0]!.requirements[0]!.results).toHaveLength(2);
  });

  it('deduplicates reference urls drawn from several metadata fields', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          {
            check_id: 'refs',
            extra: {
              metadata: {
                references: ['https://a', 'https://a'],
                source: 'https://a',
                shortlink: 'https://b',
                'source-rule-url': '',
                asvs: { control_url: 'https://c' },
              },
            },
          },
        ]),
      ),
    ) as HDFResults;
    expect(hdf.baselines[0]!.requirements[0]!.tags?.references).toEqual([
      'https://a',
      'https://b',
      'https://c',
    ]);
  });

  it('ignores a CWE entry that carries no parsable id', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([{ check_id: 'badcwe', extra: { metadata: { cwe: ['not a cwe reference'] } } }]),
      ),
    ) as HDFResults;
    expect(hdf.baselines[0]!.requirements[0]!.tags?.nist).toEqual(['SA-11', 'RA-5']);
  });

  it('handles scan errors whose type is a bare string or absent', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        JSON.stringify({
          version: '1.174.0',
          results: [],
          errors: [
            { message: 'a', type: 'PlainString', path: 'x.yml' },
            { message: 'b' },
          ],
          paths: { scanned: [] },
        }),
      ),
    ) as HDFResults;
    const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'semgrep-scan-errors')!;
    expect(req.results[0]!.message).toContain('PlainString');
    expect(req.results[1]!.message).toContain('Unknown');
    expect(req.results[1]!.codeDesc).toBe('Path: unknown');
  });

  it('derives a title from a single-segment rule id', async () => {
    const hdf = JSON.parse(await convertSemgrepToHdf(scan([{ check_id: 'rule' }]))) as HDFResults;
    expect(hdf.baselines[0]!.requirements[0]!.title).toBe('Rule');
  });
});
