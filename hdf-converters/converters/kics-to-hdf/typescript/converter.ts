import { parseJSON } from '@mitre/hdf-utilities';
import { DEFAULT_STATIC_ANALYSIS_NIST_TAGS } from '@mitre/hdf-mappings';
import {
  buildHdfResults,
  buildNistCciTags,
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  inputChecksum,
  mapCWEToNIST,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
import { nistToCci } from '@mitre/hdf-mappings';
import { kicsMappingData, type KicsMappingEntry } from './mapping-data.js';
import type {
  Description,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
} from '@mitre/hdf-schema';

/** One occurrence of a query, against a specific file and resource. */
interface KicsFile {
  file_name?: string;
  similarity_id?: string;
  line?: number;
  resource_type?: string;
  resource_name?: string;
  issue_type?: string;
  search_key?: string;
  search_line?: number;
  search_value?: string;
  expected_value?: string;
  actual_value?: string;
}

/** One query, with every place it fired. KICS already groups this way. */
interface KicsQuery {
  query_id?: string;
  query_name?: string;
  query_url?: string;
  severity?: string;
  platform?: string;
  cwe?: string;
  risk_score?: string | number;
  cloud_provider?: string;
  category?: string;
  experimental?: boolean;
  description?: string;
  description_id?: string;
  files?: KicsFile[];
}

interface KicsReport {
  queries?: KicsQuery[];
  kics_version?: string;
  severity_counters?: Record<string, number>;
  total_counter?: number;
  files_scanned?: number;
  files_parsed?: number;
  files_failed_to_scan?: number;
  queries_total?: number;
  queries_failed_to_execute?: number;
}

/**
 * KICS publishes five severities. SARIF collapses CRITICAL and HIGH into
 * `error`; converting the native format keeps them apart, which is a large part
 * of why this converter exists.
 *
 * No level maps to 0: `impact 0` reports Not Applicable in HDF and would drop
 * the finding from the compliance score entirely.
 */
const IMPACT_BY_SEVERITY: Record<string, number> = {
  critical: 0.9,
  high: 0.7,
  medium: 0.5,
  low: 0.3,
  info: 0.1,
  trace: 0.1,
};

const DEFAULT_IMPACT = 0.5;

/**
 * Records which tier resolved a requirement's NIST tags, so a reviewed mapping
 * stays distinguishable from a CWE-derived guess and from a static default.
 * Follows the precedent set by UNRATED_SEVERITY_TAG in converterutil, which
 * exists so a defaulted impact stays distinguishable from a genuine rated one.
 *
 * The per-query table is authoritative, matching how the Checkov and AWS Config
 * mappers in the v1 line work: the rule-to-control decision is reviewed before
 * shipping rather than computed at conversion time, which is also what lets
 * those tables carry control enhancements. CWE is a fallback because it is a
 * lossy proxy — only 30 of the 102 CWEs KICS uses resolve against the CWE→NIST
 * table, 52% of queries by volume.
 */
const NIST_MAPPING_TAG = 'nistMapping';
const NIST_MAPPING_TABLE = 'mapped';
const NIST_MAPPING_CWE = 'cwe-derived';
const NIST_MAPPING_FALLBACK = 'static-fallback';

function impactFor(severity?: string): number {
  if (typeof severity !== 'string' || severity.length === 0) return DEFAULT_IMPACT;
  return IMPACT_BY_SEVERITY[severity.toLowerCase()] ?? DEFAULT_IMPACT;
}

/** KICS emits the bare number, e.g. "778". Normalize before the lookup. */
function cweIdentifiers(query: KicsQuery): string[] {
  const raw = query.cwe;
  if (raw === undefined || raw === null || String(raw).trim() === '') return [];
  const id = String(raw).trim().replace(/^CWE-/i, '');
  return /^\d+$/.test(id) ? [`CWE-${id}`] : [];
}

function locationFor(file: KicsFile): string {
  const parts = [`File: ${file.file_name ?? 'unknown'}`];
  if (typeof file.line === 'number' && file.line > 0) parts.push(`Line: ${file.line}`);
  if (file.resource_type) parts.push(`Resource type: ${file.resource_type}`);
  if (file.resource_name && file.resource_name !== 'unknown') {
    parts.push(`Resource: ${file.resource_name}`);
  }
  if (file.search_key) parts.push(`Key: ${file.search_key}`);
  return parts.join('\n');
}

/**
 * The remediation pair. SARIF keeps only `actual_value` inside its message, so
 * a SARIF-derived control can say what the configuration is but never what it
 * should be.
 */
function evidenceFor(file: KicsFile): string {
  const parts: string[] = [];
  if (file.expected_value) parts.push(`Expected: ${file.expected_value}`);
  if (file.actual_value) parts.push(`Actual: ${file.actual_value}`);
  if (file.issue_type) parts.push(`Issue type: ${file.issue_type}`);
  if (file.search_value) parts.push(`Search value: ${file.search_value}`);
  return parts.join('\n');
}

/**
 * Resolution order: the reviewed per-query table, then the query's CWE, then the
 * static-analysis defaults. `table` is a parameter so all three tiers are
 * testable without shipping unreviewed rows in the table itself.
 */
export function resolveControls(
  query: KicsQuery,
  table: Record<string, KicsMappingEntry> = kicsMappingData,
): { nist: string[]; cci: string[]; source: string } {
  const entry = typeof query.query_id === 'string' ? table[query.query_id] : undefined;
  if (entry !== undefined && entry.nist.length > 0) {
    return { nist: entry.nist, cci: entry.cci, source: NIST_MAPPING_TABLE };
  }

  const fromCwe = mapCWEToNIST(cweIdentifiers(query), []);
  if (fromCwe.length > 0) {
    return { nist: fromCwe, cci: nistToCci(fromCwe), source: NIST_MAPPING_CWE };
  }

  const fallback = [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS];
  return { nist: fallback, cci: nistToCci(fallback), source: NIST_MAPPING_FALLBACK };
}

function tagsFor(query: KicsQuery): Record<string, unknown> {
  const cwe = cweIdentifiers(query);
  const { nist, cci, source } = resolveControls(query);

  const extras: Record<string, unknown> = {
    [NIST_MAPPING_TAG]: source,
  };
  // Kept even when it does not resolve: an unmapped CWE that is invisible in
  // the output is a gap nobody can see.
  if (cwe.length > 0) extras.cwe = cwe;
  if (query.severity) extras.severity = query.severity;
  if (query.platform) extras.platform = query.platform;
  if (query.cloud_provider) extras.cloudProvider = query.cloud_provider;
  if (query.category) extras.category = query.category;
  if (query.risk_score !== undefined) extras.riskScore = String(query.risk_score);
  if (query.description_id) extras.descriptionId = query.description_id;
  if (query.experimental) extras.experimental = true;

  const issueTypes = [...new Set((query.files ?? []).map((f) => f.issue_type).filter(Boolean))];
  if (issueTypes.length > 0) extras.issueType = issueTypes;
  const resourceTypes = [...new Set((query.files ?? []).map((f) => f.resource_type).filter(Boolean))];
  if (resourceTypes.length > 0) extras.resourceType = resourceTypes;

  return buildNistCciTags(nist, cci, extras);
}

/**
 * KICS reports violations only. Its output carries no record of the queries
 * that ran without finding anything — `queries[]` contains only those that
 * fired — so no passing requirement can be derived from it, and a converted
 * profile is failures-only by construction.
 *
 * That makes the compliance percentage misleading on its own: a scan where 72
 * of 2,034 queries fired renders as 100% failed. This requirement carries the
 * denominator so the ratio is legible. Impact 0 keeps it out of the score,
 * matching buildNoFindingsRequirement.
 */
function buildCoverageRequirement(report: KicsReport, startTime: Date): EvaluatedRequirement {
  const executed = report.queries_total ?? 0;
  const fired = (report.queries ?? []).filter((q) => (q.files ?? []).length > 0).length;
  const summary =
    `KICS executed ${executed} queries against ${report.files_scanned ?? 0} file(s) ` +
    `(${report.files_parsed ?? 0} parsed); ${fired} produced findings. ` +
    `KICS reports violations only and does not enumerate the queries that ran ` +
    `without finding anything, so no passing requirements can be derived from ` +
    `its output and the compliance ratio should not be read as a pass rate.`;

  return {
    id: 'kics-scan-coverage',
    title: 'KICS scan coverage',
    impact: 0,
    descriptions: [{ label: 'default', data: summary }],
    results: [{ status: ResultStatus.Passed, codeDesc: summary, startTime }],
    tags: {
      queriesExecuted: executed,
      queriesWithFindings: fired,
      filesScanned: report.files_scanned ?? 0,
      filesParsed: report.files_parsed ?? 0,
      filesFailedToScan: report.files_failed_to_scan ?? 0,
      queriesFailedToExecute: report.queries_failed_to_execute ?? 0,
    },
  } as EvaluatedRequirement;
}

function buildRequirement(query: KicsQuery, startTime: Date): EvaluatedRequirement {
  const tags = tagsFor(query);
  const descriptions: Description[] = [{ label: 'default', data: query.description ?? '' }];

  const results: RequirementResult[] = (query.files ?? []).map((file) => ({
    // KICS reports only violations; there is no passing or suppressed state in
    // its output to derive anything else from.
    status: ResultStatus.Failed,
    codeDesc: locationFor(file),
    message: evidenceFor(file),
    startTime,
  }));

  const requirement = createRequirement(
    query.query_id ?? query.query_name ?? 'unknown',
    query.query_name ?? query.query_id ?? 'Unnamed KICS query',
    descriptions,
    impactFor(query.severity),
    results,
    { tags },
  ) as EvaluatedRequirement;

  requirement.verificationMethod = VerificationMethodEnum.Automated;
  const controlType = deriveControlTypeFromTags(tags.nist as string[]);
  if (controlType !== undefined) requirement.controlType = controlType;
  return requirement;
}

/**
 * Converts native `kics scan --report-formats json` output to HDF.
 *
 * KICS also emits SARIF, which carries its CWE taxonomy properly. What SARIF
 * drops is the remediation pair (`expected_value`), the add-a-block versus
 * fix-a-value distinction (`issue_type`), the stable finding fingerprint
 * (`similarity_id`), and one level of severity granularity.
 *
 * @param input - KICS JSON report string
 * @returns HDF JSON string
 */
export async function convertKicsToHdf(
  input: string,
  converterVersion = '1.0.0',
): Promise<string> {
  validateInputSize(input, 'kics');
  if (!input || input.trim().length === 0) {
    throw new Error('kics: empty input');
  }

  const report = parseJSON<KicsReport>(input);
  if (!Array.isArray(report.queries) || report.kics_version === undefined) {
    throw new Error('kics: input does not look like a KICS report');
  }

  const startTime = new Date();
  const requirements: EvaluatedRequirement[] = report.queries
    .filter((q) => Array.isArray(q.files) && q.files.length > 0)
    .map((q) => buildRequirement(q, startTime));

  if (requirements.length === 0) {
    requirements.push(
      buildNoFindingsRequirement(
        'kics-no-findings',
        `KICS scanned ${report.files_scanned ?? 0} file(s) and reported no findings.`,
        startTime,
      ),
    );
  }
  requirements.push(buildCoverageRequirement(report, startTime));

  const baseline: EvaluatedBaseline = createMinimalBaseline('KICS Scan', requirements, {
    title: 'KICS infrastructure-as-code scan',
    resultsChecksum: await inputChecksum(input),
  }) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'kics-to-hdf',
    converterVersion,
    toolName: 'KICS',
    toolVersion: report.kics_version,
    toolFormat: 'json',
    baselines: [baseline],
    timestamp: startTime,
  });
}
