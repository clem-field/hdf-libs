import { parseJSON } from '@mitre/hdf-utilities';
import { getCweNistControl, nistToCci } from '@mitre/hdf-mappings';
import {
  buildHdfResults,
  buildNistCciTags,
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  inputChecksum,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
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

/**
 * Rule-level metadata from the Semgrep registry. Every field is optional: a
 * locally authored rule may declare none of it.
 *
 * Fields documented as arrays arrive as bare strings when a rule declares a
 * single value, so anything list-shaped is typed permissively and normalized
 * on read.
 */
interface SemgrepMetadata {
  cwe?: string[] | string;
  owasp?: string[] | string;
  references?: string[] | string;
  subcategory?: string[] | string;
  technology?: string[] | string;
  vulnerability_class?: string[] | string;
  confidence?: string;
  likelihood?: string;
  /** Severity of the consequence -- NOT the HDF impact float. */
  impact?: string;
  category?: string;
  source?: string;
  shortlink?: string;
  'source-rule-url'?: string;
  'bandit-code'?: string;
  asvs?: Record<string, unknown>;
}

interface SemgrepExtra {
  message?: string;
  metadata?: SemgrepMetadata;
  severity?: string;
  /** Redacted to 'requires login' unless the scan is authenticated. */
  lines?: string;
  fingerprint?: string;
  /** Replacement text for the matched span; only present when a rule autofixes. */
  fix?: string;
  engine_kind?: string;
}

interface SemgrepPosition {
  line?: number;
  col?: number;
}

interface SemgrepResult {
  check_id: string;
  path?: string;
  start?: SemgrepPosition;
  end?: SemgrepPosition;
  extra?: SemgrepExtra;
}

/**
 * `type` is a heterogeneous array -- a discriminant string followed by an
 * optional payload, e.g. ['PartialParsing', [{path, start, end}]].
 */
interface SemgrepError {
  message?: string;
  level?: string;
  type?: unknown;
  path?: string;
}

interface SemgrepReport {
  results?: SemgrepResult[];
  errors?: SemgrepError[];
  version?: string;
  paths?: { scanned?: string[]; skipped?: unknown[] };
  engine_requested?: string;
}

/**
 * Semgrep's OSS severities are a three-level scale; its supply-chain rules add
 * a four-level one. Both are mapped so a mixed scan does not fall through.
 */
const IMPACT_BY_SEVERITY: Record<string, number> = {
  critical: 0.9,
  error: 0.7,
  high: 0.7,
  warning: 0.5,
  medium: 0.5,
  info: 0.3,
  low: 0.3,
};

/**
 * An unrecognized severity is treated as moderate rather than zero: impact 0
 * reports Not Applicable, which would drop the finding from the score.
 */
const DEFAULT_IMPACT = 0.5;

/** Fields Semgrep redacts in unauthenticated (OSS) scans. */
const REDACTED_PLACEHOLDER = 'requires login';

/** Applied when a rule declares no CWE, matching the static-analysis default. */
const DEFAULT_NIST_TAGS = ['SA-11', 'RA-5'];

const SCAN_ERRORS_ID = 'semgrep-scan-errors';

function isPresent(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value !== REDACTED_PLACEHOLDER;
}

function normalizeToArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === 'string');
  }
  return typeof value === 'string' ? [value] : [];
}

/**
 * Semgrep emits CWEs in prose form -- 'CWE-89: Improper Neutralization of ...'
 * -- while the mapping keys on the bare number.
 */
function extractCweIds(metadata: SemgrepMetadata): number[] {
  return normalizeToArray(metadata.cwe)
    .map((entry) => /CWE-(\d+)/i.exec(entry)?.[1])
    .filter((id): id is string => id !== undefined)
    .map((id) => Number.parseInt(id, 10))
    .filter((id) => Number.isFinite(id));
}

function nistControlsFor(metadata: SemgrepMetadata): string[] {
  const controls = extractCweIds(metadata)
    .map((cweId) => getCweNistControl(cweId))
    .filter(isPresent);
  const deduped = [...new Set(controls)];
  return deduped.length > 0 ? deduped : [...DEFAULT_NIST_TAGS];
}

function impactFor(result: SemgrepResult): number {
  const severity = result.extra?.severity;
  if (!isPresent(severity)) {
    return DEFAULT_IMPACT;
  }
  return IMPACT_BY_SEVERITY[severity.toLowerCase()] ?? DEFAULT_IMPACT;
}

/**
 * Semgrep rule ids are dotted paths whose final segment is the rule name. The
 * JSON output carries no human-readable rule title anywhere -- unlike the SARIF
 * output, whose rule objects have `name` and `shortDescription` -- so one is
 * derived.
 */
function titleFor(checkId: string): string {
  const segments = checkId.split('.').filter((segment) => segment.length > 0);
  const ruleName = segments[segments.length - 1] ?? checkId;
  return ruleName
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function codeDescFor(result: SemgrepResult): string {
  const path = result.path ?? 'unknown';
  const startLine = result.start?.line;
  const endLine = result.end?.line;
  if (startLine === undefined) {
    return `Path: ${path}`;
  }
  const span =
    endLine === undefined || endLine === startLine
      ? `line ${startLine}`
      : `lines ${startLine}-${endLine}`;
  return `Path: ${path}, ${span}`;
}

function messageFor(result: SemgrepResult): string {
  const parts: string[] = [];
  if (isPresent(result.extra?.lines)) {
    parts.push(`Matched code:\n${result.extra.lines}`);
  }
  // `fix` is replacement text for the matched span, not a standalone
  // instruction -- rendering it bare produces 'Suggested fix: False'.
  if (isPresent(result.extra?.fix)) {
    parts.push(`Suggested fix -- replace the matched code with:\n${result.extra.fix}`);
  }
  return parts.join('\n\n');
}

/** Documentation and cross-framework links, deduplicated. */
function referencesFor(metadata: SemgrepMetadata): string[] {
  const urls = [
    ...normalizeToArray(metadata.references),
    metadata.source,
    metadata.shortlink,
    metadata['source-rule-url'],
    typeof metadata.asvs?.control_url === 'string' ? metadata.asvs.control_url : undefined,
  ].filter(isPresent);
  return [...new Set(urls)];
}

function tagsFor(metadata: SemgrepMetadata, checkId: string, severity?: string): Record<string, unknown> {
  const nist = [...new Set(nistControlsFor(metadata))];
  const cci = nistToCci(nist);

  const extras: Record<string, unknown> = {
    checkId,
    cwe: normalizeToArray(metadata.cwe),
  };
  const owasp = normalizeToArray(metadata.owasp);
  if (owasp.length > 0) extras.owasp = owasp;
  const subcategory = normalizeToArray(metadata.subcategory);
  if (subcategory.length > 0) extras.subcategory = subcategory;
  const technology = normalizeToArray(metadata.technology);
  if (technology.length > 0) extras.technology = technology;
  const vulnerabilityClass = normalizeToArray(metadata.vulnerability_class);
  if (vulnerabilityClass.length > 0) extras.vulnerabilityClass = vulnerabilityClass;
  if (isPresent(severity)) extras.severity = severity;
  if (isPresent(metadata.confidence)) extras.confidence = metadata.confidence;
  if (isPresent(metadata.likelihood)) extras.likelihood = metadata.likelihood;
  // Renamed: semgrep's metadata.impact rates the severity of the consequence
  // and is not HDF's impact float. Tagging it as `impact` would shadow it.
  if (isPresent(metadata.impact)) extras.semgrepImpact = metadata.impact;
  if (isPresent(metadata.category)) extras.category = metadata.category;
  if (isPresent(metadata['bandit-code'])) extras.banditCode = metadata['bandit-code'];
  if (metadata.asvs && typeof metadata.asvs === 'object') extras.asvs = metadata.asvs;
  const references = referencesFor(metadata);
  if (references.length > 0) extras.references = references;

  return buildNistCciTags(nist, cci, extras);
}

/** Every occurrence of one rule becomes a result under a single requirement. */
function buildRequirement(
  checkId: string,
  results: SemgrepResult[],
  startTime: Date,
): EvaluatedRequirement {
  const representative = results[0]!;
  const metadata = representative.extra?.metadata ?? {};
  const description = representative.extra?.message ?? '';

  const descriptions: Description[] = [{ label: 'default', data: description }];

  const requirementResults: RequirementResult[] = results.map((result) => ({
    // Semgrep reports only violations. Findings suppressed with a `nosemgrep`
    // comment are omitted from the output entirely rather than flagged, so no
    // skipped status is derivable.
    status: ResultStatus.Failed,
    codeDesc: codeDescFor(result),
    message: messageFor(result),
    startTime,
  }));

  const tags = tagsFor(metadata, checkId, representative.extra?.severity);

  const requirement = createRequirement(
    checkId,
    titleFor(checkId),
    descriptions,
    impactFor(representative),
    requirementResults,
    { tags },
  ) as EvaluatedRequirement;

  requirement.verificationMethod = VerificationMethodEnum.Automated;
  const controlType = deriveControlTypeFromTags(tags.nist as string[]);
  if (controlType !== undefined) {
    requirement.controlType = controlType;
  }
  return requirement;
}

/**
 * Scan failures become their own requirement so a file that failed to parse is
 * visible rather than buried: absence of findings in it is not evidence of
 * compliance.
 */
function buildErrorsRequirement(errors: SemgrepError[], startTime: Date): EvaluatedRequirement {
  const results: RequirementResult[] = errors.map((error) => {
    const kind = Array.isArray(error.type) ? String(error.type[0]) : String(error.type ?? 'Unknown');
    return {
      status: ResultStatus.Error,
      codeDesc: `Path: ${error.path ?? 'unknown'}`,
      message: `${kind}: ${error.message ?? ''}`,
      startTime,
    };
  });

  const requirement = createRequirement(
    SCAN_ERRORS_ID,
    'Semgrep scan errors',
    [
      {
        label: 'default',
        data: 'Errors reported by Semgrep while scanning. A file that failed to parse was not fully analyzed.',
      },
    ],
    DEFAULT_IMPACT,
    results,
    { tags: buildNistCciTags([...DEFAULT_NIST_TAGS], []) },
  ) as EvaluatedRequirement;
  requirement.verificationMethod = VerificationMethodEnum.Automated;
  return requirement;
}

/**
 * Converts native `semgrep scan --json` output to HDF Results.
 *
 * The SARIF output is convertible through the SARIF converter, but SARIF keeps
 * the rule metadata only as untyped prose tags on the rule object and drops
 * impact, likelihood, the ASVS control mapping, reference URLs and
 * vulnerability_class outright.
 *
 * @param input - Semgrep JSON report string
 * @returns HDF JSON string
 */
export async function convertSemgrepToHdf(
  input: string,
  converterVersion = '1.0.0',
): Promise<string> {
  validateInputSize(input, 'semgrep');
  if (!input || input.trim().length === 0) {
    throw new Error('semgrep: empty input');
  }

  const report = parseJSON<SemgrepReport>(input);
  if (!Array.isArray(report.results) || !Array.isArray(report.errors)) {
    throw new Error('semgrep: input does not look like a Semgrep report');
  }

  const startTime = new Date();

  // Group by rule, preserving the order rules were first seen.
  const groups = new Map<string, SemgrepResult[]>();
  for (const result of report.results) {
    if (typeof result?.check_id !== 'string') {
      continue;
    }
    const existing = groups.get(result.check_id);
    if (existing) {
      existing.push(result);
    } else {
      groups.set(result.check_id, [result]);
    }
  }

  const requirements: EvaluatedRequirement[] = [];
  for (const [checkId, results] of groups) {
    requirements.push(buildRequirement(checkId, results, startTime));
  }
  if (report.errors.length > 0) {
    requirements.push(buildErrorsRequirement(report.errors, startTime));
  }
  if (requirements.length === 0) {
    const scanned = report.paths?.scanned?.length ?? 0;
    requirements.push(
      buildNoFindingsRequirement(
        'semgrep-no-findings',
        `Semgrep scanned ${scanned} file(s) and reported no findings.`,
        startTime,
      ),
    );
  }

  const resultsChecksum = await inputChecksum(input);
  const baseline: EvaluatedBaseline = createMinimalBaseline('Semgrep Scan', requirements, {
    title: 'Semgrep static analysis scan',
    resultsChecksum,
  }) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'semgrep-to-hdf',
    converterVersion,
    toolName: 'Semgrep',
    toolVersion: report.version,
    toolFormat: 'json',
    baselines: [baseline],
    timestamp: startTime,
  });
}
