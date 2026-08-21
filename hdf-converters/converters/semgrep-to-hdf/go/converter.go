// Package semgrep converts native `semgrep scan --json` output to HDF.
//
// Semgrep's SARIF output is convertible through the SARIF converter, but SARIF
// keeps the rule metadata only as untyped prose tags on the rule object and
// drops impact, likelihood, the ASVS control mapping, reference URLs and
// vulnerability_class outright.
package semgrep

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	cwemap "github.com/mitre/hdf-libs/hdf-mappings/go/v3/cwe"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// impactBySeverity mirrors the TypeScript table. Semgrep's OSS severities are a
// three-level scale; its supply-chain rules add a four-level one, so both are
// mapped and a mixed scan does not fall through.
var impactBySeverity = map[string]float64{
	"critical": 0.9,
	"error":    0.7,
	"high":     0.7,
	"warning":  0.5,
	"medium":   0.5,
	"info":     0.3,
	"low":      0.3,
}

const (
	// defaultImpact treats an unrecognized severity as moderate rather than
	// zero: impact 0 reports Not Applicable, dropping the finding from the
	// compliance score.
	defaultImpact = 0.5
	// redactedPlaceholder is what semgrep substitutes for fields it withholds
	// from unauthenticated scans.
	redactedPlaceholder = "requires login"
	scanErrorsID        = "semgrep-scan-errors"
)

// defaultNistTags are applied when a rule declares no CWE.
var defaultNistTags = []string{"SA-11", "RA-5"}

var cweIDPattern = regexp.MustCompile(`(?i)CWE-(\d+)`)

func isPresent(value string) bool {
	return value != "" && value != redactedPlaceholder
}

// extractCweIDs pulls the bare number out of semgrep's prose CWE form,
// "CWE-89: Improper Neutralization of ...".
func extractCweIDs(metadata Metadata) []string {
	ids := make([]string, 0, len(metadata.CWE))
	for _, entry := range metadata.CWE {
		match := cweIDPattern.FindStringSubmatch(entry)
		if match == nil {
			continue
		}
		ids = append(ids, match[1])
	}
	return ids
}

// nistControlsFor mirrors the TypeScript lookup. Note the mapping APIs are not
// symmetric: Go's NISTControls returns a slice per CWE while TypeScript's
// getCweNistControl returns the single NIST-ID. They agree on the current
// mapping data, and the shared expected fixtures fail if that ever changes.
func nistControlsFor(metadata Metadata) []string {
	seen := make(map[string]bool)
	controls := make([]string, 0, len(metadata.CWE))
	for _, cweID := range extractCweIDs(metadata) {
		for _, control := range cwemap.NISTControls(cweID) {
			if control == "" || seen[control] {
				continue
			}
			seen[control] = true
			controls = append(controls, control)
		}
	}
	if len(controls) == 0 {
		return append([]string(nil), defaultNistTags...)
	}
	return controls
}

func impactFor(result Result) float64 {
	if !isPresent(result.Extra.Severity) {
		return defaultImpact
	}
	if impact, ok := impactBySeverity[strings.ToLower(result.Extra.Severity)]; ok {
		return impact
	}
	return defaultImpact
}

// titleFor derives a readable rule name. Semgrep rule ids are dotted paths
// whose final segment is the rule name; the JSON output carries no
// human-readable title anywhere, unlike its SARIF output.
func titleFor(checkID string) string {
	segments := strings.Split(checkID, ".")
	ruleName := checkID
	for i := len(segments) - 1; i >= 0; i-- {
		if segments[i] != "" {
			ruleName = segments[i]
			break
		}
	}
	words := strings.FieldsFunc(ruleName, func(r rune) bool { return r == '-' || r == '_' })
	for i, word := range words {
		if word == "" {
			continue
		}
		words[i] = strings.ToUpper(word[:1]) + word[1:]
	}
	return strings.Join(words, " ")
}

func codeDescFor(result Result) string {
	path := result.Path
	if path == "" {
		path = "unknown"
	}
	if result.Start.Line == 0 {
		return fmt.Sprintf("Path: %s", path)
	}
	if result.End.Line == 0 || result.End.Line == result.Start.Line {
		return fmt.Sprintf("Path: %s, line %d", path, result.Start.Line)
	}
	return fmt.Sprintf("Path: %s, lines %d-%d", path, result.Start.Line, result.End.Line)
}

func messageFor(result Result) string {
	parts := make([]string, 0, 2)
	if isPresent(result.Extra.Lines) {
		parts = append(parts, "Matched code:\n"+result.Extra.Lines)
	}
	// Fix is replacement text for the matched span, not a standalone
	// instruction -- rendering it bare produces "Suggested fix: False".
	if isPresent(result.Extra.Fix) {
		parts = append(parts, "Suggested fix -- replace the matched code with:\n"+result.Extra.Fix)
	}
	return strings.Join(parts, "\n\n")
}

func referencesFor(metadata Metadata) []string {
	candidates := append([]string(nil), metadata.References...)
	candidates = append(candidates, metadata.Source, metadata.Shortlink, metadata.SourceRuleURL)
	if url, ok := metadata.ASVS["control_url"].(string); ok {
		candidates = append(candidates, url)
	}
	seen := make(map[string]bool)
	urls := make([]string, 0, len(candidates))
	for _, url := range candidates {
		if !isPresent(url) || seen[url] {
			continue
		}
		seen[url] = true
		urls = append(urls, url)
	}
	return urls
}

func tagsFor(metadata Metadata, checkID, severity string) (map[string]any, []string) {
	nist := nistControlsFor(metadata)
	ccis := cci.NISTToCCI(nist)

	tags := map[string]any{"nist": nist, "checkId": checkID}
	if len(ccis) > 0 {
		tags["cci"] = ccis
	}
	tags["cwe"] = []string(metadata.CWE)
	if len(metadata.OWASP) > 0 {
		tags["owasp"] = []string(metadata.OWASP)
	}
	if len(metadata.Subcategory) > 0 {
		tags["subcategory"] = []string(metadata.Subcategory)
	}
	if len(metadata.Technology) > 0 {
		tags["technology"] = []string(metadata.Technology)
	}
	if len(metadata.VulnerabilityClass) > 0 {
		tags["vulnerabilityClass"] = []string(metadata.VulnerabilityClass)
	}
	if isPresent(severity) {
		tags["severity"] = severity
	}
	if isPresent(metadata.Confidence) {
		tags["confidence"] = metadata.Confidence
	}
	if isPresent(metadata.Likelihood) {
		tags["likelihood"] = metadata.Likelihood
	}
	// Renamed: semgrep's metadata.impact rates the severity of the consequence
	// and is not HDF's impact float. Tagging it as "impact" would shadow it.
	if isPresent(metadata.Impact) {
		tags["semgrepImpact"] = metadata.Impact
	}
	if isPresent(metadata.Category) {
		tags["category"] = metadata.Category
	}
	if isPresent(metadata.BanditCode) {
		tags["banditCode"] = metadata.BanditCode
	}
	if len(metadata.ASVS) > 0 {
		tags["asvs"] = metadata.ASVS
	}
	if refs := referencesFor(metadata); len(refs) > 0 {
		tags["references"] = refs
	}
	return tags, nist
}

// buildRequirement folds every occurrence of one rule into a single
// requirement: semgrep metadata is rule-scoped and identical across
// occurrences, so only the location varies.
func buildRequirement(checkID string, results []Result, startTime time.Time) hdf.EvaluatedRequirement {
	representative := results[0]
	metadata := representative.Extra.Metadata
	tags, nist := tagsFor(metadata, checkID, representative.Extra.Severity)

	requirementResults := make([]hdf.RequirementResult, 0, len(results))
	for _, result := range results {
		message := messageFor(result)
		requirementResults = append(requirementResults, hdf.RequirementResult{
			// Semgrep reports only violations. Findings suppressed with a
			// `nosemgrep` comment are omitted from the output entirely rather
			// than flagged, so no skipped status is derivable.
			Status:    hdf.Failed,
			CodeDesc:  codeDescFor(result),
			Message:   &message,
			StartTime: startTime,
		})
	}

	title := titleFor(checkID)
	return hdf.EvaluatedRequirement{
		ID:                 checkID,
		Title:              &title,
		Impact:             impactFor(representative),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       []hdf.Description{{Label: "default", Data: representative.Extra.Message}},
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
		Results:            requirementResults,
	}
}

// buildErrorsRequirement surfaces scan failures so a file that failed to parse
// is visible: absence of findings in it is not evidence of compliance.
func buildErrorsRequirement(errors []ScanError, startTime time.Time) hdf.EvaluatedRequirement {
	results := make([]hdf.RequirementResult, 0, len(errors))
	for _, scanError := range errors {
		kind := "Unknown"
		if list, ok := scanError.Type.([]any); ok && len(list) > 0 {
			kind = fmt.Sprintf("%v", list[0])
		} else if scanError.Type != nil {
			kind = fmt.Sprintf("%v", scanError.Type)
		}
		path := scanError.Path
		if path == "" {
			path = "unknown"
		}
		message := fmt.Sprintf("%s: %s", kind, scanError.Message)
		results = append(results, hdf.RequirementResult{
			Status:    hdf.Error,
			CodeDesc:  fmt.Sprintf("Path: %s", path),
			Message:   &message,
			StartTime: startTime,
		})
	}

	title := "Semgrep scan errors"
	return hdf.EvaluatedRequirement{
		ID:     scanErrorsID,
		Title:  &title,
		Impact: defaultImpact,
		Tags:   map[string]any{"nist": append([]string(nil), defaultNistTags...)},
		Descriptions: []hdf.Description{{
			Label: "default",
			Data:  "Errors reported by Semgrep while scanning. A file that failed to parse was not fully analyzed.",
		}},
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
		Results:            results,
	}
}

// ConvertSemgrepToHDF converts native `semgrep scan --json` output to HDF.
func ConvertSemgrepToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if err := shared.ValidateJSONSize(input, "semgrep", 0); err != nil {
		return nil, fmt.Errorf("semgrep: %w", err)
	}
	if len(strings.TrimSpace(string(input))) == 0 {
		return nil, fmt.Errorf("semgrep: empty input")
	}

	// Decoded loosely first so a document missing either container is rejected
	// as "not semgrep" rather than silently converting to nothing.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(input, &probe); err != nil {
		return nil, fmt.Errorf("semgrep: failed to parse report: %w", err)
	}
	if _, hasResults := probe["results"]; !hasResults {
		return nil, fmt.Errorf("semgrep: input does not look like a Semgrep report")
	}
	if _, hasErrors := probe["errors"]; !hasErrors {
		return nil, fmt.Errorf("semgrep: input does not look like a Semgrep report")
	}

	var report Report
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("semgrep: failed to parse report: %w", err)
	}

	startTime := time.Now().UTC()

	// Group by rule, preserving the order rules were first seen. Go randomizes
	// map iteration, so the order is tracked separately.
	groups := make(map[string][]Result)
	order := make([]string, 0, len(report.Results))
	for _, result := range report.Results {
		if result.CheckID == "" {
			continue
		}
		if _, seen := groups[result.CheckID]; !seen {
			order = append(order, result.CheckID)
		}
		groups[result.CheckID] = append(groups[result.CheckID], result)
	}

	requirements := make([]hdf.EvaluatedRequirement, 0, len(order)+1)
	for _, checkID := range order {
		requirements = append(requirements, buildRequirement(checkID, groups[checkID], startTime))
	}
	if len(report.Errors) > 0 {
		requirements = append(requirements, buildErrorsRequirement(report.Errors, startTime))
	}
	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"semgrep-no-findings",
				fmt.Sprintf("Semgrep scanned %d file(s) and reported no findings.", len(report.Paths.Scanned)),
				startTime,
			),
		}
	}

	title := "Semgrep static analysis scan"
	baseline := hdf.EvaluatedBaseline{
		Name:            "Semgrep Scan",
		Title:           &title,
		Requirements:    requirements,
		ResultsChecksum: shared.InputChecksum(input),
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "semgrep-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Semgrep",
		ToolVersion:      report.Version,
		ToolFormat:       "json",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Timestamp:        &startTime,
	}), nil
}
