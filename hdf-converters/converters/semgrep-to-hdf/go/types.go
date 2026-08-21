package semgrep

import "encoding/json"

// Report is the top-level `semgrep scan --json` output.
type Report struct {
	Results         []Result        `json:"results"`
	Errors          []ScanError     `json:"errors"`
	Version         string          `json:"version"`
	Paths           Paths           `json:"paths"`
	EngineRequested string          `json:"engine_requested"`
	RawResults      json.RawMessage `json:"-"`
}

// Paths records which files the scan covered. `skipped` is only emitted when
// files were actually skipped.
type Paths struct {
	Scanned []string `json:"scanned"`
}

// Result is one finding.
type Result struct {
	CheckID string   `json:"check_id"`
	Path    string   `json:"path"`
	Start   Position `json:"start"`
	End     Position `json:"end"`
	Extra   Extra    `json:"extra"`
}

// Position is a location within the scanned file.
type Position struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

// Extra carries the per-finding envelope.
type Extra struct {
	Message  string   `json:"message"`
	Metadata Metadata `json:"metadata"`
	Severity string   `json:"severity"`
	// Lines and Fingerprint are redacted to the literal string
	// "requires login" unless the scan is authenticated.
	Lines       string `json:"lines"`
	Fingerprint string `json:"fingerprint"`
	// Fix is replacement text for the matched span; present only when a rule
	// ships an autofix.
	Fix        string `json:"fix"`
	EngineKind string `json:"engine_kind"`
}

// Metadata is the rule-level registry metadata. Fields documented as arrays
// arrive as bare strings when a rule declares a single value, so anything
// list-shaped is decoded through StringOrSlice.
type Metadata struct {
	CWE                StringOrSlice `json:"cwe"`
	OWASP              StringOrSlice `json:"owasp"`
	References         StringOrSlice `json:"references"`
	Subcategory        StringOrSlice `json:"subcategory"`
	Technology         StringOrSlice `json:"technology"`
	VulnerabilityClass StringOrSlice `json:"vulnerability_class"`
	Confidence         string        `json:"confidence"`
	Likelihood         string        `json:"likelihood"`
	// Impact rates the severity of the consequence -- NOT the HDF impact float.
	Impact        string         `json:"impact"`
	Category      string         `json:"category"`
	Source        string         `json:"source"`
	Shortlink     string         `json:"shortlink"`
	SourceRuleURL string         `json:"source-rule-url"`
	BanditCode    string         `json:"bandit-code"`
	ASVS          map[string]any `json:"asvs"`
}

// ScanError is one error reported during the scan. Type is a heterogeneous
// array -- a discriminant string followed by an optional payload, e.g.
// ["PartialParsing", [{path, start, end}]] -- so it is decoded loosely and read
// only for its discriminant.
type ScanError struct {
	Message string `json:"message"`
	Level   string `json:"level"`
	Type    any    `json:"type"`
	Path    string `json:"path"`
}

// StringOrSlice decodes a JSON value that may be either a string or an array
// of strings into a slice.
type StringOrSlice []string

// UnmarshalJSON implements json.Unmarshaler.
func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single == "" {
			*s = nil
		} else {
			*s = []string{single}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		*s = many
		return nil
	}
	// A shape we do not model is treated as absent rather than fatal: one
	// unexpected metadata field should not fail the whole conversion.
	*s = nil
	return nil
}
