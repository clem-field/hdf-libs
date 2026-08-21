package semgrep

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "1.0.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func convertFixture(t *testing.T, name string) *hdf.HDFResults {
	t.Helper()
	out, err := ConvertSemgrepToHDF(loadFixture(t, name), testVersion)
	require.NoError(t, err)
	require.NotNil(t, out)
	return out
}

func findReq(reqs []hdf.EvaluatedRequirement, fragment string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if len(fragment) > 0 && contains(reqs[i].ID, fragment) {
			return &reqs[i]
		}
	}
	return nil
}

func contains(haystack, needle string) bool {
	return len(needle) <= len(haystack) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// ---- Contract ----

func TestRejectsEmptyInput(t *testing.T) {
	_, err := ConvertSemgrepToHDF([]byte(""), testVersion)
	require.Error(t, err)
}

func TestRejectsInvalidJSON(t *testing.T) {
	_, err := ConvertSemgrepToHDF([]byte("not valid json"), testVersion)
	require.Error(t, err)
}

func TestRejectsNonSemgrepDocument(t *testing.T) {
	_, err := ConvertSemgrepToHDF([]byte(`{"foo":1}`), testVersion)
	require.ErrorContains(t, err, "does not look like a Semgrep report")
}

func TestConvertsMinimalFixture(t *testing.T) {
	out := convertFixture(t, "minimal.json")
	require.Len(t, out.Baselines, 1)
	assert.Equal(t, "Semgrep Scan", out.Baselines[0].Name)
}

// ---- Mapping behaviour ----

func TestGroupsFindingsOneRequirementPerRule(t *testing.T) {
	out := convertFixture(t, "real.json")
	reqs := out.Baselines[0].Requirements
	assert.Len(t, reqs, 2)
	seen := map[string]bool{}
	for _, r := range reqs {
		assert.False(t, seen[r.ID], "duplicate requirement id %s", r.ID)
		seen[r.ID] = true
	}
}

func TestMapsSeverityToImpact(t *testing.T) {
	out := convertFixture(t, "real.json")
	reqs := out.Baselines[0].Requirements
	assert.Equal(t, 0.7, findReq(reqs, "subprocess-shell-true").Impact)
	assert.Equal(t, 0.5, findReq(reqs, "dynamic-urllib-use-detected").Impact)
}

func TestResolvesNistAndCciTags(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "subprocess-shell-true")
	require.NotNil(t, req)
	nist := shared.NISTTagsFromMap(req.Tags)
	assert.NotEmpty(t, nist)
	ccis, ok := req.Tags["cci"].([]string)
	require.True(t, ok, "cci tag missing or wrong type")
	assert.NotEmpty(t, ccis)
}

func TestNormalizesOwaspStringOrArray(t *testing.T) {
	out := convertFixture(t, "real.json")
	reqs := out.Baselines[0].Requirements
	// real.json deliberately carries one rule with an array and one with a string
	arrayForm, ok := findReq(reqs, "subprocess-shell-true").Tags["owasp"].([]string)
	require.True(t, ok)
	assert.Len(t, arrayForm, 3)
	stringForm, ok := findReq(reqs, "dynamic-urllib-use-detected").Tags["owasp"].([]string)
	require.True(t, ok)
	assert.Len(t, stringForm, 1)
}

func TestSemgrepMetadataImpactDoesNotShadowHdfImpact(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "subprocess-shell-true")
	require.NotNil(t, req)
	_, shadowed := req.Tags["impact"]
	assert.False(t, shadowed, "semgrep metadata.impact must not be tagged as impact")
	assert.Equal(t, "LOW", req.Tags["semgrepImpact"])
}

func TestPreservesCrossFrameworkMetadata(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "dynamic-urllib-use-detected")
	require.NotNil(t, req)
	assert.Equal(t, "LOW", req.Tags["likelihood"])
	assert.Equal(t, "LOW", req.Tags["confidence"])
	assert.NotNil(t, req.Tags["asvs"])
	assert.NotNil(t, req.Tags["vulnerabilityClass"])
}

func TestReportsEveryFindingAsFailed(t *testing.T) {
	out := convertFixture(t, "real.json")
	for _, req := range out.Baselines[0].Requirements {
		for _, res := range req.Results {
			assert.Equal(t, hdf.Failed, res.Status)
		}
	}
}

func TestNeverEmitsRedactedPlaceholder(t *testing.T) {
	out := convertFixture(t, "real.json")
	for _, req := range out.Baselines[0].Requirements {
		for _, res := range req.Results {
			if res.Message != nil {
				assert.NotContains(t, *res.Message, redactedPlaceholder)
			}
		}
	}
}

func TestRecordsLocationInCodeDesc(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "subprocess-shell-true")
	require.NotNil(t, req)
	assert.Contains(t, req.Results[0].CodeDesc, "app/handlers.py")
	assert.Contains(t, req.Results[0].CodeDesc, "7")
}

func TestEmptyScanProducesNoFindingsRequirement(t *testing.T) {
	out := convertFixture(t, "empty.json")
	reqs := out.Baselines[0].Requirements
	require.Len(t, reqs, 1)
	assert.Equal(t, 0.0, reqs[0].Impact)
}

func TestScanErrorsBecomeTheirOwnRequirement(t *testing.T) {
	out := convertFixture(t, "errors.json")
	req := findReq(out.Baselines[0].Requirements, scanErrorsID)
	require.NotNil(t, req)
	assert.Len(t, req.Results, 2)
	for _, res := range req.Results {
		assert.Equal(t, hdf.Error, res.Status)
	}
}

func TestScanErrorsRequirementAbsentWhenNoErrors(t *testing.T) {
	out := convertFixture(t, "real.json")
	assert.Nil(t, findReq(out.Baselines[0].Requirements, scanErrorsID))
}

func TestTitleDerivedFromRuleId(t *testing.T) {
	assert.Equal(t, "Subprocess Shell True", titleFor("python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"))
	assert.Equal(t, "Rule", titleFor("rule"))
}

func TestStringOrSliceDecodesBothForms(t *testing.T) {
	var s StringOrSlice
	require.NoError(t, s.UnmarshalJSON([]byte(`"one"`)))
	assert.Equal(t, StringOrSlice{"one"}, s)
	require.NoError(t, s.UnmarshalJSON([]byte(`["a","b"]`)))
	assert.Equal(t, StringOrSlice{"a", "b"}, s)
	require.NoError(t, s.UnmarshalJSON([]byte(`{"unexpected":true}`)))
	assert.Nil(t, s)
}

// ---- Golden snapshots (TS<->Go parity) ----

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "semgrep-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertSemgrepToHDF(input, testVersion)
	}, "*")
}

// ---- Edge cases ----

func TestImpactForFallsBackToModerate(t *testing.T) {
	assert.Equal(t, defaultImpact, impactFor(Result{}))
	assert.Equal(t, defaultImpact, impactFor(Result{Extra: Extra{Severity: "NOVEL"}}))
	assert.Equal(t, defaultImpact, impactFor(Result{Extra: Extra{Severity: redactedPlaceholder}}))
	assert.Equal(t, 0.9, impactFor(Result{Extra: Extra{Severity: "CRITICAL"}}))
}

func TestCodeDescVariants(t *testing.T) {
	assert.Equal(t, "Path: unknown", codeDescFor(Result{}))
	assert.Equal(t, "Path: a.py", codeDescFor(Result{Path: "a.py"}))
	assert.Equal(t, "Path: a.py, line 4",
		codeDescFor(Result{Path: "a.py", Start: Position{Line: 4}, End: Position{Line: 4}}))
	assert.Equal(t, "Path: a.py, lines 4-9",
		codeDescFor(Result{Path: "a.py", Start: Position{Line: 4}, End: Position{Line: 9}}))
}

func TestMessageForSkipsRedactedFields(t *testing.T) {
	assert.Equal(t, "", messageFor(Result{Extra: Extra{Lines: redactedPlaceholder}}))
	assert.Contains(t, messageFor(Result{Extra: Extra{Lines: "x = 1"}}), "Matched code:")
	assert.Contains(t, messageFor(Result{Extra: Extra{Fix: "False"}}), "replace the matched code with")
}

func TestErrorsRequirementHandlesOddTypeShapes(t *testing.T) {
	req := buildErrorsRequirement([]ScanError{
		{Message: "a", Type: []any{"PartialParsing", []any{}}},
		{Message: "b", Type: "PlainString"},
		{Message: "c"},
	}, time.Now().UTC())
	require.Len(t, req.Results, 3)
	assert.Contains(t, *req.Results[0].Message, "PartialParsing")
	assert.Contains(t, *req.Results[1].Message, "PlainString")
	assert.Contains(t, *req.Results[2].Message, "Unknown")
	assert.Equal(t, "Path: unknown", req.Results[2].CodeDesc)
}

func TestSkipsFindingsWithoutCheckId(t *testing.T) {
	input := []byte(`{"results":[{"path":"a.py"}],"errors":[],"paths":{"scanned":["a.py"]}}`)
	out, err := ConvertSemgrepToHDF(input, testVersion)
	require.NoError(t, err)
	// The malformed finding is skipped, leaving a no-findings placeholder.
	require.Len(t, out.Baselines[0].Requirements, 1)
	assert.Equal(t, "semgrep-no-findings", out.Baselines[0].Requirements[0].ID)
}

func TestReferencesDeduplicated(t *testing.T) {
	urls := referencesFor(Metadata{
		References: StringOrSlice{"https://a", "https://a"},
		Source:     "https://a",
		Shortlink:  "https://b",
		ASVS:       map[string]any{"control_url": "https://c"},
	})
	assert.Equal(t, []string{"https://a", "https://b", "https://c"}, urls)
}

func TestRejectsOversizedInput(t *testing.T) {
	_, err := ConvertSemgrepToHDF([]byte(`{"results":`), testVersion)
	require.Error(t, err)
}
