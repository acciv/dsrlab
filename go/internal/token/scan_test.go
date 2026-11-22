package token_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dsrlab/internal/token"
)

const (
	// All values below are synthetic placeholders, never real credentials.
	syntheticID        = "100000000000000001" // 18 digits, reserved dummy range
	syntheticTimestamp = "TEST01"             // 6 chars, explicitly non-secret
)

func syntheticToken() string {
	return syntheticID + "." + syntheticTimestamp + "." + strings.Repeat("A", 27)
}

func falsePositiveToken() string {
	return syntheticID + "." + syntheticTimestamp + ".DUMMY" + strings.Repeat("A", 22)
}

func mixedEntropyToken() string {
	return syntheticID + "." + syntheticTimestamp + "." +
		strings.Repeat("A", 13) + strings.Repeat("B", 14)
}

func expectedEntropy(value string) float64 {
	counts := make(map[byte]int)
	for i := 0; i < len(value); i++ {
		counts[value[i]]++
	}
	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(len(value))
		entropy -= p * math.Log2(p)
	}
	return math.Round(entropy*100) / 100
}

const validConfigJSON = `{
  "version": "1.0",
  "exclude_dirs": [".git", "node_modules"],
  "exclude_extensions": [".png", ".bin"],
  "max_file_bytes": 1048576,
  "max_line_bytes": 4096,
  "workers": 4,
  "patterns": [{
    "id": "discord_bot_token",
    "type": "discord_bot_token",
    "regex": "([0-9]{17,20})\\.([A-Za-z0-9_-]{6})\\.([A-Za-z0-9_-]{27})",
    "value_group": 3,
    "risk_weight": 50,
    "expected_length": 27
  }],
  "false_positive_markers": ["DUMMY", "FAKE", "EXAMPLE", "SAMPLE", "REDACTED", "PLACEHOLDER", "TESTKEY"],
  "risk_levels": {"low":25,"medium":50,"high":75,"critical":90}
}`

func configJSON(pattern, maxFile string) string {
	return fmt.Sprintf(`{"version":"1.0","max_file_bytes":%s,"max_line_bytes":4096,`+
		`"workers":1,"patterns":[%s],"false_positive_markers":["DUMMY"]}`,
		maxFile, pattern)
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadTestConfig(t *testing.T) token.Config {
	t.Helper()
	cfg, err := token.LoadConfig(writeConfig(t, validConfigJSON))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfig(t *testing.T) {
	cfg := loadTestConfig(t)
	if cfg.Version != "1.0" || cfg.MaxFileBytes != 1048576 || cfg.MaxLineBytes != 4096 {
		t.Fatalf("unexpected scalar config: %+v", cfg)
	}
	if cfg.Workers != 4 || len(cfg.ExcludeDirs) != 2 || len(cfg.Patterns) != 1 {
		t.Fatalf("unexpected config collections: %+v", cfg)
	}
	p := cfg.Patterns[0]
	if p.ID != "discord_bot_token" || p.Type != "discord_bot_token" ||
		p.ValueGroup != 3 || p.RiskWeight != 50 || p.ExpectedLength != 27 {
		t.Fatalf("unexpected pattern: %+v", p)
	}
	if cfg.RiskLevels["critical"] != 90 {
		t.Fatalf("unexpected risk levels: %v", cfg.RiskLevels)
	}
	// A successfully compiled pattern must actually detect a synthetic token.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), syntheticToken())
	report, err := token.ScanPath(root, cfg)
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("compiled pattern did not scan: report=%+v err=%v", report, err)
	}
}

func TestLoadConfigInvalid(t *testing.T) {
	goodPattern := `{"id":"p","type":"discord_bot_token",` +
		`"regex":"([0-9]{17,20})\\.([A-Za-z0-9_-]{6})\\.([A-Za-z0-9_-]{27})",` +
		`"value_group":3,"risk_weight":50,"expected_length":27}`
	cases := []struct {
		name   string
		config string
	}{
		{"bad regex", configJSON(strings.Replace(goodPattern, `"([0-9]`, `"([`, 1), "100")},
		{"missing id", configJSON(strings.Replace(goodPattern, `"id":"p"`, `"id":""`, 1), "100")},
		{"missing type", configJSON(strings.Replace(goodPattern, `"type":"discord_bot_token"`, `"type":""`, 1), "100")},
		{"empty regex", configJSON(strings.Replace(goodPattern, `"regex":"([0-9]{17,20})\\.([A-Za-z0-9_-]{6})\\.([A-Za-z0-9_-]{27})"`, `"regex":""`, 1), "100")},
		{"zero value group", configJSON(strings.Replace(goodPattern, `"value_group":3`, `"value_group":0`, 1), "100")},
		{"value group too large", configJSON(strings.Replace(goodPattern, `"value_group":3`, `"value_group":4`, 1), "100")},
		{"negative risk", configJSON(strings.Replace(goodPattern, `"risk_weight":50`, `"risk_weight":-1`, 1), "100")},
		{"negative expected length", configJSON(strings.Replace(goodPattern, `"expected_length":27`, `"expected_length":-1`, 1), "100")},
		{"zero file limit", configJSON(goodPattern, "0")},
		{"negative line limit", strings.Replace(configJSON(goodPattern, "100"), `"max_line_bytes":4096`, `"max_line_bytes":-1`, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := token.LoadConfig(writeConfig(t, tc.config)); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestDetectionShapeAndBoundaries(t *testing.T) {
	cfg := loadTestConfig(t)
	token1 := syntheticToken()
	fpToken := falsePositiveToken()
	root := t.TempDir()
	content := strings.Join([]string{
		token1,                         // line 1: bare match
		"prefix=" + token1 + ";suffix", // line 2: allowed neighbours
		"x" + token1,                   // line 3: preceding letter blocks match
		token1 + "_suffix",             // line 4: following underscore blocks match
		token1 + "-suffix",             // line 5: following hyphen blocks match
		// 21 digits: the only 20-digit suffix match has a digit before it.
		"9" + strings.Repeat("1", 20) + "." + syntheticTimestamp + "." + strings.Repeat("A", 27), // line 6
		"fp=" + fpToken, // line 7: false-positive marker
		"",
	}, "\n")
	writeFile(t, filepath.Join(root, "tokens.txt"), content)

	report, err := token.ScanPath(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if report.ScannedFiles != 1 || report.SkippedFiles != 0 {
		t.Fatalf("unexpected counters: %+v", report)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(report.Findings), report.Findings)
	}
	wantLines := []int{1, 2, 7}
	wantColumns := []int{1, len("prefix=") + 1, len("fp=") + 1}
	for i, finding := range report.Findings {
		if finding.Line != wantLines[i] || finding.Column != wantColumns[i] {
			t.Fatalf("finding %d: got line=%d column=%d, want %d/%d",
				i, finding.Line, finding.Column, wantLines[i], wantColumns[i])
		}
		if finding.File != "tokens.txt" || finding.Context != "discord_bot_token" {
			t.Fatalf("finding %d: unexpected file/context: %+v", i, finding)
		}
		matched := token1
		if i == 2 {
			matched = fpToken
		}
		sum := sha256.Sum256([]byte(matched))
		wantFingerprint := "sha256:" + hex.EncodeToString(sum[:])
		if finding.Fingerprint != wantFingerprint {
			t.Fatalf("finding %d: wrong fingerprint %s", i, finding.Fingerprint)
		}
		if finding.IDLength != 18 || finding.TimestampLength != 6 || finding.SecretLength != 27 {
			t.Fatalf("finding %d: wrong lengths %+v", i, finding)
		}
		secret := matched[strings.LastIndex(matched, ".")+1:]
		if wantEntropy := expectedEntropy(secret); finding.Entropy != wantEntropy {
			t.Fatalf("finding %d: entropy %v, want %v", i, finding.Entropy, wantEntropy)
		}
		if finding.FalsePositive != (i == 2) {
			t.Fatalf("finding %d: unexpected false_positive=%v", i, finding.FalsePositive)
		}
		encoded, _ := json.Marshal(finding)
		for _, secret := range []string{token1, fpToken, strings.Repeat("A", 27)} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("finding leaked a secret: %s", encoded)
			}
		}
	}
}

func TestEntropyRounding(t *testing.T) {
	cfg := loadTestConfig(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "entropy.txt"), mixedEntropyToken()+"\n")
	report, err := token.ScanPath(root, cfg)
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("scan failed: %+v err=%v", report, err)
	}
	secret := mixedEntropyToken()[strings.LastIndex(mixedEntropyToken(), ".")+1:]
	want := expectedEntropy(secret)
	if report.Findings[0].Entropy != want {
		t.Fatalf("entropy: got %v, want %v", report.Findings[0].Entropy, want)
	}
}

func TestScanPathSkips(t *testing.T) {
	cfg := loadTestConfig(t)
	cfg.MaxFileBytes = 1000
	cfg.MaxLineBytes = 80
	cfg.ExcludeDirs = append(cfg.ExcludeDirs, "skipdir")
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "good.txt"), syntheticToken()+"\n")
	writeFile(t, filepath.Join(root, "skipdir", "inside.txt"), syntheticToken())
	writeFile(t, filepath.Join(root, "image.PNG"), syntheticToken())
	writeFile(t, filepath.Join(root, "huge.txt"), strings.Repeat("x", 1200))
	writeFile(t, filepath.Join(root, "binary.txt"), "abc\x00"+syntheticToken())
	writeFile(t, filepath.Join(root, "longline.txt"),
		strings.Repeat("y", 90)+syntheticToken()+"\n"+syntheticToken()+"\n")

	report, err := token.ScanPath(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if report.ScannedFiles != 2 || report.SkippedFiles != 3 {
		t.Fatalf("unexpected counters: %+v", report)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(report.Findings), report.Findings)
	}
	if report.Findings[0].File != "good.txt" ||
		report.Findings[1].File != "longline.txt" || report.Findings[1].Line != 2 {
		t.Fatalf("unexpected finding order/content: %+v", report.Findings)
	}
}

func TestScanPath500FilesWithWorkers(t *testing.T) {
	cfg := loadTestConfig(t)
	cfg.Workers = 4
	root := t.TempDir()
	for i := 0; i < 500; i++ {
		writeFile(t, filepath.Join(root, fmt.Sprintf("case%03d.txt", i)),
			"value: "+syntheticToken()+"\n")
	}
	report, err := token.ScanPath(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if report.ScannedFiles != 500 || report.SkippedFiles != 0 || len(report.Findings) != 500 {
		t.Fatalf("unexpected report: scanned=%d skipped=%d findings=%d",
			report.ScannedFiles, report.SkippedFiles, len(report.Findings))
	}
	for i, finding := range report.Findings {
		want := fmt.Sprintf("case%03d.txt", i)
		if finding.File != want {
			t.Fatalf("finding %d: file=%s, want sorted %s", i, finding.File, want)
		}
	}
}

func TestScanPathReadError(t *testing.T) {
	cfg := loadTestConfig(t)
	root := filepath.Join(t.TempDir(), "missing")
	if _, err := token.ScanPath(root, cfg); err == nil {
		t.Fatal("expected an error for a nonexistent root")
	}
}

func TestWriteReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "TOKEN_RAW.json")
	report := token.Report{
		ScannedFiles: 1,
		SkippedFiles: 0,
		Findings: []token.Finding{{
			File: "sample.py", Line: 4, Column: 9,
			Fingerprint: "sha256:deadbeef", IDLength: 18,
			TimestampLength: 6, SecretLength: 27, Entropy: 4.12,
			Context: "discord_bot_token", FalsePositive: false,
		}},
	}
	if err := token.WriteReport(path, report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) || data[len(data)-1] != '\n' {
		t.Fatalf("report is not newline-terminated valid JSON: %q", data)
	}
	text := string(data)
	if !strings.Contains(text, "\n  \"scanned_files\": 1,") {
		t.Fatalf("report is not 2-space indented: %q", text)
	}
	if strings.Contains(text, syntheticToken()) || strings.Contains(text, "AAAAAAAA") {
		t.Fatalf("report leaked a secret: %q", text)
	}
	var decoded token.Report
	if err := json.Unmarshal(data, &decoded); err != nil || len(decoded.Findings) != 1 {
		t.Fatalf("cannot decode report: %v %+v", err, decoded)
	}

	emptyPath := filepath.Join(t.TempDir(), "empty.json")
	if err := token.WriteReport(emptyPath, token.Report{}); err != nil {
		t.Fatal(err)
	}
	emptyData, err := os.ReadFile(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(emptyData), `"findings": []`) {
		t.Fatalf("empty findings must be an array: %q", emptyData)
	}
}
