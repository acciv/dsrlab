package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// Finding is a masked detection result. It deliberately has no field holding
// the matched secret: only its fingerprint, lengths and entropy are exposed.
type Finding struct {
	File            string  `json:"file"`
	Line            int     `json:"line"`
	Column          int     `json:"column"`
	Fingerprint     string  `json:"fingerprint"`
	IDLength        int     `json:"id_length"`
	TimestampLength int     `json:"timestamp_length"`
	SecretLength    int     `json:"secret_length"`
	Entropy         float64 `json:"entropy"`
	Context         string  `json:"context"`
	FalsePositive   bool    `json:"false_positive"`
}

// Report is the RAW token report. Findings is always a slice, never nil.
type Report struct {
	ScannedFiles int       `json:"scanned_files"`
	SkippedFiles int       `json:"skipped_files"`
	Findings     []Finding `json:"findings"`
}

type compiledPattern struct {
	id         string
	valueGroup int
	re         *regexp.Regexp
}

func preparePatterns(patterns []Pattern) ([]compiledPattern, error) {
	out := make([]compiledPattern, 0, len(patterns))
	for i, p := range patterns {
		if p.ID == "" || p.Regex == "" {
			return nil, fmt.Errorf("patterns[%d]: id and regex must not be empty", i)
		}
		re := p.re
		if re == nil {
			var err error
			re, err = regexp.Compile(p.Regex)
			if err != nil {
				return nil, fmt.Errorf("patterns[%d] (%s): invalid regex: %w", i, p.ID, err)
			}
		}
		if p.ValueGroup < 1 || p.ValueGroup > re.NumSubexp() {
			return nil, fmt.Errorf("patterns[%d] (%s): value_group %d outside 1..%d",
				i, p.ID, p.ValueGroup, re.NumSubexp())
		}
		out = append(out, compiledPattern{id: p.ID, valueGroup: p.ValueGroup, re: re})
	}
	return out, nil
}

// ScanPath walks root concurrently and returns deterministic, masked findings.
// Excluded directories are pruned by base name; excluded extensions, oversized
// files and files containing NUL bytes are counted as skipped.
func ScanPath(root string, cfg Config) (Report, error) {
	patterns, err := preparePatterns(cfg.Patterns)
	if err != nil {
		return Report{}, err
	}

	excludedDirs := make(map[string]struct{}, len(cfg.ExcludeDirs))
	for _, name := range cfg.ExcludeDirs {
		excludedDirs[strings.ToLower(name)] = struct{}{}
	}
	excludedExts := make(map[string]struct{}, len(cfg.ExcludeExtensions))
	for _, ext := range cfg.ExcludeExtensions {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext != "" && !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		excludedExts[ext] = struct{}{}
	}

	maxFileBytes := cfg.MaxFileBytes
	if maxFileBytes <= 0 { // programmatic configs: treat non-positive as unlimited
		maxFileBytes = int64(^uint64(0) >> 1)
	}
	maxLineBytes := cfg.MaxLineBytes
	if maxLineBytes <= 0 {
		maxLineBytes = int64(^uint64(0) >> 1)
	}

	files := make([]string, 0)
	skippedInWalk := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			// Never prune the scan root itself, even if its name is excluded.
			if path != root {
				if _, excluded := excludedDirs[strings.ToLower(entry.Name())]; excluded {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if _, excluded := excludedExts[strings.ToLower(filepath.Ext(entry.Name()))]; excluded {
			skippedInWalk++
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			skippedInWalk++
			return nil
		}
		if info.Size() > maxFileBytes {
			skippedInWalk++
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return Report{}, fmt.Errorf("walk %s: %w", root, err)
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers > len(files) && len(files) > 0 {
		workers = len(files)
	}

	type workerResult struct {
		findings []Finding
		scanned  int
		skipped  int
		err      error
	}
	results := make([]workerResult, workers)
	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for path := range jobs {
				found, scanned, skipped, err := scanFile(path, root, patterns, maxLineBytes,
					cfg.FalsePositiveMarkers)
				if err != nil {
					if results[index].err == nil {
						results[index].err = err
					}
					continue // keep draining the job channel
				}
				results[index].findings = append(results[index].findings, found...)
				results[index].scanned += scanned
				results[index].skipped += skipped
			}
		}(i)
	}
	for _, path := range files {
		jobs <- path
	}
	close(jobs)
	wg.Wait()

	report := Report{Findings: make([]Finding, 0), SkippedFiles: skippedInWalk}
	for _, result := range results {
		if result.err != nil {
			return Report{}, result.err
		}
		report.ScannedFiles += result.scanned
		report.SkippedFiles += result.skipped
		report.Findings = append(report.Findings, result.findings...)
	}
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.Context != b.Context {
			return a.Context < b.Context
		}
		return a.Fingerprint < b.Fingerprint
	})
	return report, nil
}

func scanFile(path, root string, patterns []compiledPattern, maxLineBytes int64,
	markers []string) ([]Finding, int, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read %s: %w", path, err)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, 0, 1, nil // binary file
	}

	name := filepath.Base(path)
	if rel, err := filepath.Rel(root, path); err == nil && rel != "." {
		name = filepath.ToSlash(rel)
	}

	findings := make([]Finding, 0)
	lineNumber := 1
	for content := string(data); len(content) > 0; lineNumber++ {
		var line string
		if newline := strings.IndexByte(content, '\n'); newline >= 0 {
			line = content[:newline]
			content = content[newline+1:]
		} else {
			line = content
			content = ""
		}
		if int64(len(line)) > maxLineBytes {
			continue
		}
		findings = append(findings, scanLine(name, lineNumber, line, patterns, markers)...)
	}
	return findings, 1, 0, nil
}

func scanLine(file string, lineNumber int, line string, patterns []compiledPattern,
	markers []string) []Finding {
	findings := make([]Finding, 0)
	for _, pattern := range patterns {
		for _, match := range pattern.re.FindAllStringSubmatchIndex(line, -1) {
			start, end := match[0], match[1]
			// Whole-match boundaries: neighbours must not be token characters.
			if start > 0 && isTokenChar(line[start-1]) {
				continue
			}
			if end < len(line) && isTokenChar(line[end]) {
				continue
			}
			full := line[start:end]
			secret := capture(line, match, 3, pattern.valueGroup)
			id := capture(line, match, 1, pattern.valueGroup)
			timestamp := capture(line, match, 2, pattern.valueGroup)
			if secret == "" || id == "" || timestamp == "" {
				continue
			}

			sum := sha256.Sum256([]byte(full))
			falsePositive := false
			for _, marker := range markers {
				if marker != "" && strings.Contains(full, marker) {
					falsePositive = true
					break
				}
			}

			findings = append(findings, Finding{
				File:            file,
				Line:            lineNumber,
				Column:          start + 1,
				Fingerprint:     "sha256:" + hex.EncodeToString(sum[:]),
				IDLength:        len(id),
				TimestampLength: len(timestamp),
				SecretLength:    len(secret),
				Entropy:         shannonEntropy(secret),
				Context:         pattern.id,
				FalsePositive:   falsePositive,
			})
		}
	}
	return findings
}

func isTokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '_' || c == '-'
}

// capture returns submatch group "preferred", falling back to "fallback"
// when a programmatic pattern has fewer groups than the standard token shape.
func capture(s string, match []int, preferred, fallback int) string {
	for _, group := range []int{preferred, fallback} {
		idx := group * 2
		if idx+1 < len(match) && match[idx] >= 0 && match[idx+1] >= match[idx] {
			return s[match[idx]:match[idx+1]]
		}
	}
	return ""
}

// shannonEntropy returns byte entropy in bits, rounded to two decimals.
func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[byte]int)
	for i := 0; i < len(value); i++ {
		counts[value[i]]++
	}
	total := float64(len(value))
	var entropy float64
	for _, count := range counts {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return math.Round(entropy*100) / 100
}

// WriteReport writes 2-space indented JSON with a trailing newline.
func WriteReport(path string, report Report) error {
	copy := report
	if copy.Findings == nil {
		copy.Findings = []Finding{}
	}
	data, err := json.MarshalIndent(copy, "", "  ")
	if err != nil {
		return fmt.Errorf("encode token report: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write token report: %w", err)
	}
	return nil
}
