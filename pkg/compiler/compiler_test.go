// SPDX-FileCopyrightText: Copyright 2026 ABOM Advisories contributors
// SPDX-License-Identifier: Apache-2.0

package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// minimalAdvisory is the smallest YAML that satisfies the OSV 1.7.5 schema.
const minimalAdvisory = `schema_version: "1.7.5"
id: ABOM-2026-001
modified: "2026-01-01T00:00:00Z"
`

// --- nodeToJSON / scalarToJSON ---

func TestNodeToJSONPreservesFieldOrder(t *testing.T) {
	// Keys are in reverse-alphabetical order so any alphabetical sorting would
	// produce a different result.
	var node yaml.Node
	if err := yaml.Unmarshal([]byte("z: 1\na: 2\nm: 3\n"), &node); err != nil {
		t.Fatal(err)
	}
	got, err := nodeToJSON(&node)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if strings.Index(s, `"z"`) >= strings.Index(s, `"a"`) ||
		strings.Index(s, `"a"`) >= strings.Index(s, `"m"`) {
		t.Errorf("field order not preserved: %s", s)
	}
}

func TestScalarToJSON(t *testing.T) {
	tests := []struct {
		tag, value, want string
	}{
		{"!!str", "hello", `"hello"`},
		{"!!str", `a "b" c`, `"a \"b\" c"`},
		{"!!bool", "true", "true"},
		{"!!bool", "false", "false"},
		{"!!int", "42", "42"},
		{"!!int", "0xff", "255"},
		{"!!float", "3.14", "3.14"},
		{"!!null", "", "null"},
		{"!!null", "null", "null"},
	}
	for _, tt := range tests {
		t.Run(tt.tag+"/"+tt.value, func(t *testing.T) {
			n := &yaml.Node{Kind: yaml.ScalarNode, Tag: tt.tag, Value: tt.value}
			got, err := scalarToJSON(n)
			if err != nil {
				t.Fatalf("scalarToJSON(%q, %q): %v", tt.tag, tt.value, err)
			}
			if string(got) != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

// --- Compile ---

func TestCompileHappyPath(t *testing.T) {
	inDir, outDir := t.TempDir(), t.TempDir()
	writeFile(t, inDir, "ABOM-2026-001.yaml", minimalAdvisory)

	if err := Compile(inDir, outDir, "advisories.json"); err != nil {
		t.Fatal(err)
	}

	var db struct {
		LastUpdated string            `json:"last_updated"`
		Advisories  []json.RawMessage `json:"advisories"`
	}
	readJSON(t, filepath.Join(outDir, "advisories.json"), &db)

	ts, err := time.Parse(time.RFC3339, db.LastUpdated)
	if err != nil {
		t.Errorf("last_updated %q is not RFC3339: %v", db.LastUpdated, err)
	}
	if time.Since(ts) > time.Minute {
		t.Errorf("last_updated %q is unexpectedly old", db.LastUpdated)
	}

	if len(db.Advisories) != 1 {
		t.Fatalf("got %d advisories, want 1", len(db.Advisories))
	}
	var adv map[string]any
	if err := json.Unmarshal(db.Advisories[0], &adv); err != nil {
		t.Fatal(err)
	}
	if adv["id"] != "ABOM-2026-001" {
		t.Errorf("id = %v, want ABOM-2026-001", adv["id"])
	}
}


func TestCompileReportsAllErrors(t *testing.T) {
	inDir, outDir := t.TempDir(), t.TempDir()
	outFile := filepath.Join(outDir, "out.json")

	// Both are missing the required 'modified' field.
	writeFile(t, inDir, "ABOM-2026-001.yaml", "schema_version: \"1.7.5\"\nid: ABOM-2026-001\n")
	writeFile(t, inDir, "ABOM-2026-002.yaml", "schema_version: \"1.7.5\"\nid: ABOM-2026-002\n")

	err := Compile(inDir, outDir, "out.json")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	for _, name := range []string{"ABOM-2026-001.yaml", "ABOM-2026-002.yaml"} {
		if !strings.Contains(msg, name) {
			t.Errorf("error does not mention %s: %v", name, err)
		}
	}

	if _, statErr := os.Stat(outFile); !os.IsNotExist(statErr) {
		t.Error("output file must not be created when validation fails")
	}
}

func TestCompileIDMismatch(t *testing.T) {
	inDir, outDir := t.TempDir(), t.TempDir()

	// Filename says 001 but the id field says 002.
	writeFile(t, inDir, "ABOM-2026-001.yaml",
		"schema_version: \"1.7.5\"\nid: ABOM-2026-002\nmodified: \"2026-01-01T00:00:00Z\"\n")

	err := Compile(inDir, outDir, "out.json")
	if err == nil {
		t.Fatal("expected error for id/filename mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "ABOM-2026-001.yaml") {
		t.Errorf("error does not mention the offending file: %v", err)
	}
}

func TestCompileMissingInputDir(t *testing.T) {
	err := Compile(filepath.Join(t.TempDir(), "nonexistent"), t.TempDir(), "out.json")
	if err == nil {
		t.Error("expected error for missing input directory, got nil")
	}
}

func TestCompileSkipsNonYAML(t *testing.T) {
	inDir, outDir := t.TempDir(), t.TempDir()
	writeFile(t, inDir, "README.md", "# readme")
	writeFile(t, inDir, "notes.txt", "some notes")
	writeFile(t, inDir, "ABOM-2026-001.yaml", minimalAdvisory)

	if err := Compile(inDir, outDir, "advisories.json"); err != nil {
		t.Fatal(err)
	}

	var db struct {
		Advisories []json.RawMessage `json:"advisories"`
	}
	readJSON(t, filepath.Join(outDir, "advisories.json"), &db)

	if len(db.Advisories) != 1 {
		t.Errorf("got %d advisories, want 1 (non-YAML files must be skipped)", len(db.Advisories))
	}
}

func TestCompilePreservesFieldOrder(t *testing.T) {
	inDir, outDir := t.TempDir(), t.TempDir()

	// 'summary' precedes 'details' in the YAML source.
	// Alphabetically 'details' < 'summary', so a map-based encoder would
	// reverse the order. Verify the YAML source order is preserved.
	writeFile(t, inDir, "ABOM-2026-001.yaml", `schema_version: "1.7.5"
id: ABOM-2026-001
modified: "2026-01-01T00:00:00Z"
summary: short summary
details: longer details
`)
	if err := Compile(inDir, outDir, "advisories.json"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "advisories.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if strings.Index(s, `"summary"`) > strings.Index(s, `"details"`) {
		t.Error(`field order not preserved: "details" appears before "summary"`)
	}
}

// --- helpers ---

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: invalid JSON: %v", path, err)
	}
}
