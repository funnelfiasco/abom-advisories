// SPDX-FileCopyrightText: Copyright 2026 ABOM Advisories contributors
// SPDX-License-Identifier: Apache-2.0

package compiler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "embed"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

//go:embed osv_schema.json
var osvSchemaJSON []byte

// schemaID must match the $id in osv_schema.json so the compiler can resolve
// internal $ref pointers correctly.
const schemaID = "https://raw.githubusercontent.com/ossf/osv-schema/main/validation/schema.json"

type database struct {
	LastUpdated string            `json:"last_updated"`
	Advisories  []json.RawMessage `json:"advisories"`
}

// Compile reads all YAML advisory files from inputDir, validates each against
// the embedded OSV 1.7.5 schema, and writes a compiled JSON database to
// filepath.Join(outputDir, outputFile).
//
// All files are validated before writing; if any fail, Compile returns an
// error listing every failure without producing output.
func Compile(inputDir, outputDir, outputFile string) error {
	schema, err := loadSchema()
	if err != nil {
		return fmt.Errorf("loading OSV schema: %w", err)
	}

	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return fmt.Errorf("reading input directory %q: %w", inputDir, err)
	}

	// Sort newest-first by (year desc, index desc), comparing numerically so
	// that e.g. ABOM-2026-1869 comes before ABOM-2026-812.
	sort.Slice(entries, func(i, j int) bool {
		yi, ni := parseAdvisoryID(entries[i].Name())
		yj, nj := parseAdvisoryID(entries[j].Name())
		if yi != yj {
			return yi > yj
		}
		return ni > nj
	})

	var advisories []json.RawMessage
	var validationErrs []string

	for _, entry := range entries {
		if entry.IsDir() || !isYAMLFile(entry.Name()) {
			continue
		}
		path := filepath.Join(inputDir, entry.Name())
		advisory, err := readAndValidate(path, schema)
		if err != nil {
			validationErrs = append(validationErrs, fmt.Sprintf("%s: %s", entry.Name(), err))
			continue
		}
		advisories = append(advisories, advisory)
	}

	if len(validationErrs) > 0 {
		return fmt.Errorf("validation failed:\n  %s", strings.Join(validationErrs, "\n  "))
	}

	if err := os.MkdirAll(outputDir, fs.ModePerm); err != nil {
		return fmt.Errorf("creating output directory %q: %w", outputDir, err)
	}

	db := database{
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Advisories:  advisories,
	}

	outPath := filepath.Join(outputDir, outputFile)
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating output file %q: %w", outPath, err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	encErr := enc.Encode(db)
	closeErr := f.Close()
	if encErr != nil {
		return fmt.Errorf("writing output: %w", encErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing output file: %w", closeErr)
	}
	return nil
}

func loadSchema() (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaID, bytes.NewReader(osvSchemaJSON)); err != nil {
		return nil, err
	}
	return c.Compile(schemaID)
}

// readAndValidate parses a YAML file into a yaml.Node (preserving field
// order), converts it to JSON, validates against the OSV schema, and returns
// the raw JSON bytes.
func readAndValidate(path string, schema *jsonschema.Schema) (json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Convert the YAML node tree to JSON, preserving field order.
	jsonBytes, err := nodeToJSON(&node)
	if err != nil {
		return nil, fmt.Errorf("converting to JSON: %w", err)
	}

	// Unmarshal to any for schema validation (order doesn't matter here).
	var v any
	if err := json.Unmarshal(jsonBytes, &v); err != nil {
		return nil, fmt.Errorf("unmarshalling JSON: %w", err)
	}

	if err := schema.Validate(v); err != nil {
		return nil, err
	}

	if _, ok := v.(map[string]any); !ok {
		return nil, fmt.Errorf("expected JSON object, got %T", v)
	}
	return jsonBytes, nil
}

// nodeToJSON converts a yaml.Node tree to JSON, preserving mapping field order.
func nodeToJSON(n *yaml.Node) (json.RawMessage, error) {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return json.RawMessage("null"), nil
		}
		return nodeToJSON(n.Content[0])

	case yaml.MappingNode:
		var buf bytes.Buffer
		buf.WriteByte('{')
		for i := 0; i < len(n.Content); i += 2 {
			if i > 0 {
				buf.WriteByte(',')
			}
			key, err := json.Marshal(n.Content[i].Value)
			if err != nil {
				return nil, fmt.Errorf("encoding key: %w", err)
			}
			buf.Write(key)
			buf.WriteByte(':')
			val, err := nodeToJSON(n.Content[i+1])
			if err != nil {
				return nil, fmt.Errorf("encoding value for key %q: %w", n.Content[i].Value, err)
			}
			buf.Write(val)
		}
		buf.WriteByte('}')
		return buf.Bytes(), nil

	case yaml.SequenceNode:
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, child := range n.Content {
			if i > 0 {
				buf.WriteByte(',')
			}
			v, err := nodeToJSON(child)
			if err != nil {
				return nil, err
			}
			buf.Write(v)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil

	case yaml.ScalarNode:
		return scalarToJSON(n)

	case yaml.AliasNode:
		return nodeToJSON(n.Alias)

	default:
		return nil, fmt.Errorf("unknown YAML node kind %v", n.Kind)
	}
}

// scalarToJSON converts a YAML scalar node to its JSON representation.
func scalarToJSON(n *yaml.Node) (json.RawMessage, error) {
	switch n.Tag {
	case "!!null":
		return json.RawMessage("null"), nil
	case "!!bool":
		if n.Value == "true" {
			return json.RawMessage("true"), nil
		}
		return json.RawMessage("false"), nil
	case "!!int":
		i, err := strconv.ParseInt(n.Value, 0, 64)
		if err != nil {
			u, err2 := strconv.ParseUint(n.Value, 0, 64)
			if err2 != nil {
				return nil, fmt.Errorf("invalid integer %q: %w", n.Value, err)
			}
			return json.Marshal(u)
		}
		return json.Marshal(i)
	case "!!float":
		f, err := strconv.ParseFloat(n.Value, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid float %q: %w", n.Value, err)
		}
		return json.Marshal(f)
	default:
		// !!str, !!timestamp, and anything else treated as a JSON string.
		return json.Marshal(n.Value)
	}
}

// parseAdvisoryID extracts the year and numeric index from a filename of the
// form PREFIX-YYYY-N[.ext]. Returns (0, 0) for names that do not match.
func parseAdvisoryID(name string) (year, index int) {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	parts := strings.SplitN(base, "-", 3)
	if len(parts) != 3 {
		return 0, 0
	}
	y, err1 := strconv.Atoi(parts[1])
	n, err2 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil {
		return 0, 0
	}
	return y, n
}

func isYAMLFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}
