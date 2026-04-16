// SPDX-FileCopyrightText: Copyright 2026 ABOM Advisories contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/julietsecurity/abom-advisories/pkg/compiler"
)

func runCompile(args []string) {
	fs := flag.NewFlagSet("compile", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: abom-advisories compile [flags]

Reads YAML advisory files from the input directory, validates each against
the OSV 1.7.5 schema, and writes the compiled database to a single JSON file.

Flags:
`)
		fs.PrintDefaults()
	}

	inputDir := fs.String("input-directory", "advisories", "Directory containing input files")
	outputDir := fs.String("output-directory", "db", "Output directory name")
	outFile := fs.String("output-file", "advisories.json", "Output file name")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}

	if err := compiler.Compile(*inputDir, *outputDir, *outFile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s/%s\n", *outputDir, *outFile)
}
