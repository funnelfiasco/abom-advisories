// SPDX-FileCopyrightText: Copyright 2026 ABOM Advisories contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
)

// Execute is the entry point called from main.
func Execute() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "compile":
		runCompile(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: abom-advisories <command> [flags]

Build an ABOM advisories database from component advisory files.

Commands:
  compile    Compile advisory YAML files into a single JSON database

Flags:
  -h, --help  Show this help message
`)
}
