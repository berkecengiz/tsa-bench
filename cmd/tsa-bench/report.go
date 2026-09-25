package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/report"
)

// partitionArgs separates flag arguments from positional ones. valueFlags
// names the flags that take a separate value argument.
func partitionArgs(args []string, valueFlags map[string]bool) (flags, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			return flags, positional
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)

		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			continue // --flag=value carries its own value
		}
		if valueFlags[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return flags, positional
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	outDir := fs.String("output", "", "directory for the comparison files (default: the first result directory's parent)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "tsa-bench report [flags] <result-dir> [result-dir...]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Builds comparison.json, comparison.csv and comparison.html from one or")
		fmt.Fprintln(os.Stderr, "more run directories. Sends no network traffic.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	// Go's flag package stops at the first non-flag argument, so
	// "report <dir> --output x" would silently treat --output as a directory.
	// Partition first, so flags work on either side of the paths.
	flags, dirs := partitionArgs(args, map[string]bool{"output": true})
	if err := fs.Parse(flags); err != nil {
		return err
	}
	dirs = append(dirs, fs.Args()...)
	if len(dirs) == 0 {
		return fail(2, "at least one result directory is required")
	}

	summaries := make([]*report.Summary, 0, len(dirs))
	for _, d := range dirs {
		s, err := report.LoadSummary(d)
		if err != nil {
			return fail(1, "%v", err)
		}
		summaries = append(summaries, s)
	}

	target := *outDir
	if target == "" {
		target = filepath.Dir(filepath.Clean(dirs[0]))
	}
	if err := os.MkdirAll(target, 0o700); err != nil {
		return fail(1, "create output directory: %v", err)
	}

	cmp := report.BuildComparison(dirs, summaries, time.Now())

	jsonPath := filepath.Join(target, "comparison.json")
	csvPath := filepath.Join(target, "comparison.csv")
	htmlPath := filepath.Join(target, "comparison.html")

	if err := report.WriteJSONFile(jsonPath, cmp); err != nil {
		return fail(1, "write comparison.json: %v", err)
	}
	if err := report.WriteComparisonCSV(csvPath, cmp); err != nil {
		return fail(1, "write comparison.csv: %v", err)
	}
	if err := report.WriteComparisonHTML(htmlPath, cmp); err != nil {
		return fail(1, "write comparison.html: %v", err)
	}

	fmt.Printf("compared %d run(s):\n", len(cmp.Entries))
	for _, e := range cmp.Entries {
		note := ""
		if e.ClientBottleneck {
			note = "  [client bottleneck: lower bound only]"
		}
		if e.Partial {
			note += "  [partial run: " + e.StopReason + "]"
		}
		fmt.Printf("  %-20s %8.2f TPS  success %7.3f%%  p95 %8.2f ms  p99 %8.2f ms%s\n",
			e.Provider, e.AchievedTPS, e.SuccessRate*100, e.P95MS, e.P99MS, note)
	}
	fmt.Printf("\nwritten:\n  %s\n  %s\n  %s\n", jsonPath, csvPath, htmlPath)
	return nil
}
