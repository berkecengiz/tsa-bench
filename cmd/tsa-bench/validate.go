package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/berkecengiz/tsa-bench/internal/config"
	"github.com/berkecengiz/tsa-bench/internal/load"
)

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to the configuration file (required)")
	profilePath := fs.String("profile", "", "optional load profile to validate against the configured limits")
	quiet := fs.Bool("quiet", false, "print nothing on success")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "tsa-bench validate — check a configuration file without sending any network traffic.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fail(2, "--config is required")
	}

	cfg, err := config.LoadFile(*cfgPath)
	if err != nil {
		return fail(1, "%v", err)
	}

	// Resolving credentials proves the referenced environment variables are
	// actually readable. The values themselves are discarded immediately and
	// are never printed.
	if _, err := cfg.ResolveCredentials(); err != nil {
		return fail(1, "credentials: %v", err)
	}

	if *profilePath != "" {
		profile, err := load.LoadProfile(*profilePath)
		if err != nil {
			return fail(1, "%v", err)
		}
		maxReq := int64(cfg.Limits.MaxRequests)
		if maxReq == 0 {
			maxReq = int64(cfg.Limits.HardCap)
		}
		if err := profile.CheckAgainstQuota(maxReq, int64(cfg.Limits.HardCap)); err != nil {
			return fail(1, "%v", err)
		}
		if !*quiet {
			fmt.Printf("profile %s: %d stages, %d planned requests, %d reserved\n",
				profile.Name, len(profile.Stages), profile.TotalPlanned(), profile.Reserve)
			for _, s := range profile.Stages {
				if s.Mode == load.ModeSequential {
					fmt.Printf("  %-16s sequential  %6d requests\n", s.Name, s.Count)
				} else {
					fmt.Printf("  %-16s %6.0f TPS x %-6s %6d requests\n",
						s.Name, s.TPS, s.Duration, s.Planned())
				}
			}
		}
	}

	warnings := cfg.Warnings()
	if !*quiet {
		fmt.Println("configuration is valid (no network traffic was sent)")
		fmt.Println()
		fmt.Print(cfg.String())
	}
	if len(warnings) > 0 {
		fmt.Fprintln(os.Stderr)
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "WARNING [%s]: %s\n", w.Field, w.Message)
		}
	}
	return nil
}
