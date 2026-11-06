// Copyright 2025-2026 David Araújo
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "1.3.0"

// errReported signals a failure whose details were already printed.
var errReported = errors.New("one or more inputs could not be processed")

var cfg Config

func warnf(quiet bool, format string, args ...any) {
	if !quiet {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

var rootCmd = &cobra.Command{
	Use:   "stringx [flags] [FILE...]",
	Short: "Finds printable strings in a file, with advanced filtering and tooling",
	Long: `An enhanced version of the classic 'strings' utility, written in Go.

FILE may be "-" for standard input, or a directory with -R.

Filters of the same kind are alternatives (-f url -f email: either), while
different kinds must all match (-f url -r example: a URL containing "example").

Note: --count and --color take an optional value, so pass it with '='
(--count=freq, --color=never). '--count freq' would treat 'freq' as a file.`,
	Version:       version,
	SilenceUsage:  true,
	SilenceErrors: true,

	PreRunE: func(cmd *cobra.Command, args []string) error {
		return cfg.prepare()
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		return run(cmd, args, &cfg)
	},
}

func run(cmd *cobra.Command, args []string, cfg *Config) error {
	if len(args) == 0 {
		stat, err := os.Stdin.Stat()
		if err == nil && stat.Mode()&os.ModeCharDevice != 0 {
			return cmd.Help()
		}
	}

	var out io.Writer
	var pager *FullPager
	var stdout *bufio.Writer
	if cfg.InteractiveOut {
		pager = NewFullPager(cfg.QuietOut)
		out = pager
	} else {
		stdout = bufio.NewWriterSize(os.Stdout, 64*1024)
		out = stdout
	}

	units := buildUnits(collectInputs(args, cfg, os.Stdin), cfg)
	tracker, failed := runUnits(units, cfg, out, func(in *input, err error) {
		warnf(cfg.QuietOut, "Error: %v\n", err)
		if cfg.CountType != "" && errors.Is(err, os.ErrNotExist) && slices.Contains(validCountTypes, in.name) {
			warnf(cfg.QuietOut, "Hint: use --count=%s (with '=') to select the count type\n", in.name)
		}
	})

	writeCounts(out, cfg, tracker)

	if stdout != nil {
		if err := stdout.Flush(); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if pager != nil {
		pager.Show()
	}

	if failed {
		return errReported
	}
	return nil
}

func writeCounts(out io.Writer, cfg *Config, tracker *StateTracker) {
	switch cfg.CountType {
	case "total":
		if cfg.JSONOut {
			fmt.Fprintf(out, "{\"total\":%d}\n", tracker.totalCount)
		} else {
			fmt.Fprintf(out, "%d\n", tracker.totalCount)
		}

	case "freq":
		type kv struct {
			Key   string
			Value int
		}
		sorted := make([]kv, 0, len(tracker.counts))
		for k, v := range tracker.counts {
			sorted = append(sorted, kv{k, v})
		}
		// Highest count first; ties broken alphabetically for stable output.
		slices.SortFunc(sorted, func(a, b kv) int {
			if a.Value != b.Value {
				return b.Value - a.Value
			}
			return strings.Compare(a.Key, b.Key)
		})

		for _, e := range sorted {
			if cfg.JSONOut {
				b, _ := json.Marshal(struct {
					String string `json:"string"`
					Count  int    `json:"count"`
				}{e.Key, e.Value})
				fmt.Fprintf(out, "%s\n", b)
			} else {
				fmt.Fprintf(out, "% 7d %s\n", e.Value, e.Key)
			}
		}
	}
}

func init() {
	flags := rootCmd.Flags()
	flags.SortFlags = false

	// Selection
	flags.StringVarP(&cfg.LengthRange, "length", "l", "4:", "String length range in characters: MIN:MAX, MIN: or :MAX")
	flags.StringSliceVarP(&cfg.Encodings, "encoding", "e", []string{"ascii"}, "Encodings to search: ascii, utf-8, utf-16le, utf-16be, all (comma-separated)")
	flags.StringVarP(&cfg.Section, "section", "s", "", "Only scan this section of an executable (ELF, PE, Mach-O), e.g. .rodata")
	flags.BoolVarP(&cfg.Recursive, "recursive", "R", false, "Scan directories recursively")

	// Filters
	flags.StringSliceVarP(&cfg.FindStrs, "find", "f", nil, fmt.Sprintf("Predefined patterns, repeatable (any may match): %s", strings.Join(findChoices(), ", ")))
	flags.StringArrayVarP(&cfg.RegexStrs, "regex", "r", nil, "Only print strings matching this regex, repeatable (any may match)")
	flags.StringArrayVarP(&cfg.WordLists, "wordlist", "w", nil, "Only print strings containing a whole word from this file, repeatable")
	flags.StringArrayVarP(&cfg.ExcludeStrs, "exclude", "x", nil, "Drop strings matching this regex, repeatable")
	flags.Float64Var(&cfg.EntropyMin, "entropy", 0, "Only print strings with Shannon entropy >= this value")

	// Decoding
	flags.StringSliceVarP(&cfg.DecodeMethods, "decode", "d", nil, "Decode recursively with: base64, base32, hex, url, gzip, zlib, xor (comma-separated)")

	// Output
	flags.StringVarP(&cfg.Radix, "radix", "t", "", "Print offsets instead of line:column, in x (hex), d (decimal) or o (octal)")
	flags.IntVarP(&cfg.Context, "context", "C", 0, "Show a hexdump of N bytes around each string")
	flags.StringVar(&cfg.Color, "color", "auto", "Highlight output: auto, always, never")
	flags.Lookup("color").NoOptDefVal = "always"
	flags.BoolVar(&cfg.JSONOut, "json", false, "Output as a stream of JSON objects (one per line)")
	flags.StringVarP(&cfg.CountType, "count", "c", "", "Display counts. Options: total (default), freq. Use --count=freq")
	flags.Lookup("count").NoOptDefVal = "total"
	flags.BoolVarP(&cfg.InteractiveOut, "interactive", "i", false, "Use a full pager (scroll up/down) for output")
	flags.BoolVarP(&cfg.QuietOut, "quiet", "q", false, "Print bare strings and suppress error messages (pipeline friendly)")

	flags.IntVarP(&cfg.Jobs, "jobs", "j", runtime.NumCPU(), "Number of scans to run in parallel")

	// --sector was the original name of --section; keep accepting it.
	flags.SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if name == "sector" {
			name = "section"
		}
		return pflag.NormalizedName(name)
	})
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		if !errors.Is(err, errReported) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}
