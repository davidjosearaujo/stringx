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
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "1.2.0"

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

Note: --count takes an optional value, so pass it with '=' (--count=freq, -c=freq)
or attached (-cfreq). '--count freq' would treat 'freq' as a file name.`,
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

func run(cmd *cobra.Command, files []string, cfg *Config) error {
	if len(files) == 0 {
		stat, err := os.Stdin.Stat()
		if err == nil && stat.Mode()&os.ModeCharDevice != 0 {
			return cmd.Help()
		}
		if cfg.Section != "" {
			return errors.New("--section needs a file argument (sections can't be located in piped input)")
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

	tracker := NewStateTracker()
	processor := NewStringProcessor(cfg, tracker, out)
	failed := false

	if len(files) == 0 {
		if err := processor.FindStringsInStream(os.Stdin, "<stdin>", cfg.Encoding, 0, 0); err != nil {
			warnf(cfg.QuietOut, "Error processing stdin: %v\n", err)
			failed = true
		}
	}
	for _, filename := range files {
		if err := scanFile(processor, cfg, filename); err != nil {
			warnf(cfg.QuietOut, "Error: %v\n", err)
			if cfg.CountType != "" && errors.Is(err, os.ErrNotExist) && slices.Contains(validCountTypes, filename) {
				warnf(cfg.QuietOut, "Hint: use --count=%s (with '=') to select the count type\n", filename)
			}
			failed = true
		}
	}

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

func scanFile(processor *StringProcessor, cfg *Config, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var stream io.Reader = file
	var baseOffset int64
	if cfg.Section != "" {
		stream, baseOffset, err = openSection(file, cfg.Section)
		if err != nil {
			return fmt.Errorf("%s: section %q: %w", filename, cfg.Section, err)
		}
	}

	return processor.FindStringsInStream(stream, filename, cfg.Encoding, 0, baseOffset)
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

	flags.StringVarP(&cfg.LengthRange, "length", "l", "4:", "Specify string length range MIN:MAX or MIN: or :MAX")
	flags.Float64Var(&cfg.EntropyMin, "entropy", 0, "Filter strings, only printing those with entropy >= this value")

	flags.StringVarP(&cfg.RegexStr, "regex", "r", "", "Filter strings, only printing those that match the regex")
	flags.StringVarP(&cfg.ExcludeStr, "exclude", "x", "", "Exclude strings that match this regex")

	flags.StringVarP(&cfg.FindStr, "find", "f", "", fmt.Sprintf("Use a predefined regex pattern. Choices: %v", findChoices()))

	flags.StringVarP(&cfg.WordList, "wordlist", "w", "", "Search for multiple words (\"Fuzzing\" style) from a wordlist file")

	flags.BoolVar(&cfg.JSONOut, "json", false, "Output as a stream of JSON objects (one per line)")

	flags.StringVarP(&cfg.CountType, "count", "c", "", "Display counts. Options: total (default), freq. Use --count=freq")
	flags.Lookup("count").NoOptDefVal = "total"

	flags.BoolVarP(&cfg.QuietOut, "quiet", "q", false, "Suppress all error messages and status output (pipeline friendly)")

	flags.StringVarP(&cfg.Encoding, "encoding", "e", "ascii", "Encoding to search for (ascii, utf-16le, utf-16be)")
	flags.StringSliceVarP(&cfg.DecodeMethods, "decode", "d", nil, "Try to recursively decode found strings with (base64, hex)")

	flags.BoolVarP(&cfg.InteractiveOut, "interactive", "i", false, "Use a full pager (scroll up/down) for output")

	flags.StringVarP(&cfg.Section, "section", "s", "", "Only scan this section of an executable (ELF, PE, Mach-O), e.g. .rodata")

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
