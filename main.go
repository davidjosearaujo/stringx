package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var predefinedPatterns = map[string]string{
	"ip":          `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
	"email":       `[\w\.-]+@[\w\.-]+\.[\w]+`,
	"url":         `https?://[^\s/$.?#].[^\s]*`,
	"hash_md5":    `\b[a-fA-F\d]{32}\b`,
	"hash_sha256": `\b[a-fA-F\d]{64}\b`,
	"base64":      `^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`,
}

type Config struct {
	LengthRange   string
	MinLength     int
	MaxLength     int
	RegexStr      string
	FindStr       string
	EntropyMin    float64
	JSONOut       bool
	UniqueOut     bool
	CountOut      bool
	compiledRegex *regexp.Regexp
}

type StateTracker struct {
	counts  map[string]int
	uniques map[string]struct{}
}

func NewStateTracker(cfg *Config) *StateTracker {
	st := &StateTracker{}
	if cfg.CountOut {
		st.counts = make(map[string]int)
	}
	if cfg.UniqueOut {
		st.uniques = make(map[string]struct{})
	}
	return st
}

type StringProcessor struct {
	cfg     *Config
	tracker *StateTracker
	writer  io.Writer
}

func NewStringProcessor(cfg *Config, tracker *StateTracker, writer io.Writer) *StringProcessor {
	return &StringProcessor{
		cfg:     cfg,
		tracker: tracker,
		writer:  writer,
	}
}

func getEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isPrintable(b byte) bool {
	return (32 <= b && b <= 126) || b == 9
}

func (sp *StringProcessor) processString(
	foundString string,
	startOffset int64,
	startLine int,
	startCol int,
	filename string,
) {
	var entropy float64
	if sp.cfg.EntropyMin > 0 || sp.cfg.JSONOut {
		entropy = getEntropy(foundString)
		if sp.cfg.EntropyMin > 0 && entropy < sp.cfg.EntropyMin {
			return
		}
	}

	if sp.cfg.compiledRegex != nil {
		if !sp.cfg.compiledRegex.MatchString(foundString) {
			return
		}
	}

	if sp.cfg.CountOut {
		sp.tracker.counts[foundString]++
		return
	}

	if sp.cfg.UniqueOut {
		if _, exists := sp.tracker.uniques[foundString]; exists {
			return
		}
		sp.tracker.uniques[foundString] = struct{}{}
	}

	if sp.cfg.JSONOut {
		data := map[string]interface{}{
			"file":    filename,
			"string":  foundString,
			"length":  len(foundString),
			"entropy": math.Round(entropy*10000) / 10000,
			"offset":  startOffset,
			"line":    startLine,
			"column":  startCol,
		}

		jsonBytes, err := json.Marshal(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling JSON: %v\n", err)
			return
		}
		fmt.Fprintln(sp.writer, string(jsonBytes))

	} else {
		fmt.Fprintf(sp.writer, "%s:%d:%d:%s\n", filename, startLine, startCol, foundString)
	}
}

func (sp *StringProcessor) FindStringsInStream(stream io.Reader, filename string) error {
	reader := bufio.NewReader(stream)

	var currentString bytes.Buffer
	var fileOffset int64 = 0
	var stringStartOffset int64 = -1
	var currentLine int = 1
	var currentCol int = 1
	var stringStartLine int = -1
	var stringStartCol int = -1

	for {
		b, err := reader.ReadByte()

		isEOF := (err == io.EOF)
		if err != nil && !isEOF {
			return fmt.Errorf("error reading %s: %w", filename, err)
		}

		currentFileOffset := fileOffset

		if !isEOF && isPrintable(b) {
			if stringStartOffset == -1 {
				stringStartOffset = currentFileOffset
				stringStartLine = currentLine
				stringStartCol = currentCol
			}
			currentString.WriteByte(b)
		} else {
			if sp.cfg.MaxLength >= currentString.Len() && currentString.Len() >= sp.cfg.MinLength {
				sp.processString(
					currentString.String(),
					stringStartOffset,
					stringStartLine,
					stringStartCol,
					filename,
				)
			}

			currentString.Reset()
			stringStartOffset = -1
			stringStartLine = -1
			stringStartCol = -1
		}

		if isEOF {
			break
		}

		if b == '\n' {
			currentLine++
			currentCol = 1
		} else {
			currentCol++
		}
		fileOffset++
	}
	return nil
}

var (
	cfg     Config
	tracker *StateTracker
)

var rootCmd = &cobra.Command{
	Use:     "stringx [flags] [FILE...]",
	Short:   "Finds printable strings in a file, with advanced filtering.",
	Long:    `An enhanced version of the classic 'strings' utility, written in Go.`,
	Version: "1.0.0",

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {

		if cfg.RegexStr != "" && cfg.FindStr != "" {
			return fmt.Errorf("flags --regex and --find are mutually exclusive")
		}

		pattern := cfg.RegexStr
		if cfg.FindStr != "" {
			var exists bool
			pattern, exists = predefinedPatterns[cfg.FindStr]
			if !exists {
				return fmt.Errorf("unknown --find pattern: %s", cfg.FindStr)
			}
		}

		if pattern != "" {
			var err error
			cfg.compiledRegex, err = regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid regex '%s': %w", pattern, err)
			}
		}

		tracker = NewStateTracker(&cfg)

		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		files := args
		processor := NewStringProcessor(&cfg, tracker, os.Stdout)
		parts := strings.Split(cfg.LengthRange, ":")
		if len(parts) > 0 {
			fmt.Println(parts)
			if parts[0] == "" {
				cfg.MinLength = 0
			} else {
				fmt.Sscanf(parts[0], "%d", &cfg.MinLength)
			}
			if len(parts) < 2 || parts[1] == "" {
				cfg.MaxLength = math.MaxInt32
			} else {
				fmt.Sscanf(parts[1], "%d", &cfg.MaxLength)
			}
		}

		if len(files) == 0 {
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) != 0 {
				return cmd.Help()
			}

			if err := processor.FindStringsInStream(os.Stdin, "<stdin>"); err != nil {
				fmt.Fprintf(os.Stderr, "Error processing stdin: %v\n", err)
			}
		} else {
			for _, filename := range files {
				file, err := os.Open(filename)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: File not found: %s\n", filename)
					continue
				}

				err = processor.FindStringsInStream(file, filename)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", filename, err)
				}
				file.Close()
			}
		}

		if cfg.CountOut {
			type kv struct {
				Key   string
				Value int
			}
			var sortedCounts []kv
			for k, v := range tracker.counts {
				sortedCounts = append(sortedCounts, kv{k, v})
			}

			sort.Slice(sortedCounts, func(i, j int) bool {
				return sortedCounts[i].Value > sortedCounts[j].Value
			})

			for _, kv := range sortedCounts {
				fmt.Fprintf(os.Stdout, "% 7d %s\n", kv.Value, kv.Key)
			}
		}
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfg.LengthRange, "length", "l", "8", "Specify string length range MIN:MAX or MIN: or :MAX (default: 8, no maximum)")
	rootCmd.PersistentFlags().Float64Var(&cfg.EntropyMin, "entropy-min", 3, "Filter strings, only printing those with entropy >= this value (default: 3)")

	rootCmd.PersistentFlags().StringVarP(&cfg.RegexStr, "regex", "r", "", "Filter strings, only printing those that match the regex")

	var choices []string
	for k := range predefinedPatterns {
		choices = append(choices, k)
	}
	sort.Strings(choices)
	findHelp := fmt.Sprintf("Use a predefined regex pattern. Choices: %v", choices)
	rootCmd.PersistentFlags().StringVarP(&cfg.FindStr, "find", "f", "", findHelp)

	rootCmd.PersistentFlags().BoolVar(&cfg.JSONOut, "json", false, "Output as a stream of JSON objects (one per line)")
	rootCmd.PersistentFlags().BoolVar(&cfg.UniqueOut, "unique", false, "Only print the first occurrence of each unique string")
	rootCmd.PersistentFlags().BoolVar(&cfg.CountOut, "count", false, "Count occurrences of each string and print a summary at the end")

	rootCmd.MarkFlagsMutuallyExclusive("json", "unique", "count")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
