package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

var predefinedPatterns = map[string]string{
	"ip":          `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
	"email":       `[\w\.-]+@[\w\.-]+\.[\w]+`,
	"url":         `https?://[^\s/$.?#].[^\s]*`,
	"hash_md5":    `\b[a-fA-F\d]{32}\b`,
	"hash_sha256": `\b[a-fA-F\d]{64}\b`,
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
	QuietOut      bool
	compiledRegex *regexp.Regexp

	Encoding      string
	DecodeMethods []string
	WordList      string
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

func isPrintable(r rune) bool {
	return (32 <= r && r <= 126) || r == 9
}

func (sp *StringProcessor) processString(
	foundString string,
	startOffset int64,
	startLine int,
	startCol int,
	filename string,
	currentDepth int,
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
	}

	if sp.cfg.UniqueOut {
		if _, exists := sp.tracker.uniques[foundString]; exists {
			if nil == sp.cfg.DecodeMethods || len(sp.cfg.DecodeMethods) == 0 {
				return
			}
		} else {
			sp.tracker.uniques[foundString] = struct{}{}
		}
	}

	if !sp.cfg.CountOut {
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
			if currentDepth > 0 {
				data["recursive_depth"] = currentDepth
			}

			jsonBytes, err := json.Marshal(data)
			if err != nil {
				if !sp.cfg.QuietOut {
					fmt.Fprintf(os.Stderr, "Error marshalling JSON: %v\n", err)
				}
				return
			}
			fmt.Fprintln(sp.writer, string(jsonBytes))

		} else {
			if !sp.cfg.QuietOut {
				indent := strings.Repeat("  ", currentDepth)
				fmt.Fprintf(sp.writer, "%s%s:%d:%d:%s\n", indent, filename, startLine, startCol, foundString)
			} else {
				fmt.Fprintf(sp.writer, "%s\n", foundString)
			}
		}
	}

	if nil == sp.cfg.DecodeMethods || len(sp.cfg.DecodeMethods) == 0 || currentDepth >= 10 {
		return
	}

	for _, method := range sp.cfg.DecodeMethods {
		var decodedBytes []byte
		var err error

		switch method {
		case "base64":
			s := strings.Map(func(r rune) rune {
				if strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", r) {
					return r
				}
				return -1
			}, foundString)
			if len(s)%4 != 0 {
				s += strings.Repeat("=", 4-len(s)%4)
			}
			decodedBytes, err = base64.StdEncoding.DecodeString(s)
			if err != nil {
				decodedBytes, err = base64.StdEncoding.DecodeString(foundString)
			}
		case "hex":
			s := strings.Map(func(r rune) rune {
				if strings.ContainsRune("0123456789abcdefABCDEF", r) {
					return r
				}
				return -1
			}, foundString)
			decodedBytes, err = hex.DecodeString(s)
		}

		if err == nil && len(decodedBytes) > 0 {
			newFilename := fmt.Sprintf("%s->%s@%d", filename, method, startOffset)
			memStream := bytes.NewReader(decodedBytes)

			sp.FindStringsInStream(memStream, newFilename, "ascii", currentDepth+1)
		}
	}
}

func (sp *StringProcessor) FindStringsInStream(stream io.Reader, filename string, encoding string, currentDepth int) error {
	reader := bufio.NewReader(stream)

	var currentString bytes.Buffer
	var fileOffset int64 = 0
	var stringStartOffset int64 = -1
	var currentLine int = 1
	var currentCol int = 1
	var stringStartLine int = -1
	var stringStartCol int = -1

	var charSize int
	var endianness binary.ByteOrder
	var decoder transform.Transformer

	switch encoding {
	case "utf-16le":
		charSize = 2
		endianness = binary.LittleEndian
		decoder = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	case "utf-16be":
		charSize = 2
		endianness = binary.BigEndian
		decoder = unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewDecoder()
	case "ascii":
		charSize = 1
	default:
		return fmt.Errorf("unsupported encoding: %s", encoding)
	}

	charBuf := make([]byte, charSize)

	for {
		n, err := io.ReadFull(reader, charBuf)
		isEOF := (err == io.EOF || err == io.ErrUnexpectedEOF)
		if err != nil && !isEOF {
			return fmt.Errorf("error reading %s: %w", filename, err)
		}
		if n == 0 && isEOF {
			break
		}

		var r rune
		if encoding == "ascii" {
			r = rune(charBuf[0])
		} else if n == 2 {
			if endianness == binary.LittleEndian {
				r = rune(binary.LittleEndian.Uint16(charBuf))
			} else {
				r = rune(binary.BigEndian.Uint16(charBuf))
			}
		} else {
			r = 0
		}

		currentFileOffset := fileOffset

		if !isEOF && isPrintable(r) {
			if stringStartOffset == -1 {
				stringStartOffset = currentFileOffset
				stringStartLine = currentLine
				stringStartCol = currentCol
			}
			currentString.Write(charBuf[:n])
		} else {
			if currentString.Len() > 0 {
				var decodedString string
				if encoding == "ascii" {
					decodedString = currentString.String()
				} else {
					utf8Bytes, _, err := transform.Bytes(decoder, currentString.Bytes())
					if err != nil {
						if !sp.cfg.QuietOut {
							fmt.Fprintf(os.Stderr, "Warning: could not decode string at %d: %v\n", stringStartOffset, err)
						}
						decodedString = ""
					} else {
						decodedString = string(utf8Bytes)
					}
				}

				strLen := len(decodedString)
				if decodedString != "" &&
					sp.cfg.MaxLength >= strLen &&
					strLen >= sp.cfg.MinLength {

					sp.processString(
						decodedString,
						stringStartOffset,
						stringStartLine,
						stringStartCol,
						filename,
						currentDepth,
					)
				}
			}

			currentString.Reset()
			stringStartOffset = -1
			stringStartLine = -1
			stringStartCol = -1
		}

		if isEOF {
			break
		}

		if r == '\n' {
			currentLine++
			currentCol = 1
		} else {
			currentCol++
		}
		fileOffset += int64(n)
	}
	return nil
}

var (
	cfg     Config
	tracker *StateTracker
)

var rootCmd = &cobra.Command{
	Use:     "stringx [flags] [FILE...]",
	Short:   "Finds printable strings in a file, with advanced filtering and tooling",
	Long:    `An enhanced version of the classic 'strings' utility, written in Go.`,
	Version: "0.2.0",

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {

		exclusiveFlags := 0
		if cfg.RegexStr != "" {
			exclusiveFlags++
		}
		if cfg.FindStr != "" {
			exclusiveFlags++
		}
		if cfg.WordList != "" {
			exclusiveFlags++
		}
		if exclusiveFlags > 1 {
			return fmt.Errorf("flags --regex, --find, and --wordlist are mutually exclusive")
		}

		pattern := cfg.RegexStr
		if cfg.FindStr != "" {
			var exists bool
			pattern, exists = predefinedPatterns[cfg.FindStr]
			if !exists {
				return fmt.Errorf("unknown --find pattern: %s", cfg.FindStr)
			}
		} else if cfg.WordList != "" {
			file, err := os.Open(cfg.WordList)
			if err != nil {
				return fmt.Errorf("could not open wordlist file %s: %w", cfg.WordList, err)
			}
			defer file.Close()

			var escapedWords []string
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				word := strings.TrimSpace(scanner.Text())
				if word != "" {
					escapedWords = append(escapedWords, regexp.QuoteMeta(word))
				}
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("error reading wordlist file %s: %w", cfg.WordList, err)
			}

			if len(escapedWords) == 0 {
				fmt.Fprintf(os.Stderr, "Warning: wordlist file %s is empty\n", cfg.WordList)
				pattern = ""
			} else {
				pattern = "(" + strings.Join(escapedWords, "|") + ")"
			}
		}

		if pattern != "" {
			var err error
			cfg.compiledRegex, err = regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid regex '%s': %w", pattern, err)
			}
		}

		parts := strings.Split(cfg.LengthRange, ":")
		if len(parts) > 0 {
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

		tracker = NewStateTracker(&cfg)
		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		files := args
		processor := NewStringProcessor(&cfg, tracker, os.Stdout)

		if len(files) == 0 {
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) != 0 {
				return cmd.Help()
			}

			if err := processor.FindStringsInStream(os.Stdin, "<stdin>", cfg.Encoding, 0); err != nil {
				if !cfg.QuietOut {
					fmt.Fprintf(os.Stderr, "Error processing stdin: %v\n", err)
				}
			}
		} else {
			for _, filename := range files {
				file, err := os.Open(filename)
				if err != nil {
					if !cfg.QuietOut {
						fmt.Fprintf(os.Stderr, "Error: File not found: %s\n", filename)
					}
					continue
				}

				err = processor.FindStringsInStream(file, filename, cfg.Encoding, 0)
				if err != nil {
					if !cfg.QuietOut {
						fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", filename, err)
					}
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
	rootCmd.PersistentFlags().StringVarP(&cfg.LengthRange, "length", "l", "4:", "Specify string length range MIN:MAX or MIN: or :MAX")
	rootCmd.PersistentFlags().Float64Var(&cfg.EntropyMin, "entropy", 0, "Filter strings, only printing those with entropy >= this value")

	rootCmd.PersistentFlags().StringVarP(&cfg.RegexStr, "regex", "r", "", "Filter strings, only printing those that match the regex")

	var choices []string
	for k := range predefinedPatterns {
		choices = append(choices, k)
	}
	sort.Strings(choices)
	findHelp := fmt.Sprintf("Use a predefined regex pattern. Choices: %v", choices)
	rootCmd.PersistentFlags().StringVarP(&cfg.FindStr, "find", "f", "", findHelp)

	rootCmd.PersistentFlags().StringVarP(&cfg.WordList, "wordlist", "w", "", "Search for multiple words (\"Fuzzing\" style) from a wordlist file")

	rootCmd.PersistentFlags().BoolVar(&cfg.JSONOut, "json", false, "Output as a stream of JSON objects (one per line)")
	rootCmd.PersistentFlags().BoolVar(&cfg.UniqueOut, "unique", false, "Only print the first occurrence of each unique string")
	rootCmd.PersistentFlags().BoolVar(&cfg.CountOut, "count", false, "Count occurrences of each string and print a summary at the end")

	rootCmd.PersistentFlags().BoolVarP(&cfg.QuietOut, "quiet", "q", false, "Suppress all error messages and status output (pipeline friendly)")

	rootCmd.MarkFlagsMutuallyExclusive("json", "unique", "count")
	rootCmd.MarkFlagsMutuallyExclusive("regex", "find", "wordlist")

	rootCmd.PersistentFlags().StringVarP(&cfg.Encoding, "encoding", "e", "ascii", "Encoding to search for (ascii, utf-16le, utf-16be)")
	rootCmd.PersistentFlags().StringSliceVarP(&cfg.DecodeMethods, "decode", "d", nil, "Try to decode found strings with (base64, hex)")
}

func main() {
	_ = binary.BigEndian
	_ = transform.ErrShortDst
	_ = unicode.ErrMissingBOM

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
