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
	"golang.org/x/term"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

type FullPager struct {
	lines      []string
	termHeight int
	isTerminal bool
	quiet      bool
	cursorLine int
}

func NewFullPager(quiet bool) *FullPager {
	p := &FullPager{
		quiet:      quiet,
		lines:      make([]string, 0, 100),
		cursorLine: 0,
	}

	if term.IsTerminal(int(os.Stdout.Fd())) {
		p.isTerminal = true
		if h, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			p.termHeight = h - 1
		} else {
			p.termHeight = 24
		}
	} else {
		p.termHeight = math.MaxInt32
	}

	return p
}

func (p *FullPager) Write(data []byte) (n int, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		p.lines = append(p.lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return 0, err
	}

	return len(data), nil
}

func (p *FullPager) Show() error {
	if !p.isTerminal {
		for _, line := range p.lines {
			fmt.Fprintln(os.Stdout, line)
		}
		return nil
	}

	fmt.Fprint(os.Stdout, "\033[?1049h")

	defer fmt.Fprint(os.Stdout, "\033[?1049l")

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		for _, line := range p.lines {
			fmt.Fprintln(os.Stdout, line)
		}
		return err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	reader := bufio.NewReader(os.Stdin)
	p.refreshScreen()

	const scrollUp = '\x01'
	const scrollDown = '\x02'

	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil
		}

		r := rune(b)

		if b == 27 {
			if reader.Buffered() > 1 {
				sequence, err := reader.Peek(2)
				if err == nil && sequence[0] == 91 {
					reader.ReadByte()
					keyByte, _ := reader.ReadByte()

					switch keyByte {
					case 65:
						r = scrollUp
					case 66:
						r = scrollDown
					default:
						continue
					}
				}
			}
		}

		maxScrollLine := len(p.lines) - p.termHeight
		if maxScrollLine < 0 {
			maxScrollLine = 0
		}

		switch r {
		case 'q', 'Q':
			return nil
		case scrollDown, '\n':
			if p.cursorLine < maxScrollLine {
				p.cursorLine++
			}
		case scrollUp:
			if p.cursorLine > 0 {
				p.cursorLine--
			}
		case ' ':
			p.cursorLine += p.termHeight
			if p.cursorLine > maxScrollLine {
				p.cursorLine = maxScrollLine
			}
		case 'b', 'B':
			p.cursorLine -= p.termHeight
			if p.cursorLine < 0 {
				p.cursorLine = 0
			}
		case 'g':
			p.cursorLine = 0
		case 'G':
			p.cursorLine = maxScrollLine
		}

		p.refreshScreen()
	}
}

func (p *FullPager) refreshScreen() {

	fmt.Fprint(os.Stdout, "\033[2J\033[H")

	endLine := p.cursorLine + p.termHeight
	if endLine > len(p.lines) {
		endLine = len(p.lines)
	}

	for _, line := range p.lines[p.cursorLine:endLine] {
		fmt.Fprint(os.Stdout, line+"\r\n")
	}

	linesPrinted := endLine - p.cursorLine
	for i := linesPrinted; i < p.termHeight; i++ {
		fmt.Fprint(os.Stdout, "~\r\n")
	}

	p.showPrompt()
}

func (p *FullPager) showPrompt() {
	if p.quiet {
		return
	}

	fmt.Fprintf(os.Stdout, "\033[%d;1H", p.termHeight+1)

	totalLines := len(p.lines)

	fmt.Fprint(os.Stdout, "\033[K")

	if totalLines == 0 {
		fmt.Fprint(os.Stdout, "(empty file)")
		return
	}

	currentLineIndex := p.cursorLine

	isEnd := (currentLineIndex + p.termHeight) >= totalLines

	if isEnd {
		fmt.Fprintf(os.Stdout, "--- (END) ---")
	} else {
		percent := int(math.Round(float64(currentLineIndex+p.termHeight) / float64(totalLines) * 100))
		if percent > 100 {
			percent = 100
		}

		fmt.Fprintf(os.Stdout, "--- %d/%d (%d%%) --- (Up/Down/Enter: line, space/b: page, g/G: top/bottom, q: quit)",
			currentLineIndex+1, totalLines, percent)
	}

	fmt.Fprintf(os.Stdout, "\033[H")
}

var predefinedPatterns = map[string]string{
	"ip":          `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
	"email":       `[\w\.-]+@[\w\.-]+\.[\w]+`,
	"url":         `https?://\S+`,
	"hash_md5":    `\b[a-fA-F\d]{32}\b`,
	"hash_sha256": `\b[a-fA-F\d]{64}\b`,
}

type Config struct {
	LengthRange    string
	MinLength      int
	MaxLength      int
	RegexStr       string
	FindStr        string
	EntropyMin     float64
	JSONOut        bool
	CountType      string // Replaces CountOut bool. Can be "", "total", "freq"
	QuietOut       bool
	WordList       string
	ExcludeStr     string
	Encoding       string
	DecodeMethods  []string
	InteractiveOut bool

	compiledIncludeRegexes []*regexp.Regexp
	compiledExcludeRegex   *regexp.Regexp
}

type StateTracker struct {
	counts     map[string]int
	totalCount int // Tracks total matches for "total" mode
}

func NewStateTracker(cfg *Config) *StateTracker {
	st := &StateTracker{
		counts:     make(map[string]int),
		totalCount: 0,
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

	if sp.cfg.compiledExcludeRegex != nil {
		if sp.cfg.compiledExcludeRegex.MatchString(foundString) {
			return
		}
	}

	if len(sp.cfg.compiledIncludeRegexes) > 0 {
		for _, r := range sp.cfg.compiledIncludeRegexes {
			if !r.MatchString(foundString) {
				return
			}
		}
	}

	// 1. Handle Count Aggregation Modes
	// If "total" or "freq" is active, we aggregate here and DO NOT print to stream.
	if sp.cfg.CountType == "total" {
		sp.tracker.totalCount++
		return
	}

	if sp.cfg.CountType == "freq" {
		sp.tracker.counts[foundString]++
		return
	}

	// 2. Print Output
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

	isAscii := encoding == "ascii"

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
		if isAscii {

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

			if isAscii {
				currentString.WriteByte(charBuf[0])
			} else {
				currentString.Write(charBuf[:n])
			}
		} else {

			if currentString.Len() > 0 {
				var decodedString string
				if isAscii {
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
	Version: "0.1.1",

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {

		var includePatterns []string

		if cfg.RegexStr != "" {
			includePatterns = append(includePatterns, cfg.RegexStr)
		}
		if cfg.FindStr != "" {
			pattern, exists := predefinedPatterns[cfg.FindStr]
			if !exists {
				return fmt.Errorf("unknown --find pattern: %s", cfg.FindStr)
			}
			includePatterns = append(includePatterns, pattern)
		}
		if cfg.WordList != "" {
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

					wholeWord := "\\b" + regexp.QuoteMeta(word) + "\\b"
					escapedWords = append(escapedWords, wholeWord)
				}
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("error reading wordlist file %s: %w", cfg.WordList, err)
			}

			if len(escapedWords) > 0 {
				pattern := "(" + strings.Join(escapedWords, "|") + ")"
				includePatterns = append(includePatterns, pattern)
			} else {
				fmt.Fprintf(os.Stderr, "Warning: wordlist file %s is empty\n", cfg.WordList)
			}
		}

		for _, pattern := range includePatterns {
			r, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid include regex '%s': %w", pattern, err)
			}
			cfg.compiledIncludeRegexes = append(cfg.compiledIncludeRegexes, r)
		}

		if cfg.ExcludeStr != "" {
			var err error
			cfg.compiledExcludeRegex, err = regexp.Compile(cfg.ExcludeStr)
			if err != nil {
				return fmt.Errorf("invalid exclude regex '%s': %w", cfg.ExcludeStr, err)
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

		var outputWriter io.Writer = os.Stdout
		var pager *FullPager
		var err error

		if cfg.InteractiveOut {
			pager = NewFullPager(cfg.QuietOut)
			outputWriter = pager
		}

		processor := NewStringProcessor(&cfg, tracker, outputWriter)

		if len(files) == 0 {

			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) != 0 {
				return cmd.Help()
			}

			if err = processor.FindStringsInStream(os.Stdin, "<stdin>", cfg.Encoding, 0); err != nil && err != io.EOF {
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
				if err != nil && err != io.EOF {
					if !cfg.QuietOut {
						fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", filename, err)
					}
				}
				file.Close()
			}
		}

		// Post-Processing: Handle Count and Frequency Modes
		if cfg.CountType == "freq" {
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
				fmt.Fprintf(outputWriter, "% 7d %s\n", kv.Value, kv.Key)
			}
		} else if cfg.CountType == "total" {
			fmt.Fprintf(outputWriter, "%d\n", tracker.totalCount)
		}

		if pager != nil {
			pager.Show()
		}

		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfg.LengthRange, "length", "l", "4:", "Specify string length range MIN:MAX or MIN: or :MAX")
	rootCmd.PersistentFlags().Float64Var(&cfg.EntropyMin, "entropy", 0, "Filter strings, only printing those with entropy >= this value")

	rootCmd.PersistentFlags().StringVarP(&cfg.RegexStr, "regex", "r", "", "Filter strings, only printing those that match the regex")
	rootCmd.PersistentFlags().StringVarP(&cfg.ExcludeStr, "exclude", "x", "", "Exclude strings that match this regex")

	var choices []string
	for k := range predefinedPatterns {
		choices = append(choices, k)
	}
	sort.Strings(choices)
	findHelp := fmt.Sprintf("Use a predefined regex pattern. Choices: %v", choices)
	rootCmd.PersistentFlags().StringVarP(&cfg.FindStr, "find", "f", "", findHelp)

	rootCmd.PersistentFlags().StringVarP(&cfg.WordList, "wordlist", "w", "", "Search for multiple words (\"Fuzzing\" style) from a wordlist file")

	rootCmd.PersistentFlags().BoolVar(&cfg.JSONOut, "json", false, "Output as a stream of JSON objects (one per line)")

	// UPDATED: Single flag --count that accepts optional values
	rootCmd.PersistentFlags().StringVarP(&cfg.CountType, "count", "c", "", "Display counts. Options: total, freq")
	// This allows --count to be used without arguments (defaults to "total")
	rootCmd.PersistentFlags().Lookup("count").NoOptDefVal = "total"

	rootCmd.PersistentFlags().BoolVarP(&cfg.QuietOut, "quiet", "q", false, "Suppress all error messages and status output (pipeline friendly)")

	rootCmd.PersistentFlags().StringVarP(&cfg.Encoding, "encoding", "e", "ascii", "Encoding to search for (ascii, utf-16le, utf-16be)")
	rootCmd.PersistentFlags().StringSliceVarP(&cfg.DecodeMethods, "decode", "d", nil, "Try to decode found strings with (base64, hex)")

	rootCmd.PersistentFlags().BoolVarP(&cfg.InteractiveOut, "interactive", "i", false, "Use a full pager (scroll up/down) for output")
}

func main() {
	_ = binary.BigEndian
	_ = transform.ErrShortDst
	_ = unicode.ErrMissingBOM

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}