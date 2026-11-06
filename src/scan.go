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
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
)

// maxDecodeDepth bounds how many times decoded content is decoded again.
const maxDecodeDepth = 10

type StateTracker struct {
	counts     map[string]int
	totalCount int
}

func NewStateTracker() *StateTracker {
	return &StateTracker{counts: make(map[string]int)}
}

type StringProcessor struct {
	cfg     *Config
	tracker *StateTracker
	writer  io.Writer
}

func NewStringProcessor(cfg *Config, tracker *StateTracker, writer io.Writer) *StringProcessor {
	return &StringProcessor{cfg: cfg, tracker: tracker, writer: writer}
}

type jsonResult struct {
	File           string  `json:"file"`
	String         string  `json:"string"`
	Length         int     `json:"length"`
	Entropy        float64 `json:"entropy"`
	Offset         int64   `json:"offset"`
	Line           int     `json:"line"`
	Column         int     `json:"column"`
	RecursiveDepth int     `json:"recursive_depth,omitempty"`
}

func getEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isPrintable(r rune) bool {
	return (32 <= r && r <= 126) || r == 9
}

// matches reports whether s passes the entropy, exclude and include filters.
// It also returns the entropy when it had to be computed.
func (sp *StringProcessor) matches(s string) (bool, float64) {
	var entropy float64
	if sp.cfg.EntropyMin > 0 || sp.cfg.JSONOut {
		entropy = getEntropy(s)
		if sp.cfg.EntropyMin > 0 && entropy < sp.cfg.EntropyMin {
			return false, entropy
		}
	}
	if sp.cfg.exclude != nil && sp.cfg.exclude.MatchString(s) {
		return false, entropy
	}
	for _, m := range sp.cfg.includes {
		if !m.MatchString(s) {
			return false, entropy
		}
	}
	return true, entropy
}

func (sp *StringProcessor) processString(
	foundString string,
	startOffset int64,
	startLine int,
	startCol int,
	filename string,
	currentDepth int,
) {
	if ok, entropy := sp.matches(foundString); ok {
		sp.emit(foundString, entropy, startOffset, startLine, startCol, filename, currentDepth)
	}

	// Decoding is independent of the output filters: a base64 blob rarely
	// matches e.g. `--find url` itself, but the URL hidden inside it should.
	if currentDepth < maxDecodeDepth {
		sp.decode(foundString, startOffset, filename, currentDepth)
	}
}

func (sp *StringProcessor) emit(s string, entropy float64, offset int64, line, col int, filename string, depth int) {
	switch sp.cfg.CountType {
	case "total":
		sp.tracker.totalCount++
		return
	case "freq":
		sp.tracker.counts[s]++
		return
	}

	if sp.cfg.JSONOut {
		jsonBytes, err := json.Marshal(jsonResult{
			File:           filename,
			String:         s,
			Length:         len(s),
			Entropy:        math.Round(entropy*10000) / 10000,
			Offset:         offset,
			Line:           line,
			Column:         col,
			RecursiveDepth: depth,
		})
		if err != nil {
			warnf(sp.cfg.QuietOut, "Error marshalling JSON: %v\n", err)
			return
		}
		jsonBytes = append(jsonBytes, '\n')
		sp.writer.Write(jsonBytes)
		return
	}

	if sp.cfg.QuietOut {
		fmt.Fprintf(sp.writer, "%s\n", s)
		return
	}
	indent := strings.Repeat("  ", depth)
	fmt.Fprintf(sp.writer, "%s%s:%d:%d:%s\n", indent, filename, line, col, s)
}

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func (sp *StringProcessor) decode(s string, offset int64, filename string, depth int) {
	for _, method := range sp.cfg.DecodeMethods {
		var decoded []byte
		var err error

		switch method {
		case "base64":
			// Accepts both the standard and the URL-safe ("-_") alphabets by
			// mapping URL-safe characters onto their standard equivalents.
			clean := strings.Map(func(r rune) rune {
				switch {
				case r == '-':
					return '+'
				case r == '_':
					return '/'
				case strings.ContainsRune(base64Alphabet, r):
					return r
				}
				return -1
			}, s)
			if len(clean)%4 != 0 {
				clean += strings.Repeat("=", 4-len(clean)%4)
			}
			decoded, err = base64.StdEncoding.DecodeString(clean)
			if err != nil {
				decoded, err = base64.StdEncoding.DecodeString(s)
			}
		case "hex":
			clean := strings.Map(func(r rune) rune {
				if strings.ContainsRune("0123456789abcdefABCDEF", r) {
					return r
				}
				return -1
			}, s)
			decoded, err = hex.DecodeString(clean)
		}

		if err == nil && len(decoded) > 0 {
			name := fmt.Sprintf("%s->%s@%d", filename, method, offset)
			// Errors from an in-memory reader are impossible.
			_ = sp.FindStringsInStream(bytes.NewReader(decoded), name, "ascii", depth+1, 0)
		}
	}
}

// FindStringsInStream scans stream for runs of printable characters in the
// given encoding. baseOffset is added to every reported offset, which lets
// callers scanning a slice of a file (e.g. one section) report file offsets.
func (sp *StringProcessor) FindStringsInStream(stream io.Reader, filename string, encoding string, currentDepth int, baseOffset int64) error {
	var charSize int
	var bigEndian bool
	switch encoding {
	case "ascii":
		charSize = 1
	case "utf-16le":
		charSize = 2
	case "utf-16be":
		charSize = 2
		bigEndian = true
	default:
		return fmt.Errorf("unsupported encoding: %s", encoding)
	}

	reader := bufio.NewReaderSize(stream, 64*1024)

	// Every printable character is ASCII, so the current string is built as
	// plain bytes regardless of the source encoding.
	var current []byte
	var offset, startOffset int64
	line, col := 1, 1
	var startLine, startCol int

	flush := func() {
		if n := len(current); n > 0 && n >= sp.cfg.MinLength && n <= sp.cfg.MaxLength {
			sp.processString(string(current), baseOffset+startOffset, startLine, startCol, filename, currentDepth)
		}
		current = current[:0]
	}

	for {
		var r rune
		b0, err := reader.ReadByte()
		if err == nil && charSize == 2 {
			var b1 byte
			b1, err = reader.ReadByte()
			if bigEndian {
				r = rune(b0)<<8 | rune(b1)
			} else {
				r = rune(b1)<<8 | rune(b0)
			}
		} else {
			r = rune(b0)
		}
		if err != nil {
			// A string running up to the end of the input is still a string.
			flush()
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("error reading %s: %w", filename, err)
		}

		if isPrintable(r) {
			if len(current) == 0 {
				startOffset, startLine, startCol = offset, line, col
			}
			current = append(current, byte(r))
		} else if len(current) > 0 {
			flush()
		}

		if r == '\n' {
			line++
			col = 1
		} else {
			col++
		}
		offset += int64(charSize)
	}
}
