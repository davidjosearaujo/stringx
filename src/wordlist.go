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
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// wordSet reports whether a string contains any word from a wordlist as a
// whole word. It is equivalent to the regex `\b(w1|w2|...)\b` built from
// regexp.QuoteMeta'd words, but uses a hash lookup per candidate position, so
// it stays fast with wordlists of millions of entries (where a giant regex
// alternation becomes unusably slow).
type wordSet struct {
	words   map[string]struct{}
	lengths []int // distinct word lengths, ascending
}

func newWordSet(words []string) *wordSet {
	ws := &wordSet{words: make(map[string]struct{}, len(words))}
	seen := map[int]bool{}
	for _, w := range words {
		if w == "" {
			continue
		}
		ws.words[w] = struct{}{}
		if !seen[len(w)] {
			seen[len(w)] = true
			ws.lengths = append(ws.lengths, len(w))
		}
	}
	slices.Sort(ws.lengths)
	return ws
}

func loadWordSet(path string) (*wordSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open wordlist file %s: %w", path, err)
	}
	defer f.Close()
	ws, err := readWordSet(f)
	if err != nil {
		return nil, fmt.Errorf("error reading wordlist file %s: %w", path, err)
	}
	return ws, nil
}

func readWordSet(r io.Reader) (*wordSet, error) {
	var words []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if w := strings.TrimSpace(scanner.Text()); w != "" {
			words = append(words, w)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return newWordSet(words), nil
}

func (ws *wordSet) Len() int { return len(ws.words) }

func (ws *wordSet) MatchString(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isWordBoundary(s, i) {
			continue
		}
		for _, l := range ws.lengths {
			j := i + l
			if j > len(s) {
				break
			}
			if !isWordBoundary(s, j) {
				continue
			}
			if _, ok := ws.words[s[i:j]]; ok {
				return true
			}
		}
	}
	return false
}

// isWordBoundary mirrors RE2's ASCII `\b` assertion at byte position i.
func isWordBoundary(s string, i int) bool {
	before := i > 0 && isWordByte(s[i-1])
	after := i < len(s) && isWordByte(s[i])
	return before != after
}

func isWordByte(b byte) bool {
	return b == '_' || ('0' <= b && b <= '9') || ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z')
}
