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
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var predefinedPatterns = map[string]string{
	"ip":          `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
	"email":       `[\w\.-]+@[\w\.-]+\.[\w]+`,
	"url":         `https?://\S+`,
	"hash_md5":    `\b[a-fA-F\d]{32}\b`,
	"hash_sha256": `\b[a-fA-F\d]{64}\b`,
}

var (
	validEncodings     = []string{"ascii", "utf-16le", "utf-16be"}
	validDecodeMethods = []string{"base64", "hex"}
	validCountTypes    = []string{"total", "freq"}
)

// matcher is satisfied by *regexp.Regexp and *wordSet.
type matcher interface {
	MatchString(s string) bool
}

type Config struct {
	LengthRange    string
	MinLength      int
	MaxLength      int
	RegexStr       string
	FindStr        string
	EntropyMin     float64
	JSONOut        bool
	CountType      string
	QuietOut       bool
	WordList       string
	ExcludeStr     string
	Encoding       string
	DecodeMethods  []string
	InteractiveOut bool
	Section        string

	includes []matcher
	exclude  *regexp.Regexp
}

// prepare validates the user-supplied options and compiles filters.
// It must be called once before the Config is used for scanning.
func (c *Config) prepare() error {
	var err error
	if c.MinLength, c.MaxLength, err = parseLengthRange(c.LengthRange); err != nil {
		return err
	}

	if !slices.Contains(validEncodings, c.Encoding) {
		return fmt.Errorf("unsupported --encoding %q (choices: %s)", c.Encoding, strings.Join(validEncodings, ", "))
	}
	for _, m := range c.DecodeMethods {
		if !slices.Contains(validDecodeMethods, m) {
			return fmt.Errorf("unsupported --decode method %q (choices: %s)", m, strings.Join(validDecodeMethods, ", "))
		}
	}
	if c.CountType != "" && !slices.Contains(validCountTypes, c.CountType) {
		return fmt.Errorf("unsupported --count type %q (choices: %s)", c.CountType, strings.Join(validCountTypes, ", "))
	}

	c.includes = nil
	if c.RegexStr != "" {
		r, err := regexp.Compile(c.RegexStr)
		if err != nil {
			return fmt.Errorf("invalid --regex %q: %w", c.RegexStr, err)
		}
		c.includes = append(c.includes, r)
	}
	if c.FindStr != "" {
		pattern, ok := predefinedPatterns[c.FindStr]
		if !ok {
			return fmt.Errorf("unknown --find pattern %q (choices: %s)", c.FindStr, strings.Join(findChoices(), ", "))
		}
		c.includes = append(c.includes, regexp.MustCompile(pattern))
	}
	if c.WordList != "" {
		ws, err := loadWordSet(c.WordList)
		if err != nil {
			return err
		}
		if ws.Len() == 0 {
			// An empty wordlist used to be ignored; keep that behaviour.
			warnf(c.QuietOut, "Warning: wordlist file %s is empty\n", c.WordList)
		} else {
			c.includes = append(c.includes, ws)
		}
	}

	c.exclude = nil
	if c.ExcludeStr != "" {
		if c.exclude, err = regexp.Compile(c.ExcludeStr); err != nil {
			return fmt.Errorf("invalid --exclude %q: %w", c.ExcludeStr, err)
		}
	}
	return nil
}

// parseLengthRange parses "MIN:MAX", "MIN:", ":MAX" or "MIN".
func parseLengthRange(s string) (min, max int, err error) {
	min, max = 0, math.MaxInt32
	minStr, maxStr, hasColon := strings.Cut(strings.TrimSpace(s), ":")

	parse := func(v, which string) (int, error) {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid --length %q: %s must be a non-negative integer", s, which)
		}
		return n, nil
	}

	if minStr != "" {
		if min, err = parse(minStr, "MIN"); err != nil {
			return
		}
	}
	if hasColon && maxStr != "" {
		if max, err = parse(maxStr, "MAX"); err != nil {
			return
		}
	}
	if min > max {
		return 0, 0, fmt.Errorf("invalid --length %q: MIN is greater than MAX", s)
	}
	return min, max, nil
}

func findChoices() []string {
	return slices.Sorted(maps.Keys(predefinedPatterns))
}
