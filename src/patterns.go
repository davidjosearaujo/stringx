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
	"net"
	"regexp"
	"slices"
	"strings"
)

// matcher is a string filter that can also report where it matched (used to
// highlight matches with --color). *regexp.Regexp satisfies it.
type matcher interface {
	MatchString(s string) bool
	FindAllStringIndex(s string, n int) [][]int
}

// anyOf matches when any of its matchers does.
type anyOf []matcher

func (a anyOf) MatchString(s string) bool {
	for _, m := range a {
		if m.MatchString(s) {
			return true
		}
	}
	return false
}

func (a anyOf) FindAllStringIndex(s string, n int) [][]int {
	var spans [][]int
	for _, m := range a {
		spans = append(spans, m.FindAllStringIndex(s, -1)...)
	}
	spans = mergeSpans(spans)
	if n >= 0 && len(spans) > n {
		spans = spans[:n]
	}
	return spans
}

// combine returns a single matcher for ms (nil if empty).
func combine(ms []matcher) matcher {
	switch len(ms) {
	case 0:
		return nil
	case 1:
		return ms[0]
	}
	return anyOf(ms)
}

// mergeSpans sorts spans and merges overlapping or touching ones.
func mergeSpans(spans [][]int) [][]int {
	if len(spans) < 2 {
		return spans
	}
	slices.SortFunc(spans, func(a, b []int) int { return a[0] - b[0] })
	out := [][]int{spans[0]}
	for _, s := range spans[1:] {
		last := out[len(out)-1]
		if s[0] <= last[1] {
			last[1] = max(last[1], s[1])
		} else {
			out = append(out, s)
		}
	}
	return out
}

type preset struct {
	desc    string
	pattern string         // a regular expression, or
	custom  func() matcher // a custom matcher, or
	group   []string       // a set of other presets
}

const ipv4Octet = `(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`

// Common TLDs only: matching any [a-z]{2,} suffix flags every "file.ext" and
// "pkg.Func" in a binary. TLDs that collide with common file extensions
// (.sh, .py, .pl, .rs, .md, .so, .cc, .ps, ...) are left out on purpose.
var domainTLDs = []string{
	"com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "pro",
	"io", "co", "ai", "app", "dev", "xyz", "top", "site", "online", "tech",
	"cloud", "onion", "club", "shop",
	"uk", "de", "fr", "ru", "cn", "jp", "br", "in", "eu", "nl", "au", "ca",
	"ch", "se", "no", "es", "it", "us", "me", "tv", "ly", "gl", "su", "ir",
	"kr", "tw", "hk", "sg", "za", "mx", "ar", "be", "at", "dk", "fi", "ie",
	"il", "nz", "pt", "gr", "cz", "hu", "ro", "ua", "tr", "vn", "th", "my",
	"ph", "pk", "ng", "ke", "eg", "sa", "ae",
}

var presets = map[string]preset{
	"ip": {
		desc:    "IPv4 address",
		pattern: `\b(?:` + ipv4Octet + `\.){3}` + ipv4Octet + `\b`,
	},
	"ipv6": {
		desc:   "IPv6 address",
		custom: func() matcher { return ipv6Matcher{} },
	},
	"email": {
		desc:    "email address",
		pattern: `[\w\.-]+@[\w\.-]+\.[\w]+`,
	},
	"url": {
		desc:    "http(s) URL",
		pattern: `https?://\S+`,
	},
	"domain": {
		desc:    "domain name with a common TLD",
		pattern: `(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:` + strings.Join(domainTLDs, "|") + `)\b`,
	},
	"guid": {
		desc:    "GUID / UUID",
		pattern: `\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`,
	},
	"hash_md5": {
		desc:    "32 hex digits",
		pattern: `\b[a-fA-F\d]{32}\b`,
	},
	"hash_sha1": {
		desc:    "40 hex digits",
		pattern: `\b[a-fA-F\d]{40}\b`,
	},
	"hash_sha256": {
		desc:    "64 hex digits",
		pattern: `\b[a-fA-F\d]{64}\b`,
	},
	"aws_key": {
		desc:    "AWS access key ID",
		pattern: `\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[A-Z0-9]{16}\b`,
	},
	"github_token": {
		desc:    "GitHub token (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)",
		pattern: `\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`,
	},
	"slack_token": {
		desc:    "Slack token (xox?-) or webhook URL",
		pattern: `\bxox[abposr]-[A-Za-z0-9-]{10,}|https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+`,
	},
	"google_api_key": {
		desc:    "Google API key",
		pattern: `\bAIza[0-9A-Za-z_-]{35}`,
	},
	"jwt": {
		desc:    "JSON Web Token",
		pattern: `\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`,
	},
	"private_key": {
		desc:    "PEM / OpenSSH / PGP private key header",
		pattern: `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`,
	},
	"secrets": {
		desc:  "all token and key presets",
		group: []string{"aws_key", "github_token", "slack_token", "google_api_key", "jwt", "private_key"},
	},
}

func findChoices() []string {
	return slices.Sorted(maps.Keys(presets))
}

func presetMatcher(name string) (matcher, error) {
	p, ok := presets[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return nil, fmt.Errorf("unknown --find pattern %q (choices: %s)", name, strings.Join(findChoices(), ", "))
	}
	switch {
	case p.custom != nil:
		return p.custom(), nil
	case p.group != nil:
		var ms []matcher
		for _, member := range p.group {
			m, err := presetMatcher(member)
			if err != nil {
				return nil, err
			}
			ms = append(ms, m)
		}
		return combine(ms), nil
	default:
		return regexp.MustCompile(p.pattern), nil
	}
}

// ipv6Matcher finds IPv6 addresses. A regex covering every compressed form
// is unreadable, so this picks out runs of [0-9a-fA-F:.] that stand alone
// as a word and validates them with net.ParseIP.
type ipv6Matcher struct{}

func (ipv6Matcher) MatchString(s string) bool {
	return len(ipv6Matcher{}.FindAllStringIndex(s, 1)) > 0
}

func (ipv6Matcher) FindAllStringIndex(s string, n int) [][]int {
	var out [][]int
	for i := 0; i < len(s) && (n < 0 || len(out) < n); {
		if !isIPv6Byte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isIPv6Byte(s[j]) {
			j++
		}
		// Reject runs glued to other word characters, e.g. "std::map" or
		// "0xdead::beef", which would otherwise yield "d::" or "dead::beef".
		if (i == 0 || !isWordByte(s[i-1])) && (j == len(s) || !isWordByte(s[j])) {
			cand := strings.TrimRight(s[i:j], ".")
			if strings.Count(cand, ":") >= 2 && strings.ContainsAny(cand, "0123456789abcdefABCDEF") && net.ParseIP(cand) != nil {
				out = append(out, []int{i, i + len(cand)})
			}
		}
		i = j
	}
	return out
}

func isIPv6Byte(b byte) bool {
	return b == ':' || b == '.' || ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F')
}
