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

// Run with: SX_BENCH_FILE=/path/to/file go test -run x -bench . ./src
package main

import (
	"os"
	"testing"
)

func BenchmarkScanRandom(b *testing.B) {
	data, err := os.ReadFile(os.Getenv("SX_BENCH_FILE"))
	if err != nil {
		b.Skip(err)
	}
	cfg := Config{LengthRange: "4:"}
	cfg.prepare()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		units := buildUnits([]*input{{name: "in", data: data, buffered: true}}, &cfg)
		runUnits(units, &cfg, discard{}, func(*input, error) {})
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
