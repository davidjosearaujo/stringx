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
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
)

var errSectionNotFound = fmt.Errorf("section not found or unsupported format")

func isMachOMagic(magic []byte) bool {
	return bytes.HasPrefix(magic, []byte{0xfe, 0xed, 0xfa, 0xce}) || // 32-bit
		bytes.HasPrefix(magic, []byte{0xce, 0xfa, 0xed, 0xfe}) || // 32-bit reverse
		bytes.HasPrefix(magic, []byte{0xfe, 0xed, 0xfa, 0xcf}) || // 64-bit
		bytes.HasPrefix(magic, []byte{0xcf, 0xfa, 0xed, 0xfe}) // 64-bit reverse
}

func isMachOFatMagic(magic []byte) bool {
	return bytes.HasPrefix(magic, []byte{0xca, 0xfe, 0xba, 0xbe}) ||
		bytes.HasPrefix(magic, []byte{0xbe, 0xba, 0xfe, 0xca})
}

// openSection returns a reader over the named section of an ELF, PE or
// Mach-O file, plus the section's offset within the file so reported string
// offsets can be opened directly in a hex editor or disassembler. inFile is
// false when offsets don't map to the file (compressed ELF sections).
func openSection(r io.ReaderAt, name string) (sec io.ReadSeeker, base int64, inFile bool, err error) {
	magic := make([]byte, 4)
	if _, err := r.ReadAt(magic, 0); err != nil && err != io.EOF {
		return nil, 0, false, fmt.Errorf("error reading magic bytes: %w", err)
	}

	switch {
	case bytes.HasPrefix(magic, []byte("\x7fELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			return nil, 0, false, err
		}
		s := f.Section(name)
		if s == nil {
			break
		}
		if s.Type == elf.SHT_NOBITS {
			return bytes.NewReader(nil), int64(s.Offset), true, nil
		}
		if s.Flags&elf.SHF_COMPRESSED != 0 {
			// Offsets inside decompressed data don't map to the file.
			return s.Open(), 0, false, nil
		}
		return s.Open(), int64(s.Offset), true, nil

	case bytes.HasPrefix(magic, []byte("MZ")):
		f, err := pe.NewFile(r)
		if err != nil {
			return nil, 0, false, err
		}
		if s := f.Section(name); s != nil {
			return s.Open(), int64(s.Offset), true, nil
		}

	case isMachOMagic(magic):
		f, err := macho.NewFile(r)
		if err != nil {
			return nil, 0, false, err
		}
		if s := f.Section(name); s != nil {
			return s.Open(), int64(s.Offset), true, nil
		}

	case isMachOFatMagic(magic):
		// Universal binary: use the first architecture that has the section.
		ff, err := macho.NewFatFile(r)
		if err != nil {
			return nil, 0, false, err
		}
		for _, arch := range ff.Arches {
			if s := arch.Section(name); s != nil {
				return s.Open(), int64(arch.Offset) + int64(s.Offset), true, nil
			}
		}
	}

	return nil, 0, false, errSectionNotFound
}
