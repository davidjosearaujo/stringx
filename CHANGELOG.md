# Changelog

All notable changes to stringx are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-11-13

### Added

- `-d xor` takes a key, so a known key can be read straight off instead of
  brute-forced: `-d xor:5a`, `-d xor:0x5a`, `-d xor:deadbeef` (multi-byte keys
  repeat over the input), or `-d xor:s:mykey` for a text key. A value that
  isn't valid hex is taken as text, so `-d xor:hunter2` works.
- Keys are repeatable (`-d xor:5a,xor:deadbeef`) and additive, like every other
  decoder: the plain, un-XORed input is always scanned as well. Results are
  labelled with the key they came from, e.g. `malware.bin->xor(0xdeadbeef)`.
- XOR keys reach `-C`/`--context` and `--section` too: the hexdump shows the
  deciphered bytes, in the right key phase.

### Changed

- A bare `-d xor` still brute-forces all 255 single-byte keys; its warning now
  points at `-d xor:KEY` as the alternative to adding a filter.
- A key given to a decoder that takes none is rejected, e.g. `-d hex:5a`.

## [1.3.0] - 2026-11-06

### Added

- `--find` presets: `ipv6`, `domain`, `guid`, `hash_sha1`, `aws_key`,
  `github_token`, `slack_token`, `google_api_key`, `jwt`, `private_key`, and
  `secrets`, which combines all the token and key presets.
- Decoders: `base32`, `url` (`%XX`), `gzip` and `zlib` (the whole input or any
  decoded blob), and `xor` (brute-forcing all single-byte keys).
- Base64, base32 and hex embedded in longer strings are decoded too
  (`key=...`, `0x...`, `powershell -enc ...`), and UTF-16 is detected
  automatically in decoded data.
- Encodings: `utf-8` (including non-ASCII text) and `all`; `-e` takes a list.
- `-R`/`--recursive` scans directories, and `-j`/`--jobs` scans in parallel
  with output kept in input order. `-` reads standard input.
- `-t`/`--radix` prints offsets like `strings -t`, `--color` highlights
  matches, and `-C`/`--context` shows a hexdump around each hit (also in
  `--json`).

### Changed

- `-f`, `-r`, `-x` and `-w` are repeatable. Filters of the same kind are
  alternatives; different kinds must all match.
- `ip` now rejects octets greater than 255.
- `--section` also works on piped input.
- JSON results include the encoding, and `length` counts characters.
- Faster text output.
- `build.sh` writes bare file names to `checksums.txt`, so `sha256sum -c`
  verifies next to downloaded release assets.

## [1.2.0] - 2026-11-06

### Added

- `--json` output for `--count`, and buffered stdout for faster output.
- A test suite.

### Changed

- Found strings are decoded regardless of the output filters, so e.g.
  `-d base64 -f url` finds URLs inside base64 blobs.
- `--sector` is now `--section`; `--sector` is still accepted.
- `--length`, `--encoding`, `--decode` and `--count` are validated up front.
- The wordlist regex is now a hash lookup, which makes large wordlists such as
  `rockyou.txt` practical.
- Universal (fat) Mach-O binaries are supported.
- `debian/copyright` declares Apache-2.0, matching the upstream LICENSE and the
  source headers (it incorrectly said GPL-3.0+).

### Fixed

- Strings running to the end of the input were dropped, which also broke
  recursive decoding (`-d`).
- Decoded strings were not counted in `--count` mode.
- URL-safe base64 (the `-_` alphabet, with optional padding) was not accepted
  by `-d base64`.
- `--section` reported section offsets instead of file offsets.
- Unreadable inputs now report the real error and exit with status 1.
- Pager: terminal height detection, reading keys from the terminal when data is
  piped on stdin, very long lines, and quitting on Ctrl-C.

## [0.1.0] - 2026-02-21

- Initial release.
