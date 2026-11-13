# stringx

stringx is an enhanced, modern, and highly-filterable command-line utility for extracting printable character sequences from files.

Inspired by the classic UNIX `strings` tool, `stringx` goes beyond basic extraction, offering features essential for security analysts, reverse engineers, and data forensics professionals: secret and IOC detection, entropy and regex filtering, multi-byte encodings, recursive decoding of embedded and compressed data, and XOR deobfuscation with a known or brute-forced key.

## Key Features

- **Secret & IOC hunting:** Built-in patterns for AWS keys, GitHub and Slack tokens, Google API keys, JWTs, private keys, IPv4/IPv6 addresses, domains, URLs, emails, GUIDs and hashes (`-f secrets`, `-f ipv6`, ...).
- **Recursive Decoding:** Decode Base64 (standard or URL-safe), Base32, hex and URL-encoded strings, inflate gzip/zlib data, and search the result again, up to 10 layers deep (`-d base64,gzip`). Encoded data embedded in a longer string (`token=...`, `powershell -enc ...`) is found too, and decoded UTF-16 is detected automatically.
- **XOR deobfuscation:** Rescan the input with a known key, single or multi-byte (`-d xor:5a`, `-d xor:deadbeef`, `-d xor:s:mykey`), or try all 255 single-byte keys when you don't have one (`-d xor`).
- **Encoding Support:** ASCII, UTF-8 (including non-ASCII text), UTF-16LE and UTF-16BE, or all of the classic three at once (`-e all`).
- **Flexible Filtering:** Repeatable regexes, predefined patterns and wordlists, exclusions, Shannon entropy and length ranges.
- **Wordlist search:** Search for whole words from one or more wordlists. Lookups are hash-based, so multi-million-entry lists such as `rockyou.txt` are fine.
- **Directories & parallelism:** Scan directory trees with `-R`. Files and passes run in parallel (`-j`), with output always in input order.
- **Section targeting:** Scan a single section of an ELF, PE or Mach-O binary (including universal binaries). Reported offsets are file offsets, so they can be opened directly in a hex editor.
- **Readable output:** `strings -t`-style offsets, colored matches, hexdump context around each hit, JSON, counts, and a built-in pager.

## Usage

```shell
stringx [flags] [FILE...]
```

`FILE` may be `-` for standard input (also the default when no file is given), or a directory when `-R` is set.

**How filters combine:** filters of the same kind are alternatives, while different kinds must all match. `-f url -f email` prints URLs *or* emails; `-f url -r example` prints URLs that *also* match `example`. A string matching any `-x` is dropped.

## Examples

### 1. Hunting for leaked secrets in a source tree

```shell
stringx -R -f secrets --color ./repo
```

`secrets` combines `aws_key`, `github_token`, `slack_token`, `google_api_key`, `jwt` and `private_key`.

### 2. Decoding a PowerShell payload

`powershell -EncodedCommand` takes Base64 of UTF-16LE text. stringx detects the UTF-16 automatically:

```shell
stringx -d base64 -f url,domain suspicious.ps1
```

### 3. Compressed data hidden in Base64

Decode Base64, inflate any gzip data inside, and search the result for IPs:

```shell
stringx -d base64,gzip -f ip,ipv6 config.bin
```

`-d gzip` also works on a whole `.gz` file: `stringx -d gzip logs.gz`.

### 4. Reading XOR-obfuscated strings

With a known key, pass it and read the strings straight off:

```shell
stringx -d xor:5a malware.bin
stringx -d xor:deadbeef -f url -C 16 malware.bin
```

The key is hex (`5a`, `0x5a`, `deadbeef`) or, with an `s:` prefix, text (`s:mykey`); a value that isn't valid hex is taken as text too, so `-d xor:hunter2` works. Multi-byte keys repeat over the input. Keys are repeatable (`-d xor:5a,xor:deadbeef`), and the plain, un-XORed input is always scanned as well.

Without a key, every single-byte key is tried; keep only real hits with a filter:

```shell
stringx -d xor -f url -t x malware.bin
```

Results are labelled with their key, e.g. `malware.bin->xor(0x5a):3e9:http://c2.example/beacon`. Without a filter, the output contains the strings for all 255 keys, so add `-f`, `-r` or `-w`.

### 5. Hexdump context around hits

```shell
stringx -f aws_key -C 16 firmware.bin
```

```
firmware.bin:1:3:secret=AKIAIOSFODNN7EXAMPLE
    00000000  01 02 73 65 63 72 65 74  3d 41 4b 49 41 49 4f 53  |..secret=AKIAIOS|
    00000010  46 4f 44 4e 4e 37 45 58  41 4d 50 4c 45 00 ff     |FODNN7EXAMPLE..|
```

### 6. Classic `strings -t x` output

```shell
stringx -q -t x my_binary
```

### 7. Every encoding at once

```shell
stringx -e all memory.dmp -f url
```

With several encodings, results are tagged with their encoding, e.g. `memory.dmp[utf-16le]:...`.

### 8. High-entropy strings

Strings of at least 16 characters with an entropy above 4.0, a hint of key material or compressed blobs:

```shell
stringx my_binary -l 16: --entropy 4.0
```

### 9. Counting unique hashes

```shell
stringx logs/*.log -f hash_sha256 --count=freq
```

Note the `=`: `--count` has an optional value, so `--count freq` would treat `freq` as a file name. The same applies to `--color`.

### 10. Interactive Pager

`-i` shows the output in a full-screen, `less`-style pager. It also works when the data is piped in on stdin.

```shell
stringx -i large_db_dump.bin
```

| Key | Action |
| --- | --- |
| **Up** / **Down** / **Enter** / **j** / **k** | Scroll line-by-line |
| **Space** | Scroll down one page |
| **b** | Scroll up one page (back) |
| **g** | Go to the top of the output |
| **G** | Go to the bottom of the output |
| **q** / **Ctrl-C** | Quit the pager and exit `stringx` |

## Predefined Patterns (`-f`)

| Name | Matches |
| - | - |
| `ip` | IPv4 address (octets 0–255) |
| `ipv6` | IPv6 address, any compressed form (validated, so `std::map` and timestamps don't match) |
| `domain` | Domain name with a common TLD (TLDs that clash with file extensions, such as `.sh` or `.py`, are left out) |
| `url` | `http://` or `https://` URL |
| `email` | Email address |
| `guid` | GUID / UUID |
| `hash_md5`, `hash_sha1`, `hash_sha256` | 32, 40 or 64 hex digits |
| `aws_key` | AWS access key ID (`AKIA...`, `ASIA...`) |
| `github_token` | GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) |
| `slack_token` | Slack token (`xoxb-`, ...) or webhook URL |
| `google_api_key` | Google API key (`AIza...`) |
| `jwt` | JSON Web Token |
| `private_key` | PEM, OpenSSH or PGP private key header |
| `secrets` | All of `aws_key`, `github_token`, `slack_token`, `google_api_key`, `jwt`, `private_key` |

## Decoders (`-d`)

| Method | What it does |
| - | - |
| `base64` | Decodes Base64, standard or URL-safe, with or without padding |
| `base32` | Decodes Base32, any case, with or without padding |
| `hex` | Decodes hex, including `0x...` and space-separated bytes |
| `url` | Decodes `%XX` escapes |
| `gzip` | Inflates gzip data, either the whole input or any decoded blob |
| `zlib` | Inflates zlib data, either the whole input or any decoded blob |
| `xor` | Rescans the whole input with each single-byte XOR key (1–255) |
| `xor:KEY` | Rescans the whole input with that key only: hex (`xor:5a`, `xor:deadbeef`) or text (`xor:s:mykey`), repeating over the input |

Decoded content is searched again, up to 10 layers deep, in the selected encodings, plus UTF-16 when the data looks like it. Filters only decide what is printed, never what gets decoded. Each inflated stream is capped at 128 MiB.

## Command Reference

| Flag | Short | Description | Example |
| - | - | - | - |
| `--length` | `-l` | String length range in characters: `MIN:MAX`, `MIN:` or `:MAX`. | `-l 10:50` |
| `--encoding` | `-e` | Encodings to search: `ascii`, `utf-8`, `utf-16le`, `utf-16be`, `all` (comma-separated). | `-e utf-8,utf-16le` |
| `--section` | `-s` | Only scan this section of an executable (ELF, PE, Mach-O). `--sector` is accepted as an alias. | `-s .rodata` |
| `--recursive` | `-R` | Scan directories recursively. Symlinks and special files inside the tree are skipped. | `-R ./src` |
| `--find` | `-f` | Predefined patterns (see above). Repeatable or comma-separated. | `-f url,email` |
| `--regex` | `-r` | Only print strings matching this regex. Repeatable. | `-r 'KEY_[A-Z0-9]{20}'` |
| `--wordlist` | `-w` | Only print strings containing a whole word from this file. Repeatable. | `-w rockyou.txt` |
| `--exclude` | `-x` | Drop strings matching this regex. Repeatable. | `-x localhost` |
| `--entropy` | | Only print strings with Shannon entropy >= this value. | `--entropy 4` |
| `--decode` | `-d` | Decoders (see above). Repeatable or comma-separated. `xor` takes an optional key. | `-d base64,gzip`, `-d xor:5a` |
| `--radix` | `-t` | Print offsets instead of line:column, in `x` (hex), `d` (decimal) or `o` (octal). | `-t x` |
| `--context` | `-C` | Show a hexdump of N bytes around each string. | `-C 16` |
| `--color` | | Highlight matches: `auto` (default; when writing to a terminal and `NO_COLOR` is unset), `always`, `never`. | `--color=never` |
| `--json` | | Output a stream of JSON objects, one per line. | `--json` |
| `--count` | `-c` | Display counts: `total` (default) or `freq`. Attach the value with `=`. | `--count=freq` |
| `--interactive` | `-i` | Use a full-screen, `less`-style pager for output. | `-i` |
| `--quiet` | `-q` | Print bare strings and suppress error messages (pipeline friendly). | `-q` |
| `--jobs` | `-j` | Number of scans to run in parallel (default: number of CPUs). | `-j 4` |

### JSON fields

Each result has `file`, `string`, `length` (in characters), `entropy`, `offset`, `line`, `column` and `encoding`. Decoded results also have `recursive_depth`. With `-C`, a `context` object holds the `offset` and `hex` of the surrounding bytes. Counts are emitted as `{"total": N}` or `{"string": ..., "count": N}`.

## Exit Status

`stringx` exits with `0` on success and `1` if any input could not be read or an option is invalid. Strings from the inputs that *could* be read are still printed.

## Building and Testing

```shell
go test ./...      # run the test suite
go build ./src     # build for the current platform
./build.sh         # cross-compile release binaries into build/
```

The version lives in `src/main.go` and must match the top entry of `debian/changelog` (a test enforces this). `build.sh` stamps the version from a git tag such as `v1.2.0` when one exists, or from `VERSION=... ./build.sh`.
