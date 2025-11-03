# stringx

stringx is an enhanced, modern, and highly-filterable command-line utility for extracting printable character sequences from files.

Inspired by the classic UNIX `strings` tool, `stringx` goes beyond basic extraction, offering features essential for security analysts, reverse engineers, and data forensics professionals, including advanced filtering by entropy and regex, support for multi-byte encodings (UTF-16), and recursive decoding of embedded strings.

## Key Features

- **Flexible Length Filtering:** Use the powerful `-l, --length` flag to define minimum, maximum, or a range of string lengths (`MIN:MAX`, `MIN:`, or `:MAX`).
- **Recursive Decoding:** Automatically decode embedded Base64 or Hex strings and search for further strings within the decoded content (`-d, --decode base64` or `--decode hex`).
- **Encoding Support:** Search within multi-byte data streams, including **UTF-16 Little Endian** (`utf-16le`) and **UTF-16 Big Endian** (`utf-16be`), not just standard ASCII.
- **Entropy Filtering:** Identify potentially sensitive or compressed data by filtering strings based on their Shannon entropy (`--entropy-min`).
- **Predefined Regex:** Quickly filter for common data patterns like IP addresses, URLs, MD5/SHA256 hashes, and emails (`-f, --find ip`).
- **Data Analysis Output:** Get summary counts of unique strings (`--count`) or output results as **JSON** for easy integration into other tools (`--json`).

## Usage

You can pipe data to `stringx` or provide file paths.

```shell
stringx [flags] [FILE...]
```

## Examples

### 1. Finding High-Entropy Strings

Search a binary file for strings longer than 16 characters that have an entropy score above 4.0, indicating potential key material or compressed blobs:

```shell
stringx my_binary -l 16: --entropy-min 4.0
```

### 2. Recursive Decoding and Searching

Search a firmware dump for Base64 encoded data, then recursively search the decoded content for further strings (up to a depth of 10):

```shell
stringx firmware.bin -d base64 --json
```

### 3. Finding URLs in UTF-16 Data

Scan a Windows memory dump (`.dmp`) file, expecting UTF-16 Little Endian encoding, and filter results to only show valid URLs:

```shell
stringx memory.dmp -e utf-16le -f url
```

### 4. Counting Unique API Keys

Find all strings matching a 64-character SHA256 hash pattern and print a summary count of how many times each unique hash was found:

```shell
stringx logs/*.log -f hash_sha256 --count
```

## Command Reference

| Flag | Short | Description | Example
| - | - | - | - |
| `--length` | `-l` | Specify string length range. Use `MIN:MAX`, `MIN:`, or `:MAX`. | `-l 10:50` (10 to 50 chars) |
| `--encoding` | `-e` | Encoding to search for (`ascii`, `utf-16le`, `utf-16be`). | `-e utf-16le` |
| `--decode` | `-d` | Try to recursively decode found strings using methods (e.g., `base64`, `hex`). | `-d base64` |
| `--entropy-min` | | Filter strings with entropy >= this value (e.g., 4). | `--entropy-min 3` |
| `--regex` | `-r` | Filter strings, only printing those that match the regex. | `-r 'KEY_[A-Z0-9]{20}'` |
| `--find` | `-f` | Use a predefined regex pattern. Choices: `ip`, `email`, `url`, `hash_md5`, `hash_sha256`. | `-f email` |
| `--count` | | Count occurrences of each string and print a summary. | `--count` |
| `--unique` | | Only print the first occurrence of each unique string. | `--unique` |
| `--json` | | Output results as a stream of JSON objects (one per line). | `--json` |
| `--quiet` | `-q` | Suppress all error messages and status output (pipeline friendly) | `-q` |
