# stringx

A new take on improving the amazing `strings` tool.

```shell
Usage:
  stringx [flags] [FILE...]

Flags:
      --count               Count occurrences of each string and print a summary at the end
      --entropy-min float   Filter strings, only printing those with entropy >= this value (default 3)
  -f, --find string         Use a predefined regex pattern. Choices: [base64 email hash_md5 hash_sha256 ip url]
  -h, --help                help for stringx
      --json                Output as a stream of JSON objects (one per line)
  -l, --length string       Specify string length range MIN:MAX or MIN: or :MAX (default "8:")
  -r, --regex string        Filter strings, only printing those that match the regex
      --unique              Only print the first occurrence of each unique string
  -v, --version             version for stringx
```