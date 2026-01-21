# xorcrypt

This tool is a simple Python-based CLI program that XOR-encrypts shellcode.
It supports reading shellcode both as raw binary files and as text (`\xNN`, `0xNN`, or raw hex strings), using single-byte or multi-byte XOR keys. The encrypted shellcode is written as raw bytes to a binary output file, and can optionally be displayed in several common formats in the terminal, including raw output, Python bytes literals, and C-style byte arrays.

## How to run the program

```bash
python3 xorcrypt.py --input <infile> --output <outfile> --key <hex-byte> [options]
```

or using a string key:

```bash
python3 xorcrypt.py --input <infile> --output <outfile> --key-str <string> [options]
```

---

| Option        | Description           | 
| --- |---| 
| --input, -i      | Path to input shellcode file (binary by default, use additional --text for text input) | 
| --output, -o      | Path to output file for the XOR-encrypted shellcode (raw bytes) |  
| --key, -k | XOR key as a single hex byte (00–FF or 0x00–0xFF) |
| --key-str | XOR key as a string (multi-byte key) |
| --text | Treat input file as text shellcode (\xNN, 0xNN, or raw hex)|
| --format, -f | Display output format for terminal: raw, python, or c-array                                |

---

## Supported text input formats
When using the `--text` option, the following formats are supported:
- `\xNN` byte escapes (e.g. `\x90\x90\xcc`)
- `0xNN` tokens (e.g. `0x90,0x90,0xCC`)
- Raw hex strings (e.g. `4831c050`)

## Supported output formats
The following output formats are supported via the `--format` option:

- `raw` – raw binary output
- `python` – Python bytes literal
- `c-array` – C-style unsigned char array

Note: The `--format` option only affects how the encrypted shellcode is displayed in the terminal.
The output file always contains raw XOR-encrypted bytes

---

## Example commands
### XOR with a hex key and binary input
```bash
python3 xorcrypt.py --input shellcode.bin --output encrypted.bin --key 0x41
```

### XOR with a string key and text input
```bash
python3 xorcrypt.py --input shellcode.txt --text --output encrypted.bin --key-str secret
```

### Display output as a C array
```bash
python3 xorcrypt.py --input shellcode.bin --output encrypted.bin --key 0x41 --format c-array
```
---

## Output format examples
### Raw (binary)
Outputs raw binary data.

```
b'\xb5\x01\xc8\xad\xb9\xb6\xb6'
```
Note: This output shows the raw XOR-encrypted bytes using Python’s default bytes representation.

### C-array
```
unsigned char xored_shellcode[] = {
    0xb5, 0x01, 0xc8, 0xad, 0xb9, 0xb6, 0xb6
};
```

### Python 
```
xored_shellcode = b"\xb5\x01\xc8\xad\xb9\xb6\xb6"
```

---
## Requirements
- Python 3.9+
- No external dependencies

