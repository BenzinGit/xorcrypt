# xorcrypt

This tool is a simple Python-based CLI program that XOR-encrypts shellcode.
It supports reading shellcode both as raw binary files and as text
(`\x..` format), using single-byte or multi-byte XOR keys, and outputting
the result in several common formats used in exploit development.

---

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
| --input, -i      | Input file containing shellcode | 
| --output, -o      | Write output to file (as binary)      |  
| --key, -k | XOR key as a single hex byte (00–FF) |
| --key-str | XOR key as a string (multi-byte key) |
| --text | Treat input as text |
| --format, -f | Output format (raw, c-array, python) |

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
Outputs raw binary data (written directly to a file).

```
b'\xb5\x01\xc8\xad\xb9\xb6\xb6'
```

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
