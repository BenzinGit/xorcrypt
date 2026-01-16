import argparse
import re
import sys

def read_shellcode(path, text_mode):
    """
    Selects the correct file-reading and parsing logic based
    on the input format and returns shellcode as a byte sequence.
    
    Args:
        path (str): Path to the shellcode file.
        text_mode (bool): If True, parse shellcode from a text representation.
                          If False, read raw binary shellcode.
    
    Returns:
        bytes: Parsed shellcode.
                
        
    Raises:
        ValueError: If the resulting shellcode is empty.    
    """

    # Read shellcode depending on input mode (text or binary)
    if (text_mode): 
        shellcode = parse_text_shellcode(read_text_file(path))
    else:
        print("[+] Reading raw binary shellcode")  
        shellcode = read_binary_file(path)
    
    # Empty shellcode is considered an error
    if len(shellcode) == 0:
        raise ValueError("Input file is empty")

    return shellcode


def read_text_file(path):
    """
    Read the contents of a UTF-8 encoded text file.

    Args:
        path (str): Path to the text file.

    Returns:
        str: Full contents of the file as a string.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file cannot be decoded as UTF-8 text.
    """
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {path}")
    except UnicodeDecodeError:
        raise ValueError(f"File is not valid UTF-8 text: {path}")


def read_binary_file(path):
    """
    Read the contents of a file in binary mode.

    Args:
        path (str): Path to the input file.

    Returns:
        bytes: Raw file contents.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {path}")
    
    


def parse_text_shellcode(content): 
    """
    Parse shellcode from common text representations into raw bytes.

    Supported formats:
      - '\\xNN' byte escapes (e.g. \\x90\\x90\\xcc)
      - '0xNN' tokens (e.g. 0x90,0x90,0xCC)
      - Raw hex string (e.g. 4831c050...)

    Whitespace is ignored.

    Args:
        content (str): Input text containing a shellcode representation.

    Returns:
        bytes: Parsed shellcode bytes.

    Raises:
        ValueError: If the format is unknown or the content is invalid.
    """
    
    # Remove all whitespaces
    compact = "".join(content.split())

    # 1) \xNN-format
    if "\\x" in compact:
        pairs = re.findall(r"\\x([0-9a-fA-F]{2})", compact)
        if not pairs:
            raise ValueError("Invalid \\xNN shellcode format")
        print("[+] Text shellcode: \\xNN format detected")        
        return bytes(int(p, 16) for p in pairs)

    # 2) 0xNN-format
    if "0x" in compact.lower():
        pairs = re.findall(r"0x([0-9a-fA-F]{2})", compact, flags=re.IGNORECASE)
        if not pairs:
            raise ValueError("Invalid 0xNN shellcode format")
        print("[+] Text shellcode: 0xNN format detected")     
        return bytes(int(p, 16) for p in pairs)

    # 3) Raw hex tring
    if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
        print("[+] Text shellcode: raw hex (or unknown) detected")
        return bytes.fromhex(compact)

    # No matches
    raise ValueError("Unknown text shellcode format (expected \\xNN, 0xNN, or raw hex)")


def xor_encrypt(data, key):
    """
    Apply repeating-key XOR to a byte sequence.

    Args:
        data (bytes): Input data to be XOR-processed.
        key (bytes): XOR key (must be non-empty).

    Returns:
        bytes: Resulting XOR-transformed data.
    """

    result = []
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % len(key)])
    return bytes(result)


def format_output(data, format):
    """
    Format binary data into a selected output representation.

    Supported formats:
      - "raw": return data unchanged (bytes)
      - "python": Python-style shellcode string
      - "c-array": C-style byte array

    Args:
        data (bytes): Input binary data.
        format (str): Desired output format.

    Returns:
        bytes | str: Formatted output depending on the selected format.

    Raises:
        ValueError: If the output format is unknown.
    """
    
    match format:
        case "raw":
            return data
        case "python":
            return format_python(data)
        case "c-array":
            return format_c(data)
        case _:
            raise ValueError(f"Unknown output format: {format}") 


def format_python(data):
    """
    Format binary data as a Python bytes literal.

    Args:
        data (bytes): Input binary data.

    Returns:
        str: Python-formatted bytes literal.
    """
    
    hex_bytes = 'xored_shellcode = b"'

    for b in data:
        hex_bytes += f"\\x{b:02x}"

    hex_bytes += '"\n'
    return hex_bytes


def format_c(data):
    """
    Format binary data as a C-style unsigned char array.

    Args:
        data (bytes): Input binary data.

    Returns:
        str: C source code defining an unsigned char array.
    """

    row_length = 16

    hex_bytes = [f"0x{b:02x}" for b in data]
    lines = []
    for i in range(0, len(hex_bytes), row_length):
        chunk = ", ".join(hex_bytes[i:i + row_length])
        lines.append("    " + chunk + ",")

    lines[-1] = lines[-1].rstrip(",")
    output = (
        "unsigned char xored_shellcode[] = {\n"
        + "\n".join(lines)
        + "\n};\n\n"
        )
    
    return output


    
def write_output(path, output):
        """
        Write binary output to a file.

        Args:
            path (str): Output file path.
            output (bytes): Binary data to write.

        Raises:
            OSError: If the file cannot be written.
        """
        
        try:
            with open(path, "wb") as f:
                f.write(output)
        except OSError as e:
            raise OSError(f"Failed to write output file '{path}': {e}")




def print_summary(file_in, file_out, key, output_format):
    """
    Print a summary of the current operation to the terminal.

    Args:
        file_in (str): Input file path.
        file_out (str): Output file path.
        key (str): XOR key.
        output_format (str): Selected output format.
    """

    print("[+] Input    : ", file_in)
    print("[+] Output   : ", file_out)
    print("[+] Key      : ", key)
    print("[+] Format   : ", output_format)


def parse_args():
    """
    Parse and return command-line arguments for the XOR shellcode tool.
    """
    
    parser = argparse.ArgumentParser(description="XOR-encrypt shellcode from a binary file or text representation",
                                     epilog="""Examples:
  xorcrypt.py -i shellcode.bin -o out.bin -k 0x41 -f c-array
  xorcrypt.py -i shellcode.bin -o out.bin -k 4f
  xorcrypt.py -i shellcode.txt --text --key-str secret -f python
""",
    formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # Input file path (binary by default unless --text is specified)                                 
    parser.add_argument("-i", "--input", dest="infile", required=True,  metavar="PATH", help="input file path (binary by default). Use --text for text shellcode")
    
    # Optional output file path; if omitted, output is printed only
    parser.add_argument("-o", "--output", dest="outfile",  metavar="PATH", help="output file path. If omitted, output is not written to file")
    
    # Treat input as text shellcode instead of raw binary
    parser.add_argument("--text", action="store_true", help="treat input as text shellcode (supports \\xNN, 0xNN, or plain hex)")
    
    # XOR key must be provided either as hex or as a string (mutually exclusive)
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument("-k", "--key",  metavar="HEX", help="XOR key as a single hex byte (00–FF or 0x00–0xFF). Example: -k 4f or -k 0x4f")
    key_group.add_argument("--key-str", metavar="STRING", help="XOR key as a string (UTF-8). Example: --key-str secret")
    
    # Select output format for the processed shellcode
    parser.add_argument("-f", "--format", metavar="FORMAT", choices=["raw", "python", "c-array"], help="output format: raw, python or c-array")
    
    # Display tool version and exit
    parser.add_argument("--version", action="version", version="xorcrypt 1.0") 
    return parser.parse_args()


def parse_key(args):    
    """
    Parse and normalize the XOR key from command-line arguments.
    
    Args:
        args (argparse.Namespace): Parsed CLI arguments containing either
            a hex key (--key) or a string key (--key-str).
    Returns:
        tuple:
            - bytes: Normalized XOR key as bytes.
            - str: Display-friendly representation of the key.
            - str: Key type identifier ("hex" or "str").

    
    """


    # If the key was provided as a hex byte (-k / --key)
    if args.key is not None:
        # Reject empty key value
        if args.key == "":
            raise ValueError("XOR key must not be empty")
        

        try:
            # Parse hex string into an integer
            key_byte = int(args.key, 16)
           
        except ValueError:
             # Raised if the hex string cannot be parsed
            raise ValueError(f"Invalid hex key: {args.key}")

        # Ensure the parsed value fits into a single byte
        if not (0 <= key_byte <= 0xFF):
            raise ValueError("Hex key must be a single byte (00–FF)")
      
       # Convert single byte integer into bytes object
        key = bytes([key_byte])

        # Preserve original key representation for display purposes
        key_display = args.key
        key_type = "hex"
    
    # If the key was provided as a string (--key-str)
    else:
        # Reject empty key string
        if (args.key_str == ""):
            raise ValueError("Key string cannot be empty. Provide at least 1 character.")
        
        # Encode key string as bytes (UTF-8)
        key = args.key_str.encode()

        # Preserve original string for display purposes
        key_display = args.key_str
        key_type = "str"

    # Return normalized key bytes, display-friendly value, and key type
    return key, key_display, key_type


def print_output(output, format):
    """
    Print formatted output to the terminal.

    Args:
        output: Formatted output data to display.
        format (str): Output format identifier used for labeling.
    """
    
    print()
    print("---- XORED", format.upper(),"OUTPUT ----")
    print()
    print(output)
    print("---- END OUTPUT ----")



def main():
    """
    Entry point for the XOR shellcode encryptor.
    Coordinates program logic, like argument parsing, key handling, shellcode processing,
    output generation and error handling.
    """
    

    try:
        # Parse command-line arguments
        args = parse_args()
        
        # Program banner
        print()
        print("=== XOR Shellcode Encryptor ===")
        print()

        # Parse and normalize XOR key from arguments
        key, key_display, key_type = parse_key(args)

        # Print a summary of the user input
        print_summary(args.infile, args.outfile,  f"{key_type}: {key_display}", args.format)
        print()

        # Read shellcode from input file (binary or text mode)
        shellcode = read_shellcode(args.infile, args.text)
            
         # Apply XOR encryption to the shellcode    
        encrypted_shellcode = xor_encrypt(shellcode, key)

        # Write raw encrypted shellcode to output file if requested
        if (args.outfile):
            write_output(args.outfile, encrypted_shellcode)
            print("[+] Output saved to", args.outfile)

        # Format and print output if a display format was selected
        if (args.format):
            output = format_output(encrypted_shellcode, args.format)
            print_output(output, args.format)
            
    except Exception as e:
        # Catch and report any error, then exit with non-zero status
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

