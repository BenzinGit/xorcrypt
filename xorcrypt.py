import argparse
import re
import sys


def read_shellcode(path, text_mode):
    if (text_mode): 
        shellcode = parse_text_shellcode(read_text_file(path))
    else:
        shellcode = read_binary_file(path)
    
    if len(shellcode) == 0:
        raise ValueError("Input file is empty")

    return shellcode



def read_binary_file(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            print("[+] Reading raw binary shellcode")  
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {path}")
    
    


def parse_text_shellcode(content): 
    # Remove whitespaces
    compact = "".join(content.split())

    # 1) \xNN-format (Python / C)
    if "\\x" in compact:
        pairs = re.findall(r"\\x([0-9a-fA-F]{2})", compact)
        if not pairs:
            raise ValueError("Invalid \\xNN shellcode format")
        print("[+] Reading text shellcode (\\xNN format detected)")
        return bytes(int(p, 16) for p in pairs)

    # 2) 0xNN-format
    if "0x" in compact.lower():
        pairs = re.findall(r"0x([0-9a-fA-F]{2})", compact, flags=re.IGNORECASE)
        if not pairs:
            raise ValueError("Invalid 0xNN shellcode format")
        print("[+] Reading text shellcode (0xNN format detected")
        return bytes(int(p, 16) for p in pairs)

    # 3) Pure hextring: 4831c050...
    if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
        print("[+] Reading text shellcode (raw hex string detected)")
        return bytes.fromhex(compact)

    # No matches
    raise ValueError("Unknown text shellcode format")



def read_text_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {path}")
    except UnicodeDecodeError:
        raise ValueError(f"File is not valid UTF-8 text: {path}")


def xor_encrypt(data, key):
    result = []
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % len(key)])
    return bytes(result)


def format_output(data, format):
    match format:
        case "raw":
            return data
        case "python":
            return format_python(data)
        case "c-array":
            return format_c(data)
        case _:
            return None; 


def format_python(data):
    out = 'xored_shellcode = b"'

    for b in data:
        out += f"\\x{b:02x}"

    out += '"\n'
    return out


def format_c(data):

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
        try:
            with open(path, "wb") as f:
                f.write(output)
                print("[+] Output saved to", path)
        except OSError as e:
            raise OSError(f"Failed to write output file '{path}': {e}")




def print_summary(file_in, file_out, key, format):
    
    print("[+] Input    : ", file_in)
    print("[+] Output   : ", file_out)
    print("[+] Key      : ", key)
    print("[+] Format   : ", format)


def parse_args():
    parser = argparse.ArgumentParser(description="XOR-encrypt shellcode from a binary file or text representation",
                                     epilog="""Examples:
  xorcrypt.py -i shellcode.bin -o out.bin -k 0x41 -f c-array
  xorcrypt.py -i shellcode.bin -o out.bin -k 4f
  xorcrypt.py -i shellcode.txt --text --key-str secret -f python
""",
    formatter_class=argparse.RawDescriptionHelpFormatter
     
                                     )
    parser.add_argument("-i", "--input", dest="infile", required=True,  metavar="PATH", help="input file path (binary by default). Use --text for text shellcode")
    parser.add_argument("-o", "--output", dest="outfile",  metavar="PATH", help="output file path. If omitted, prints to file")
    parser.add_argument("--text", action="store_true", help="treat input as text shellcode (supports \\xNN, 0xNN, or plain hex)")
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument("-k", "--key",  metavar="HEX", help="XOR key as a single hex byte (00–FF or 0x00–0xFF). Example: -k 4f or -k 0x4f")
    key_group.add_argument("--key-str", metavar="STRING", help="XOR key as a string (UTF-8). Example: --key-str secret")
    parser.add_argument("-f", "--format", metavar="FORMAT", choices=["raw", "python", "c-array"], help="output format: raw, python or c-array")
    parser.add_argument("--version", action="version", version="xorcrypt 1.0")
    return parser.parse_args()

def parse_key(args):    
    if args.key:
        try:
            key_byte = int(args.key, 16)
            key = bytes([key_byte])
        except ValueError:
            raise ValueError(f"Invalid hex key: {args.key}")

        if not (0 <= key_byte <= 0xFF):
            raise ValueError("Hex key must be a single byte (00–FF)")
      
        key_display = args.key
        key_type = "hex"
    
    else:
        if (args.key_str == ""):
            raise ValueError("Key string cannot be empty. Provide at least 1 character.")
        key = args.key_str.encode()
        key_display = args.key_str
        key_type = "str"

    return key, key_display, key_type


def print_output(output, format):
    print()
    print("---- XORED", format.upper(),"OUTPUT ----")
    print()
    print(output)
    print("---- END OUTPUT ----")



def main():
    try:
       
        args = parse_args()

        print()
        print("=== XOR Shellcode Encryptor ===")
        print()

        key, key_display, key_type = parse_key(args)

        print_summary(args.infile, args.outfile,  f"{key_type}: {key_display}", args.format)
        print()


        shellcode = read_shellcode(args.infile, args.text)
            

        encrypted_shellcode = xor_encrypt(shellcode, key)

        if (args.outfile):
            write_output(args.outfile, encrypted_shellcode)

        if (args.format):
            output = format_output(encrypted_shellcode, args.format)
            print_output(output, args.format)
            

       
        
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()








