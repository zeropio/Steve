import argparse
from parser import *

def main():
    size = 50 # default bytes
    hexcode = 00 # default hexcode

    parser = argparse.ArgumentParser(description='State of Art Code Cave Miner')
    parser.add_argument('-b', "--binary", help='Path to the binary file')
    parser.add_argument('-s', "--size", help='Code cave minimum size. Default: 50 bytes')
    parser.add_argument('-hc', "--hexcode", help='Hexcode to search. Default: 00')

    args = parser.parse_args()
    path = args.binary
    user_size = args.size
    user_hexcode = args.hexcode

    if user_size:
        size = user_size

    if user_hexcode:
        hexcode = int(user_hexcode, 16)
    
    if path:
        with open(path, "rb") as binary:
            header = binary.read(4)

            # ELF magic number
            if header.startswith(b'\x7FELF'):
                elf_search(path, size, hexcode)

            # PE magic number
            elif header.startswith(b'MZ'):
                pe_search(path, size, hexcode)

            # Mach-O magic number
            elif header in [b'\xFE\xED\xFA\xCE', b'\xCE\xFA\xED\xFE', b'\xFE\xED\xFA\xCF', b'\xCF\xFA\xED\xFE']:
                macho_search(path, size, hexcode)

            else:
                print('Unknown')

if __name__ == "__main__":
    main()
