#!/usr/bin/python3

""" pycave.py: Dirty code to find code caves in Portable Executable files"""

__author__ = 'axcheron'
__license__ = 'Apache 2'
__version__ = '0.2'  # :)

import argparse
import pefile
import sys


def pycave(file_name: str, cave_size: int, base: str) -> None:
    image_base = int(base, 16)
    min_cave = cave_size

    try:
        pe = pefile.PE(file_name)
    except (IOError, pefile.PEFormatError) as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

    print(f"[+] Minimum code cave size: {min_cave}")
    print(f"[+] Image Base:  0x{image_base:08X}")
    print(f"[+] Loading \"{file_name}\"...")

    if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:  # is aslr
        print("\n[!] ASLR is enabled. Virtual Address (VA) could be different once loaded in memory.")

    with open(file_name, "rb") as file:
        print("\n[+] Looking for code caves...")
        for section in pe.sections:
            if section.SizeOfRawData == 0:
                continue

            file.seek(section.PointerToRawData)
            data = file.read(section.SizeOfRawData)

            count = 0
            for pos, byte in enumerate(data):
                if byte == 0x00:
                    count += 1
                else:
                    if count >= min_cave:
                        raw_addr = section.PointerToRawData + pos - count
                        vir_addr = image_base + section.VirtualAddress + pos - count
                        print(f"[+] Code cave found in {section.Name.decode().strip()} \tSize: {count} bytes \tRA: 0x{raw_addr:08X} \tVA: 0x{vir_addr:08X}")
                    count = 0

    pe.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find code caves in PE files")

    parser.add_argument("-f", "--file", dest="file_name", required=True, help="PE file", type=str)
    parser.add_argument("-s", "--size", dest="size", default=300, help="Min. cave size", type=int)
    parser.add_argument("-b", "--base", dest="base", default="0x00400000", help="Image base", type=str)

    args = parser.parse_args()

    pycave(args.file_name, args.size, args.base)
