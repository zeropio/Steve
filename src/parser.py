import lief
import tabulate
from pwn import log

def elf_search(path, size, hexcode):
    try:
        binary = lief.parse(path)
    except lief.bad_format as e:
        log.error(f"Error accessing PE file: {e}")
        return 1

    code_caves = []
    for section in binary.sections:
        # Check if the section is executable
        if str(section.type) == 'SECTION_TYPES.PROGBITS' and section.flags == 6:
            cave_start = None
            for i, byte in enumerate(section.content):
                if byte == hexcode:
                    if cave_start is None:
                        cave_start = section.virtual_address + i
                elif cave_start is not None:
                    cave_size = section.virtual_address + i - cave_start
                    if cave_size >= int(size):
                        code_caves.append({
                            "Index": len(code_caves) + 1,
                            "Section": section.name,
                            "Address": f"0x{cave_start:X}",
                            "Size": cave_size
                        })

                    cave_start = None

    if code_caves:
        log.success(f"Number of code caves found: {len(code_caves)}")
        print(tabulate.tabulate(code_caves, headers="keys", tablefmt="pretty"))
    else:
        log.warning("No code caves found")

def pe_search(path, size, hexcode):
    try:
        binary = lief.parse(path)
    except lief.bad_format as e:
        log.error(f"Error accessing PE file: {e}")
        return 1

    code_caves = []
    for section in binary.sections:
        # Check if the section is executable
        if section.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE:
            cave_start = None
            for i, byte in enumerate(section.content):
                if byte == hexcode:
                    if cave_start is None:
                        cave_start = section.virtual_address + i
                elif cave_start is not None:
                    cave_size = section.virtual_address + i - cave_start
                    if cave_size >= int(size):
                        code_caves.append({
                            "Index": len(code_caves) + 1,
                            "Section": section.name,
                            "Characteristics": hex(section.characteristics),
                            "Address": f"0x{cave_start:X}",
                            "Size": cave_size
                        })

                    cave_start = None

    if code_caves:
        log.success(f"Number of code caves found: {len(code_caves)}")
        print(tabulate.tabulate(code_caves, headers="keys", tablefmt="pretty"))
    else:
        log.warning("No code caves found")

def macho_search(path, size, hexcode):
    try:
        binary = lief.parse(path)
    except lief.bad_format as e:
        log.error(f"Error accessing Mach-O file: {e}")
        return 1

    code_caves = []
    for cmd in binary.commands:
        if isinstance(cmd, lief.MachO.SegmentCommand):
            for section in cmd.sections:
                # Check if the section is executable, flags: SOME_INSTRUCTIONS and PURE_INSTRUCTIONS
                if section.flags == 2147484672:
                    cave_start = None
                    for i, byte in enumerate(section.content):
                        if byte == hexcode:
                            if cave_start is None:
                                cave_start = section.virtual_address + i
                        elif cave_start is not None:
                            cave_size = section.virtual_address + i - cave_start
                            if cave_size >= int(size):
                                code_caves.append({
                                    "Index": len(code_caves) + 1,
                                    "Segment": cmd.name,
                                    "Section": section.name,
                                    "Address": f"0x{cave_start:X}",
                                    "Size": cave_size
                                })

                            cave_start = None
    if code_caves:
        log.success(f"Number of code caves found: {len(code_caves)}")
        print(tabulate.tabulate(code_caves, headers="keys", tablefmt="pretty"))
    else:
        log.warning("No code caves found")
