import lief

def elf_search(path, size, hexcode):
    try:
        binary = lief.parse(path)
    except lief.bad_format as e:
        return f"Error accessing PE file: {e}"

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
                        print(f"Potential Code Cave:")
                        print(f"Section: {section.name}")
                        print(f"Address: {hex(cave_start)}")
                        print(f"Size: {cave_size} (unused space)\n")

                    cave_start = None

def pe_search(path, size, hexcode):
    try:
        binary = lief.parse(path)
    except lief.bad_format as e:
        return f"Error accessing PE file: {e}"

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
                        print(f"Potential Code Cave:")
                        print(f"Section: {section.name}")
                        print(f"Characteristics: {hex(section.characteristics)}")
                        print(f"Address: {hex(cave_start)}")
                        print(f"Size: {cave_size} (unused space)\n")

                    cave_start = None

def macho_search(path, size, hexcode):
    try:
        binary = lief.parse(path)
    except lief.bad_format as e:
        return f"Error accessing Mach-O file: {e}"

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
                                print(f"Potential Code Cave:")
                                print(f"Segment: {cmd.name}")
                                print(f"Section: {section.name}")
                                print(f"Address: 0x{cave_start:X}")
                                print(f"Size: {cave_size} (unused space)\n")

                            cave_start = None
