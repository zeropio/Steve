# Steve - Code Cave Miner

Steve is a simple code cave miner that detects potential code caves in PE, ELF, and Mach-O executable files.

## Features

- Detects code caves in PE, ELF, and Mach-O binaries.
- Supports user-defined minimum code cave size and hexcode pattern.
- Provides detailed information about each code cave, including section/segment details, characteristics, address, and size.

## Usage

### Requirements

- Python 3.x
- [LIEF](https://github.com/lief-project/LIEF)
- Pwntools and tabulate (are only used for formatting text)

### Usage

```bash
git clone https://github.com/zeropio/steve.git
cd steve
python src/main.py -b /path/to/binary
```

### Command-line Options

- `-b` or `--binary`: Path to the binary file.
- `-s` or `--size`: Code cave minimum size. Default: 50 bytes.
- `-hc` or `--hexcode`: Hexcode to search. Default: 00.

### Examples

```bash
python src/main.py -b /path/to/binary
python src/main.py -b /path/to/binary -s 100 -hc 90
```

### Supported Formats

- PE (Windows Executable)
- ELF (Executable and Linkable Format)
- Mach-O (Mach Object)

# Contributing

Feel free to open an issue or submit a pull request to contribute to the development of Steve. Contributions are welcome!
