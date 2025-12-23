# 0xjam3z-scanner

CLI wrapper around masscan + zgrab2 for scanning IPv4 ranges and extracting HTTP titles. It mirrors the workflow in the original `scanner.sh` script while keeping everything inside this folder.

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Usage

```bash
./build/0xjam3z-scanner <ip|cidr|range|list|country_asn.json> [options]
```

Examples:

```bash
./build/0xjam3z-scanner 1.2.3.4
./build/0xjam3z-scanner 1.2.3.0/24
./build/0xjam3z-scanner 1.2.3.4-1.2.3.250
./build/0xjam3z-scanner country_asn.json
./build/0xjam3z-scanner country_asn.json --country "United States"
./build/0xjam3z-scanner my_list.txt --list
```

Options:
- `--ports <list>` ports to scan (default: `80,443`)
- `--rate <n>` masscan rate (default: `10000`)
- `--no-download` do not auto-download/build tools
- `--output <file>` output file for titles (default: `opendomains`)
- `--list` treat input as a pre-built masscan list file
- `--country <name>` filter `country_name` when parsing `country_asn.json`

## Tooling

If `masscan` or `zgrab2` are not found on your PATH, the CLI will clone and build them into:

- `./third_party/masscan`
- `./third_party/zgrab2`

Built binaries are placed in `./bin` and used automatically.

### Windows note

`masscan` requires a Windows build toolchain. The CLI will clone the repo but you must build it manually and place the resulting `masscan.exe` in `./bin`.
