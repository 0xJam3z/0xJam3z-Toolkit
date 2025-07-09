#!/usr/bin/env python3
"""
Generate simple username permutations from a file of full names.

Examples (input line:  "James Ross")
  James
  Ross
  James.Ross
  Ross.James
  jross
  j.ross

Usage:
    python myscript.py users.txt
Creates:
    users_permutation.txt    # in the same directory as users.txt
"""

import sys
from pathlib import Path

def make_permutations(first: str, last: str) -> list[str]:
    """Return the six permutations you requested, preserving / lowering case as shown."""
    return [
        first,
        last,
        f"{first}.{last}",
        f"{last}.{first}",
        f"{first[0].lower()}{last.lower()}",
        f"{first[0].lower()}.{last.lower()}",
    ]

def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {Path(sys.argv[0]).name} <names_file>")

    in_path  = Path(sys.argv[1]).expanduser()
    if not in_path.is_file():
        sys.exit(f"[!] File not found: {in_path}")

    out_path = in_path.with_name(f"{in_path.stem}_permutation{in_path.suffix}")

    permutations: list[str] = []
    with in_path.open(encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 2:                     # skip lines without at least first & last
                continue
            first, last = parts[0], parts[-1]      # ignore any middle names
            permutations.extend(make_permutations(first, last))

    # Remove exact duplicates while preserving original order
    seen = set()
    unique_perms = [p for p in permutations if not (p in seen or seen.add(p))]

    out_path.write_text("\n".join(unique_perms) + "\n", encoding="utf-8")
    print(f"[+] Wrote {len(unique_perms)} usernames to {out_path}")

if __name__ == "__main__":
    main()
