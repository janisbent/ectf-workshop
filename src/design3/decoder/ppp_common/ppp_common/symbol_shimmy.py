"""
@file symbol_shimmy.py
@brief Shuffle binary symbols to discourage return-oriented programming
@author Plaid Parliament of Pwning
@copyright Copyright (c) 2025 Carnegie Mellon University
"""

# The Symbol Shimmy
# Protect against ROP by randomizing the order of symbols within the binary at link time!
# Requires -ffunction-sections

from .gen_secrets import GlobalSecrets

from elftools.elf.elffile import ELFFile
import argparse
from string import Template
import random


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", required=True)
    parser.add_argument("--secrets", required=True)
    parser.add_argument("--id", type=lambda x: int(x, 0), required=True)
    parser.add_argument("objects", nargs="+")

    args = parser.parse_args()

    # Seed PRNG - not a cryptographically secure PRNG but that doesn't matter since
    # revealing the seed does not do anything useful
    with open(args.secrets, "rb") as f:
        rng = random.Random(
            GlobalSecrets.deserialize(f.read()).symbol_shimmy_seed(args.id)
        )

    with open(args.template, "r") as f:
        template = Template(f.read())

    # Always include the regular text section in there somewhere just in case
    text_syms = [".text"]
    for obj in args.objects:
        with open(obj, "rb") as f:
            elf = ELFFile(f)
            text_syms.extend(
                x.name for x in elf.iter_sections() if x.name.startswith(".text.")
            )

    rng.shuffle(text_syms)

    commands = "\n".join(f"*({x})" for x in text_syms)

    print(template.substitute(TEXT_SECTIONS=commands))


if __name__ == "__main__":
    main()
