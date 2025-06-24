"""
@file gen_secrets_c.py
@brief Generate secrets C file to be included in compilation
@author Plaid Parliament of Pwning
@copyright Copyright (c) 2025 Carnegie Mellon University
"""

from .gen_secrets import GlobalSecrets

import argparse
from pathlib import Path


# Format key to be written to the header file according to our style and C syntax
def convert_to_byte_arr(key: bytes):
    result = []
    hex_bytes = [f"0x{byte:02X}" for byte in key]

    for i in range(0, len(hex_bytes), 16):
        line = "    " + ", ".join(hex_bytes[i : i + 16])
        if i + 16 < len(hex_bytes):
            line += ","
        result.append(line)

    return f"{{\n{'\n'.join(result)}}}"


def generate(secrets_file: Path, header_file: Path, decoder_id: int):
    with open(secrets_file, "rb") as f:
        serialized_secrets = f.read()

    global_secrets = GlobalSecrets.deserialize(serialized_secrets)

    enc_public_key = global_secrets.enc_public_key
    id_key = global_secrets.derive_id_key(decoder_id)
    left_tree_key = global_secrets.left_tree_key
    right_tree_key = global_secrets.right_tree_key

    with open(header_file, "w") as f:
        f.write(f"""\
/**
 * @file secrets.h
 * @author Plaid Parliament of Pwning
 * @brief Provides keys required by the decoder, regenerated during build
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "secrets.h"

#include "crypto_wrappers.h"
#include <stdint.h>

const uint8_t ENCODER_PUBLIC_KEY[PUBLIC_KEY_LEN] = {convert_to_byte_arr(enc_public_key)};

const uint8_t ID_KEY[SYMMETRIC_KEY_LEN] = {convert_to_byte_arr(id_key)};

const uint8_t LEFT_TREE_KEY[SYMMETRIC_KEY_LEN] = {convert_to_byte_arr(left_tree_key)};

const uint8_t RIGHT_TREE_KEY[SYMMETRIC_KEY_LEN] = {convert_to_byte_arr(right_tree_key)};
""")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file",
    )
    parser.add_argument(
        "header_file",
        type=Path,
        help="Path to the secrets C file to be created",
    )
    parser.add_argument(
        "decoder_id",
        type=lambda x: int(x, 0),  # To accept hex/decimal (might be unnecessary)
        help="Decoder ID to be used in creating id key",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    generate(args.secrets_file, args.header_file, args.decoder_id)


if __name__ == "__main__":
    main()
