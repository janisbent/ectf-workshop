"""
@file gen_secrets.py
@brief Generate secrets for a deployment
@author Plaid Parliament of Pwning
@copyright Copyright (c) 2025 Carnegie Mellon University
"""

from .crypto_wrappers import (
    kdf_tree_child,
    kdf_id,
    kdf_symbol_shimmy,
    TREE_KEY_LEN,
    TREE_LEFT_RIGHT_LEN,
    SYMMETRIC_KEY_LEN,
)

import monocypher
import argparse
import json
import base64
from pathlib import Path
from dataclasses import dataclass
from typing import Self


def to_base64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def from_base64(s: str) -> bytes:
    return base64.b64decode(s)


@dataclass
class Vertex:
    prefix: int
    bits: int

    def __init__(self, prefix: int, bits: int):
        self.prefix = prefix
        self.bits = bits
        assert 0 <= self.prefix < (1 << self.bits)


@dataclass
class GlobalSecrets:
    enc_private_key: bytes
    enc_public_key: bytes
    id_root_key: bytes
    channel_keys: dict[int, bytes]
    left_tree_key: bytes
    right_tree_key: bytes
    tree_root_keys: dict[int, bytes]
    symbol_shimmy_root_key: bytes

    @classmethod
    def generate(cls, channels: list[int]) -> Self:
        enc_private_key, enc_public_key = monocypher.generate_signing_key_pair()

        channel_keys = {
            ch: monocypher.generate_key(SYMMETRIC_KEY_LEN) for ch in channels + [0]
        }

        tree_root_keys = {
            ch: monocypher.generate_key(TREE_KEY_LEN) for ch in channels + [0]
        }

        return cls(
            enc_private_key=enc_private_key,
            enc_public_key=enc_public_key,
            id_root_key=monocypher.generate_key(SYMMETRIC_KEY_LEN),
            channel_keys=channel_keys,
            left_tree_key=monocypher.generate_key(TREE_LEFT_RIGHT_LEN),
            right_tree_key=monocypher.generate_key(TREE_LEFT_RIGHT_LEN),
            tree_root_keys=tree_root_keys,
            symbol_shimmy_root_key=monocypher.generate_key(SYMMETRIC_KEY_LEN),
        )

    def serialize(self) -> bytes:
        channel_keys = {ch: to_base64(k) for ch, k in self.channel_keys.items()}

        tree_root_keys = {ch: to_base64(k) for ch, k in self.tree_root_keys.items()}

        secrets = {
            "ENCODER_PRIVATE_KEY": to_base64(self.enc_private_key),
            "ENCODER_PUBLIC_KEY": to_base64(self.enc_public_key),
            "ID_ROOT_KEY": to_base64(self.id_root_key),
            "CHANNEL_KEYS": channel_keys,
            "LEFT_TREE_KEY": to_base64(self.left_tree_key),
            "RIGHT_TREE_KEY": to_base64(self.right_tree_key),
            "TREE_ROOT_KEYS": tree_root_keys,
            "SYMBOL_SHIMMY_ROOT_KEY": to_base64(self.symbol_shimmy_root_key),
        }

        return json.dumps(secrets).encode("ascii")

    @classmethod
    def deserialize(cls, b: bytes) -> Self:
        secrets = json.loads(b.decode("ascii"))

        channel_keys = {
            int(ch): from_base64(k) for ch, k in secrets["CHANNEL_KEYS"].items()
        }

        tree_root_keys = {
            int(ch): from_base64(k) for ch, k in secrets["TREE_ROOT_KEYS"].items()
        }

        return cls(
            from_base64(secrets["ENCODER_PRIVATE_KEY"]),
            from_base64(secrets["ENCODER_PUBLIC_KEY"]),
            from_base64(secrets["ID_ROOT_KEY"]),
            channel_keys,
            from_base64(secrets["LEFT_TREE_KEY"]),
            from_base64(secrets["RIGHT_TREE_KEY"]),
            tree_root_keys,
            from_base64(secrets["SYMBOL_SHIMMY_ROOT_KEY"]),
        )

    def derive_id_key(self, device_id: int) -> bytes:
        assert 0 <= device_id < 2**32

        return kdf_id(self.id_root_key, device_id)

    def derive_tree_key(self, ch: int, vertex: Vertex) -> bytes:
        assert 0 <= ch < 2**32
        assert vertex.bits >= 0
        assert 0 <= vertex.prefix < (1 << vertex.bits)

        root_key = self.tree_root_keys.get(ch)
        left_tree_key = self.left_tree_key
        right_tree_key = self.right_tree_key

        assert root_key is not None
        assert left_tree_key is not None
        assert right_tree_key is not None

        key = root_key

        if vertex.bits == 0:
            return key

        bitmask = 1 << (vertex.bits - 1)

        for _ in range(vertex.bits):
            curr_direction = vertex.prefix & bitmask
            if curr_direction == 0:
                key = kdf_tree_child(key, left_tree_key)
            else:
                key = kdf_tree_child(key, right_tree_key)
            bitmask >>= 1

        return key

    def symbol_shimmy_seed(self, id: int) -> bytes:
        return kdf_symbol_shimmy(self.symbol_shimmy_root_key, id)


def gen_secrets(channels: list[int]) -> bytes:
    secrets = GlobalSecrets.generate(channels)
    return secrets.serialize()


# Everything below this line is taken from the insecure example
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    secrets = gen_secrets(args.channels)

    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)


if __name__ == "__main__":
    main()
