"""
@file crypto_wrappers.py
@brief Crypto wrappers over Monocypher
@author Plaid Parliament of Pwning
@copyright Copyright (c) 2025 Carnegie Mellon University
"""

from .cstruct import cstruct

import monocypher
import struct

SYMMETRIC_KEY_LEN = 32
SYMMETRIC_NONCE_LEN = 24
SYMMETRIC_MAC_LEN = 16
SYMMETRIC_METADATA_LEN = SYMMETRIC_NONCE_LEN + SYMMETRIC_MAC_LEN

TREE_KEY_LEN = 16
TREE_LEFT_RIGHT_LEN = 32

PUBLIC_KEY_LEN = 64
PRIVATE_KEY_LEN = 64
SIGNATURE_LEN = 64


# Ciphertext will be length+SYMMETRIC_METADATA_LEN bytes long
# Provides authenticated encryption (any tampering will be detected upon decrypt)
# Tend to match the crypto_wrapper.c
def encrypt_symmetric(plaintext: bytes, sym_key: bytes) -> bytes:
    assert len(sym_key) == SYMMETRIC_KEY_LEN

    nonce = monocypher.generate_key(SYMMETRIC_NONCE_LEN)
    mac, ct = monocypher.lock(sym_key, nonce, plaintext)
    ciphertext = mac + nonce + ct

    assert len(ciphertext) == len(plaintext) + SYMMETRIC_METADATA_LEN
    return ciphertext


def sign_asymmetric(message: bytes, secret_key: bytes) -> bytes:
    assert len(secret_key) == PRIVATE_KEY_LEN

    out = monocypher.signature_sign(secret_key, message)

    assert len(out) == SIGNATURE_LEN
    return out


def hash_length(message: bytes, hash_size: int = 64) -> bytes:
    state = monocypher.Blake2b(hash_size=hash_size)
    state.update(message)
    hash = state.finalize()

    assert len(hash) == hash_size
    return hash


# match: crypto_wrappers.c -> kdf_tree_child() -> tmp
class TreeChildTmp(metaclass=cstruct):
    parent: bytes = f"{TREE_KEY_LEN}s"
    left_right: bytes = f"{TREE_LEFT_RIGHT_LEN}s"


def kdf_tree_child(parent_key: bytes, left_right: bytes) -> bytes:
    assert len(parent_key) == TREE_KEY_LEN
    assert len(left_right) == TREE_LEFT_RIGHT_LEN

    packed = TreeChildTmp(parent_key, left_right).pack()

    child_key = hash_length(packed, TREE_KEY_LEN)

    assert len(child_key) == TREE_KEY_LEN
    return child_key


def kdf_tree_leaf(leaf_key: bytes) -> bytes:
    assert len(leaf_key) == TREE_KEY_LEN

    frame_key = hash_length(leaf_key, SYMMETRIC_KEY_LEN)

    assert len(frame_key) == SYMMETRIC_KEY_LEN
    return frame_key


def kdf_id(id_root_key: bytes, decoder_id: int) -> bytes:
    assert len(id_root_key) == SYMMETRIC_KEY_LEN
    assert 0 <= decoder_id < 2**32

    packed = struct.pack("<I32s", decoder_id, id_root_key)

    key = hash_length(packed, SYMMETRIC_KEY_LEN)

    assert len(key) == SYMMETRIC_KEY_LEN
    return key


def kdf_symbol_shimmy(shimmy_root_key: bytes, decoder_id: int) -> bytes:
    # This happens to use the same operation so we can avoid repeating
    return kdf_id(shimmy_root_key, decoder_id)
