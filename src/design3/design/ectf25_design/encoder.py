"""
@file encoder.py
@brief Encode frames for the Decoder
@author Plaid Parliament of Pwning
@copyright Copyright (c) 2025 Carnegie Mellon University
"""

from ppp_common.cstruct import cstruct
from ppp_common.crypto_wrappers import (
    sign_asymmetric,
    encrypt_symmetric,
    kdf_tree_leaf,
    SYMMETRIC_METADATA_LEN,
    SIGNATURE_LEN,
)
from ppp_common.gen_secrets import GlobalSecrets, Vertex

from loguru import logger

MAX_FRAME_SIZE = 64


# match: frame.h -> frame_data_t
class FrameData(metaclass=cstruct):
    length: int = "I"
    frame: bytes = f"{MAX_FRAME_SIZE}s"


assert FrameData.size == 68


# match: frame.h -> frame_ch_t
class FrameCh(metaclass=cstruct):
    timestamp: int = "Q"
    ciphertext: bytes = f"{SYMMETRIC_METADATA_LEN + FrameData.size}s"
    padding: bytes = "4s"


assert FrameCh.size == 120


# match: frame.h -> frame_packet_t -> payload
class FramePacketPayload(metaclass=cstruct):
    channel_id: int = "I"
    enc_frame: bytes = f"{SYMMETRIC_METADATA_LEN + FrameCh.size}s"


assert FramePacketPayload.size == 164


# match: frame.h -> frame_packet_t
class FramePacket(metaclass=cstruct):
    payload: bytes = f"{FramePacketPayload.size}s"
    signature: bytes = f"{SIGNATURE_LEN}s"


assert FramePacket.size == 228


class Encoder:
    def __init__(self, secrets: bytes):
        self.keys = GlobalSecrets.deserialize(secrets)
        self.channel_keys = self.keys.channel_keys
        self.enc_private_key = self.keys.enc_private_key

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        if channel not in self.channel_keys:
            logger.error(f"Channel {channel} Not Defined\n")
            return b""

        # frame := len || F   (4 + 64 = 68 bytes)
        frame_data = FrameData(len(frame), frame).pack()

        # enc_frame := { frame }_ktree  (68 + 40 = 108 bytes)

        # create vertex with prefix as the timestamp of frame bits is 64
        frame_vertex = Vertex(prefix=timestamp, bits=64)

        ktree = kdf_tree_leaf(self.keys.derive_tree_key(channel, frame_vertex))

        enc_frame = encrypt_symmetric(frame_data, ktree)

        # timestamped_frame := t || enc_frame || padding (8 + 108 + 4 = 120 bytes)
        timestamped_frame = FrameCh(timestamp, enc_frame, b"").pack()

        # enc_timestamp := { timestamped_frame }_kch (120 + 40 = 160 bytes)
        enc_timestamp = encrypt_symmetric(timestamped_frame, self.channel_keys[channel])

        # message := ch || enc_timestamp || { ch || enc_timestamp }_k_e^-1 (4 + 160 + 64 = 228 bytes)
        ch_enc_timestamp = FramePacketPayload(channel, enc_timestamp).pack()
        signature = sign_asymmetric(ch_enc_timestamp, self.keys.enc_private_key)

        return FramePacket(ch_enc_timestamp, signature).pack()
