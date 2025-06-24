"""
@file gen_subscription.py
@brief Generate a subscription for a device
@author Plaid Parliament of Pwning
@copyright Copyright (c) 2025 Carnegie Mellon University
"""

from .cstruct import cstruct
from .crypto_wrappers import (
    encrypt_symmetric,
    sign_asymmetric,
    TREE_KEY_LEN,
    SYMMETRIC_KEY_LEN,
    SYMMETRIC_METADATA_LEN,
    SIGNATURE_LEN,
)
from .gen_secrets import GlobalSecrets, Vertex

import argparse
from pathlib import Path


SUBSCRIPTION_MAGIC = 0x41594E42  # BNYA

MAX_TREE_KEYS = 126


# match: subscription.h -> valid_subscription_t
class ValidSubscription(metaclass=cstruct):
    ktree: bytes = f"{MAX_TREE_KEYS * TREE_KEY_LEN}s"
    kch: bytes = f"{SYMMETRIC_KEY_LEN}s"
    start: int = "Q"
    end: int = "Q"
    channel: int = "I"
    key_count: int = "I"
    magic: int = "I"
    pad: bytes = "4s"


assert ValidSubscription.size == 2080


# match subscription.h -> subscription_update_t -> payload
class SubscriptionUpdatePayload(metaclass=cstruct):
    id: int = "I"
    ciphertext: bytes = f"{SYMMETRIC_METADATA_LEN + ValidSubscription.size}s"


assert SubscriptionUpdatePayload.size == 2124


# match subscription.c -> subscription_update_t
class SubscriptionUpdate(metaclass=cstruct):
    payload: bytes = f"{SubscriptionUpdatePayload.size}s"
    sig: bytes = f"{SIGNATURE_LEN}s"


assert SubscriptionUpdate.size == 2188


def vertices_for_range(start: int, end: int) -> list[Vertex]:
    keys_front = []
    keys_back = []
    bits = 64
    while start != end:
        assert start < end
        if start & 1 == 0 and end & 1 == 1:
            # We can move up a level
            start >>= 1
            end >>= 1
            bits -= 1
        elif start & 1 == 1:
            # start cannot be contracted, package it
            keys_front.append(Vertex(start, bits))
            start += 1
        else:  # end & 1 == 0
            # end cannot be contracted, package it
            keys_back.append(Vertex(end, bits))
            end -= 1

    return keys_front + [Vertex(start, bits)] + keys_back[::-1]


def gen_embeddable_subscription(
    secrets: bytes, device_id: int, start: int, end: int, channel: int
) -> bytes:
    """
    Generate a subscription that can be directly placed in flash
    """
    # Deserialize the contents of the secrets file + create the instance of GlobalSecrets
    secrets = GlobalSecrets.deserialize(secrets)

    # Utilize kch from the secrets file for the given channel number
    kch = secrets.channel_keys[channel]

    vertices = vertices_for_range(start, end)
    ktree = b""
    for v in vertices:
        ktree += secrets.derive_tree_key(channel, v)

    assert len(ktree) == len(vertices) * TREE_KEY_LEN

    valid_subscription = ValidSubscription(
        ktree=ktree,
        kch=kch,
        start=start,
        end=end,
        channel=channel,
        key_count=len(vertices),
        magic=SUBSCRIPTION_MAGIC,
        pad=b"",
    )

    return valid_subscription.pack()


def gen_subscription(
    secrets: bytes, device_id: int, start: int, end: int, channel: int
) -> bytes:
    """
    Generate subscription packages
    Definition inspired by the MITRE example
    """
    valid_subscription = gen_embeddable_subscription(
        secrets, device_id, start, end, channel
    )

    # Deserialize the contents of the secrets file + create the instance of GlobalSecrets
    secrets = GlobalSecrets.deserialize(secrets)

    # Derive the kid using KDF(id || Sid)
    kid = secrets.derive_id_key(device_id=device_id)

    # Encrypt the plaintext subscription blob with kid (2120 bytes)
    # mac (16 bytes) || nonce (24 bytes) || valid_subscription (2080 bytes)
    encrypted_subscription = encrypt_symmetric(valid_subscription, kid)

    # Concat the id and ciphertext to create the signature: (2124 bytes in len)
    # id (4 bytes) || ciphertext (2120 bytes)
    subscription_to_sign = SubscriptionUpdatePayload(
        id=device_id, ciphertext=encrypted_subscription
    ).pack()

    # Create signature using Ke-1 will always be 64 bytes
    ke_sig = sign_asymmetric(subscription_to_sign, secrets.enc_private_key)

    packed_subscription = SubscriptionUpdate(
        payload=subscription_to_sign, sig=ke_sig
    ).pack()

    return packed_subscription


# Everything below this line is taken from the insecure example


def parse_args():
    """
    Argument parser inspired by MITRE example
    and not modified , as provided in the NOTE
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of subscription file, overwriting existing file",
    )
    parser.add_argument(
        "--embeddable",
        action="store_true",
        help="Generate a subscription file that can be placed in flash",
    )
    parser.add_argument(
        "secrets_file",
        type=argparse.FileType("rb"),
        help="Path to the secrets file created by ectf25_design.gen_secrets",
    )
    parser.add_argument("subscription_file", type=Path, help="Subscription output")
    parser.add_argument(
        "device_id", type=lambda x: int(x, 0), help="Device ID of the update recipient."
    )
    parser.add_argument(
        "start", type=lambda x: int(x, 0), help="Subscription start timestamp"
    )
    parser.add_argument(
        "end", type=lambda x: int(x, 0), help="Subscription end timestamp"
    )
    parser.add_argument("channel", type=int, help="Channel to subscribe to")
    return parser.parse_args()


def main():
    """
    Main function
    """
    # Parsing the command line arguments
    args = parse_args()

    if args.embeddable:
        subscription = gen_embeddable_subscription(
            args.secrets_file.read(), args.device_id, args.start, args.end, args.channel
        )
    else:
        subscription = gen_subscription(
            args.secrets_file.read(), args.device_id, args.start, args.end, args.channel
        )

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)


if __name__ == "__main__":
    main()
