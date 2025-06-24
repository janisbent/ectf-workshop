"""
@file cstruct.py
@brief Helper for creating structs for C
@author Plaid Parliament of Pwning
@copyright Copyright (c) 2025 Carnegie Mellon University
"""

import struct
from typing import NamedTuple


def cstruct(clsname, base, attrs, endianness="<"):
    """
    Helper metaclass for creating auditable C structs from Python.

    To use, set this function as the metaclass for a class definition, then add fields like you
    would for a `dataclass` but assigning them their type from the `struct` library:
    ```
    class SomeStruct(metaclass=cstruct, endianness="<"): # default endianness is "<"
        first_field: int = "i"
        unsigned: int = "I"
        some_data: bytes = "123s"
    ```
    Then create the object like a tuple: `x = SomeStruct(-123, 456, b"asdf")` (can also field names)
    and pack it with `x.pack()`. Unpack from bytes with `y = SomeStruct.unpack(packed_bytes)`.
    Also adds a class property `SomeStruct.size`.
    """
    # create NamedTuple
    ann = attrs.get("__annotations__", {})
    tup = NamedTuple(
        clsname + "_super",
        [(attr, ann.get(attr)) for attr in attrs if not attr.startswith("_")],
    )

    st = struct.Struct(
        endianness + "".join(v for k, v in attrs.items() if not k.startswith("_"))
    )

    # subclass our NamedTuple
    return type(
        clsname,
        (tup,),
        {
            "_struct": st,
            "pack": lambda self: st.pack(*self),
            "unpack": classmethod(lambda cls, buf: cls(*st.unpack(buf))),
            "size": st.size,
        },
    )
