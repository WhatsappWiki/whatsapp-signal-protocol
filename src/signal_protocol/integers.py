"""Java int32 arithmetic with natural uint32 public/wire representations."""

import operator


def uint32(value):
    return operator.index(value) & 0xFFFFFFFF


def int32(value):
    value = uint32(value)
    return value if value < 0x80000000 else value - 0x100000000
