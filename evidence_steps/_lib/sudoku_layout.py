from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable


_POPCOUNT = [bin(i).count("1") for i in range(256)]


def popcount8(b: int) -> int:
    return _POPCOUNT[b & 0xFF]


@dataclass(frozen=True)
class Layout:
    name: str
    hint_mask: int
    hint_value: int
    padding_pool: bytes
    encode_hint: Callable[[int, int], int]
    encode_group: Callable[[int], int]
    decode_group: Callable[[int], tuple[int, bool]]

    def is_hint(self, b: int) -> bool:
        b &= 0xFF
        if (b & self.hint_mask) == self.hint_value:
            return True
        # prefer_ascii mode: '\n' is an on-wire alias for 0x7F.
        return self.name == "ascii" and b == 0x0A

    def hint_bytes(self) -> set[int]:
        out: set[int] = set()
        for v in range(4):
            for p in range(16):
                out.add(self.encode_hint(v, p) & 0xFF)
        return out

    def padding_bytes(self) -> set[int]:
        return {b & 0xFF for b in self.padding_pool}


def layout_ascii() -> Layout:
    padding = bytes(0x20 + i for i in range(32))

    def encode_hint(value2b: int, pos4b: int) -> int:
        b = 0x40 | ((value2b & 0x03) << 4) | (pos4b & 0x0F)
        return 0x0A if b == 0x7F else b

    def encode_group(group6b: int) -> int:
        b = 0x40 | (group6b & 0x3F)
        return 0x0A if b == 0x7F else b

    def decode_group(b: int) -> tuple[int, bool]:
        b &= 0xFF
        if b == 0x0A:
            return 0x3F, True
        if (b & 0x40) == 0:
            return 0, False
        return b & 0x3F, True

    return Layout(
        name="ascii",
        hint_mask=0x40,
        hint_value=0x40,
        padding_pool=padding,
        encode_hint=encode_hint,
        encode_group=encode_group,
        decode_group=decode_group,
    )


def layout_entropy() -> Layout:
    padding: list[int] = []
    for i in range(8):
        padding.append(0x80 + i)
        padding.append(0x10 + i)
    padding_bytes = bytes(padding)

    def encode_hint(value2b: int, pos4b: int) -> int:
        return ((value2b & 0x03) << 5) | (pos4b & 0x0F)

    def encode_group(group6b: int) -> int:
        v = group6b & 0x3F
        return ((v & 0x30) << 1) | (v & 0x0F)

    def decode_group(b: int) -> tuple[int, bool]:
        b &= 0xFF
        if (b & 0x90) != 0:
            return 0, False
        return ((b >> 1) & 0x30) | (b & 0x0F), True

    return Layout(
        name="entropy",
        hint_mask=0x90,
        hint_value=0x00,
        padding_pool=padding_bytes,
        encode_hint=encode_hint,
        encode_group=encode_group,
        decode_group=decode_group,
    )


def layout_custom(pattern: str) -> Layout:
    cleaned = "".join(pattern.strip().lower().split())
    if len(cleaned) != 8:
        raise ValueError(f"custom table must have 8 symbols, got {len(cleaned)}")

    x_bits: list[int] = []
    p_bits: list[int] = []
    v_bits: list[int] = []
    for i, c in enumerate(cleaned):
        bit = 7 - i
        if c == "x":
            x_bits.append(bit)
        elif c == "p":
            p_bits.append(bit)
        elif c == "v":
            v_bits.append(bit)
        else:
            raise ValueError(f"invalid char {c!r} in custom table")
    if len(x_bits) != 2 or len(p_bits) != 4 or len(v_bits) != 2:
        raise ValueError("custom table must contain exactly 2 x, 4 p, 2 v")

    x_mask = 0
    for b in x_bits:
        x_mask |= 1 << b

    def encode_bits(value2b: int, pos4b: int, drop_x: int) -> int:
        out = x_mask
        if drop_x >= 0:
            out &= ~(1 << x_bits[drop_x])
        for i, bit in enumerate(p_bits):
            if ((pos4b >> (3 - i)) & 0x01) == 1:
                out |= 1 << bit
        if (value2b & 0x02) != 0:
            out |= 1 << v_bits[0]
        if (value2b & 0x01) != 0:
            out |= 1 << v_bits[1]
        return out & 0xFF

    def encode_hint(value2b: int, pos4b: int) -> int:
        return encode_bits(value2b, pos4b, -1)

    def encode_group(group6b: int) -> int:
        value2b = (group6b >> 4) & 0x03
        pos4b = group6b & 0x0F
        return encode_bits(value2b, pos4b, -1)

    def decode_group(b: int) -> tuple[int, bool]:
        b &= 0xFF
        if (b & x_mask) != x_mask:
            return 0, False
        value2b = 0
        pos4b = 0
        for i, bit in enumerate(p_bits):
            if b & (1 << bit):
                pos4b |= 1 << (3 - i)
        if b & (1 << v_bits[0]):
            value2b |= 0x02
        if b & (1 << v_bits[1]):
            value2b |= 0x01
        group6b = (value2b << 4) | (pos4b & 0x0F)
        return group6b, True

    # Build padding pool by dropping one redundant x-bit so padding bytes are never hints.
    padding_set: set[int] = set()
    padding: list[int] = []
    for drop in range(len(x_bits)):
        for value2b in range(4):
            for pos4b in range(16):
                b = encode_bits(value2b, pos4b, drop)
                if popcount8(b) >= 5 and b not in padding_set:
                    padding_set.add(b)
                    padding.append(b)
    padding.sort()
    if not padding:
        raise ValueError("custom table produced empty padding pool")

    return Layout(
        name=f"custom({cleaned})",
        hint_mask=x_mask,
        hint_value=x_mask,
        padding_pool=bytes(padding),
        encode_hint=encode_hint,
        encode_group=encode_group,
        decode_group=decode_group,
    )


def layouts_for_report(custom_patterns: Iterable[str]) -> list[Layout]:
    out = [layout_ascii(), layout_entropy()]
    for p in custom_patterns:
        out.append(layout_custom(p))
    return out

