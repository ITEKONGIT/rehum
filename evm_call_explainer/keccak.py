from __future__ import annotations


MASK64 = (1 << 64) - 1
ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)


def _rotate_left(value: int, amount: int) -> int:
    if amount == 0:
        return value & MASK64
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def _permutation(state: list[int]) -> None:
    for constant in ROUND_CONSTANTS:
        columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        delta = [columns[(x - 1) % 5] ^ _rotate_left(columns[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= delta[x]

        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rotate_left(
                    state[x + 5 * y], ROTATION[x][y]
                )

        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = moved[x + 5 * y] ^ (
                    (~moved[(x + 1) % 5 + 5 * y]) & moved[(x + 2) % 5 + 5 * y]
                )
                state[x + 5 * y] &= MASK64
        state[0] ^= constant


def keccak_256(data: bytes) -> bytes:
    """Legacy Keccak-256 used by Ethereum (not standardized SHA3-256)."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(bytes((-len(padded)) % rate))
    padded[-1] |= 0x80

    state = [0] * 25
    for block_start in range(0, len(padded), rate):
        block = padded[block_start : block_start + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        _permutation(state)

    output = b"".join(lane.to_bytes(8, "little") for lane in state[: rate // 8])
    return output[:32]


def function_selector(signature: str) -> str:
    return "0x" + keccak_256(signature.encode("utf-8"))[:4].hex()
