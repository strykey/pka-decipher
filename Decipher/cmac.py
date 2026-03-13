from typing import Callable

BLOCK_SIZE = 16  # 128 bit for Twofish

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def left_shift_one(bitstring: bytes) -> bytes:
    out = bytearray(len(bitstring))
    carry = 0
    for i in reversed(range(len(bitstring))):
        new = (bitstring[i] << 1) & 0xFF
        out[i] = new | carry
        carry = (bitstring[i] & 0x80) >> 7
    return bytes(out)

def generate_subkeys(encrypt_block: Callable[[bytes], bytes]):
    const_rb = 0x87
    zero = bytes(BLOCK_SIZE)
    L = encrypt_block(zero)

    K1 = left_shift_one(L)
    if L[0] & 0x80:
        K1 = xor_bytes(K1, b'\x00' * 15 + bytes([const_rb]))

    K2 = left_shift_one(K1)
    if K1[0] & 0x80:
        K2 = xor_bytes(K2, b'\x00' * 15 + bytes([const_rb]))

    return K1, K2

def pad(block: bytes) -> bytes:
    padded = block + b'\x80'
    return padded + b'\x00' * (BLOCK_SIZE - len(padded))

class CMAC:
    def __init__(self, encrypt_block: Callable[[bytes], bytes]):
        self.encrypt_block = encrypt_block
        self.K1, self.K2 = generate_subkeys(encrypt_block)

    def digest(self, data: bytes) -> bytes:
        if len(data) == 0:
            last = xor_bytes(pad(b''), self.K2)
            blocks = []
        else:
            blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
            if len(blocks[-1]) == BLOCK_SIZE:
                last = xor_bytes(blocks[-1], self.K1)
                blocks = blocks[:-1]
            else:
                last = xor_bytes(pad(blocks[-1]), self.K2)
                blocks = blocks[:-1]

        X = bytes(BLOCK_SIZE)
        for block in blocks:
            X = self.encrypt_block(xor_bytes(X, block))

        return self.encrypt_block(xor_bytes(X, last))
