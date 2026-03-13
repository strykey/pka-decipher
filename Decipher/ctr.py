from typing import Callable

BLOCK_SIZE = 16  # 128 bit


def inc_counter_be(counter: bytearray):
    """Incrementa un contatore big-endian a 128 bit (come Crypto++)."""
    for i in range(BLOCK_SIZE - 1, -1, -1):
        counter[i] = (counter[i] + 1) & 0xFF
        if counter[i] != 0:
            break


class CTR:
    def __init__(self, encrypt_block: Callable[[bytes], bytes], initial_counter: bytes):
        assert len(initial_counter) == BLOCK_SIZE
        self.encrypt_block = encrypt_block
        self.counter = bytearray(initial_counter)

    def process(self, data: bytes) -> bytes:
        out = bytearray()
        offset = 0

        while offset < len(data):
            keystream = self.encrypt_block(bytes(self.counter))
            inc_counter_be(self.counter)

            block = data[offset:offset + BLOCK_SIZE]
            ks = keystream[:len(block)]
            out.extend(b ^ k for b, k in zip(block, ks))
            offset += BLOCK_SIZE

        return bytes(out)
