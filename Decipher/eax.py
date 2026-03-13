from typing import Callable
from Decipher.cmac import CMAC, xor_bytes, BLOCK_SIZE
from Decipher.ctr import CTR


def _omac_with_prefix(cmac: CMAC, prefix: int, data: bytes) -> bytes:
    # Prefisso di 16 byte: [0, 0, ..., prefix]
    P = b'\x00' * (BLOCK_SIZE - 1) + bytes([prefix])
    return cmac.digest(P + data)


class EAX:
    def __init__(self, encrypt_block: Callable[[bytes], bytes]):
        self.encrypt_block = encrypt_block
        self.cmac = CMAC(encrypt_block)

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b''):
        # OMAC_0 = CMAC(0x00 || nonce)
        n_tag = _omac_with_prefix(self.cmac, 0x00, nonce)

        # OMAC_1 = CMAC(0x01 || aad)
        h_tag = _omac_with_prefix(self.cmac, 0x01, aad)

        # CTR parte da n_tag
        ctr = CTR(self.encrypt_block, n_tag)
        ciphertext = ctr.process(plaintext)

        # OMAC_2 = CMAC(0x02 || ciphertext)
        c_tag = _omac_with_prefix(self.cmac, 0x02, ciphertext)

        # TAG finale = n_tag ⊕ h_tag ⊕ c_tag
        tag = xor_bytes(xor_bytes(n_tag, h_tag), c_tag)

        return ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b''):
        # Ricalcolo OMAC_0
        n_tag = _omac_with_prefix(self.cmac, 0x00, nonce)

        # CTR
        ctr = CTR(self.encrypt_block, n_tag)
        plaintext = ctr.process(ciphertext)

        # Ricalcolo OMAC_1 e OMAC_2
        h_tag = _omac_with_prefix(self.cmac, 0x01, aad)
        c_tag = _omac_with_prefix(self.cmac, 0x02, ciphertext)

        # Verifica TAG
        expected_tag = xor_bytes(xor_bytes(n_tag, h_tag), c_tag)
        if expected_tag != tag:
            raise ValueError("EAX authentication failed")

        return plaintext
