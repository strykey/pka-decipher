from Decipher.eax import EAX
from Decipher.twofish import Twofish
import zlib
import struct

def deobf_stage1(data: bytes) -> bytes:
    L = len(data)
    return bytes(data[L-1-i] ^ (L - i*L & 0xFF) for i in range(L))

def deobf_stage2(data: bytes) -> bytes:
    L = len(data)
    return bytes(b ^ (L - i & 0xFF) for i, b in enumerate(data))

def uncompress_qt(blob: bytes) -> bytes:
    size = struct.unpack(">I", blob[:4])[0]
    return zlib.decompress(blob[4:])[:size]

def decrypt_pkt(pkt: bytes) -> bytes:
    # Stage 1 deobfuscation
    stage1 = deobf_stage1(pkt)

    # Chiave e IV per i file .pkt
    key = bytes([137])*16
    iv  = bytes([16])*16

    # Twofish block cipher
    tf = Twofish(key)
    encrypt_block = tf.encrypt

    # EAX con nonce = iv
    eax = EAX(encrypt_block)

    # Supponiamo che negli .pkt il tag sia alla fine
    ciphertext = stage1[:-16]
    tag        = stage1[-16:]

    # Decrypt usando nonce fisso
    decrypted = eax.decrypt(nonce=iv, ciphertext=ciphertext, tag=tag)

    # Stage 2 deobfuscation
    stage2 = deobf_stage2(decrypted)

    # Decompressione
    xml = uncompress_qt(stage2)

    return xml
