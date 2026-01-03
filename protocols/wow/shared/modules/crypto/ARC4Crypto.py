import hashlib
import hmac
import struct
from dataclasses import dataclass
from Crypto.Cipher import ARC4

from utils.Logger import Logger


# -------------------------------------------------------
# World packet header (lokal dataclass—INGA externa moduler)
# -------------------------------------------------------
@dataclass
class WorldClientPktHeader:
    cmd: int
    size: int


class Arc4CryptoHandler:
    _serverEncrypt = None
    _clientDecrypt = None

    ARC4_DROP_BYTES = 1024

    SERVER_ENCRYPTION_KEY = bytes([
        0x08, 0xF1, 0x95, 0x9F, 0x47, 0xE5, 0xD2, 0xDB,
        0xA1, 0x3D, 0x77, 0x8F, 0x3F, 0x3E, 0xE7, 0x00
    ])

    SERVER_DECRYPTION_KEY = bytes([
        0x40, 0xAA, 0xD3, 0x92, 0x26, 0x71, 0x43, 0x47,
        0x3A, 0x31, 0x08, 0xA6, 0xE7, 0xDC, 0x98, 0x2A
    ])

    def __init__(self):
        pass

    def init_arc4(self, K):
        """
        Initializes ARC4 encryption and decryption with a session key (K).
        """

        try:
            key_bytes = bytes.fromhex(K)
        except ValueError:
            raise ValueError(f"Invalid session key hex string: {K}")

        encrypt_hash = hmac.new(self.SERVER_ENCRYPTION_KEY, key_bytes, hashlib.sha1).digest()
        decrypt_hash = hmac.new(self.SERVER_DECRYPTION_KEY, key_bytes, hashlib.sha1).digest()

        self._serverEncrypt = ARC4.new(key=encrypt_hash, drop=self.ARC4_DROP_BYTES)
        self._clientDecrypt = ARC4.new(key=decrypt_hash, drop=self.ARC4_DROP_BYTES)

    def decrypt_recv(self, header):
        try:
            return self._clientDecrypt.decrypt(header)
        except Exception as e:
            Logger.error(f"Decryption failed: {e}. Returning original header.")
            return header

    def encrypt_send(self, header):
        try:
            return self._serverEncrypt.encrypt(header)
        except Exception as e:
            Logger.error(f"Encryption failed: {e}. Returning original header.")
            return header

    def pack_data(self, cmd, size):
        try:
            value = (size << 13) | (cmd & 0x1FFF)
            packed_data = struct.pack('<I', value)
            return packed_data
        except Exception as e:
            print(f"Error while packing: {e}")
            return None

    def unpack_data(self, data: bytes) -> WorldClientPktHeader:
        try:
            value = struct.unpack('<I', data[:4])[0]
            cmd = value & 0x1FFF
            size = (value & 0xFFFFE000) >> 13
            return WorldClientPktHeader(cmd=cmd, size=size)
        except Exception as e:
            Logger.error(f"Failed to unpack data: {e}. Returning placeholder header.")
            return WorldClientPktHeader(cmd=0, size=0)