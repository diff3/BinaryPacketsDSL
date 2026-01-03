#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib

from utils.Logger import Logger

from protocols.wow.shared.modules.crypto.SRP6Crypto import SRP6Crypto


class SRP6CryptoVanilla(SRP6Crypto):
    """
    Vanilla/vMangos SHA1 interleave (no leading-zero trimming).
    """

    def __init__(self, mode: str = "vmangos"):
        super().__init__()
        self.mode = mode
        self._endian = "little"

    def get_N_bytes(self) -> bytes:
        return self._modulus_bytes_le

    def sha1_interleave(self, s_bytes: bytes) -> bytes:
        if len(s_bytes) != 32:
            raise ValueError("S must be 32 bytes")

        buf0 = s_bytes[0::2]
        buf1 = s_bytes[1::2]

        h0 = hashlib.sha1(buf0).digest()
        h1 = hashlib.sha1(buf1).digest()

        out = bytearray(40)
        for i in range(20):
            out[2 * i] = h0[i]
            out[2 * i + 1] = h1[i]
        return bytes(out)

    def server_verify(
        self,
        username: str,
        salt: bytes,
        verifier: bytes,
        b_value: int,
        b_public: bytes,
        a_public: bytes,
        m1_client: bytes,
    ):
        """
        Vanilla/vMangos server-side verification with debug logging on mismatch.
        """
        username_u = self.upper_skyfire(username)

        u_value = self.compute_u(a_public, b_public)
        s_bytes = self.server_compute_S(a_public, verifier, b_value, u_value)
        k_bytes = self.server_compute_K(s_bytes)
        m1_server = self.compute_M1(username_u, salt, a_public, b_public, k_bytes)

        if m1_server != m1_client:
            def hx(b):
                return b.hex().upper() if isinstance(b, (bytes, bytearray)) else str(b)

            Logger.error(
                "[SRP6 DEBUG] "
                f"A_le={hx(a_public)} "
                f"B_le={hx(b_public)} "
                f"s_le={hx(salt)} "
                f"v_le={hx(verifier)} "
                f"N_be={self._modulus_bytes_be.hex().upper()} "
                f"N_le={self._modulus_bytes_le.hex().upper()} "
                f"g={self.G:02X} "
                f"u_le={u_value.to_bytes(20, 'little', signed=False).hex().upper()} "
                f"S_le={hx(s_bytes)} "
                f"K_le={hx(k_bytes)} "
                f"M1_client={hx(m1_client)} "
                f"M1_server={hx(m1_server)}"
            )
            return False, None, None

        m2 = self.compute_M2(a_public, m1_client, k_bytes)
        return True, m2, k_bytes
