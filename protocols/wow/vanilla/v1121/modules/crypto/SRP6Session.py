#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from protocols.wow.vanilla.v1121.modules.crypto.SRP6CryptoVanilla import SRP6CryptoVanilla


class SRP6Session:
    """
    SRP6 server-side session state (vanilla/vMangos variant).
    Stores only SRP parameters and computed values; no protocol fields.
    """

    def __init__(self, username: str, salt: bytes, verifier: bytes, mode: str = "vmangos"):
        self.username = (username or "").upper()
        self.salt = salt
        self.verifier = verifier

        self.core = SRP6CryptoVanilla(mode=mode)

        self.b = None
        self.B = None

    def generate_B(self) -> bytes:
        """Generate (or reuse) server public B."""
        if self.B is None or self.b is None:
            self.b, self.B = self.core.server_make_B(self.verifier)
        return self.B

    def verify_proof(self, A_bytes: bytes, M1_bytes: bytes):
        """
        Validates client proof M1.
        Returns (ok, M2, session_key)
        """
        if not self.B or self.b is None:
            return False, None, None

        ok, M2, session_key = self.core.server_verify(
            username=self.username,
            salt=self.salt,
            verifier=self.verifier,
            b_value=self.b,
            b_public=self.B,
            a_public=A_bytes,
            m1_client=M1_bytes,
        )

        if not ok:
            return False, None, None

        return True, M2, session_key
