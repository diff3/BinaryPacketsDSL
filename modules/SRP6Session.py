# modules/SRP6Session.py
# -*- coding: utf-8 -*-

from modules.SRP6Core import SRP6Core


class SRP6Session:
    """
    Represents a single SRP-6 authentication session for one client.
    Handles server-private SRP6 values and calls SRP6Core for math.
    """

    def __init__(self, username: str, salt: bytes, verifier: bytes) -> None:
        _config = None

        self.username = username
        self.salt = salt
        self.verifier = verifier

        print("[SRP-DBG] username =", username)
        print("[SRP-DBG] verifier =", verifier.hex())
        print("[SRP-DBG] salt =", salt.hex())

        self.core = SRP6Core()

        self.b_value: int | None = None
        self.B_bytes: bytes | None = None

    # ------------------------------------------------------------------

    def build_challenge(self) -> dict:
        """
        Builds full DSL dict for AUTH_LOGON_CHALLENGE_S.
        """

        _config = None

        # generate b and B (B is already 32-byte LE, matching SkyFire/SRP math)
        self.b_value, self.B_bytes = self.core.server_make_B(self.verifier)

        print("[SRP-DBG] b =", self.b_value.to_bytes(32, "little").hex())
        print("[SRP-DBG] B =", self.B_bytes.hex())

        # SkyFire skickar N i little-endian på nätet
        N_le = bytes.fromhex(self.core.N_HEX_BE)[::-1]

        return {
            "cmd": 0,
            "error": 0,
            "success": 0,

            "B": self.B_bytes,      # 32-byte LE, samma som i dina tester
            "l": 1,
            "g": self.core.G,
            "blob": 32,

            "N": N_le,              # <- VIKTIGT: nu LE, som riktiga SkyFire
            "s": self.salt,         # salt behöver inte endiannas, det hashas bara
            "unk3": bytes(16),
            "securityFlags": 0,
        }

    # ------------------------------------------------------------------

    def verify_proof(
        self,
        A_bytes: bytes,
        M1_bytes: bytes
    ) -> tuple[bool, bytes | None, dict | None]:
        """
        Performs SRP verification and returns (ok, M2, fields_for_packet)
        """

        _config = None

        if self.b_value is None or self.B_bytes is None:
            return False, None, None

        ok, M2 = self.core.server_verify(
            username=self.username,
            salt=self.salt,
            verifier=self.verifier,
            b_value=self.b_value,
            b_public=self.B_bytes,
            a_public=A_bytes,
            m1_client=M1_bytes,
        )

        if not ok:
            return False, None, None

        # Build AUTH_LOGON_PROOF_S fields
        fields = {
            "cmd": 1,
            "error": 0,
            "M2": M2,
            "unk1": 0x8000,   # SkyFire standard
            "unk2": 0,
            "unk3": 0,
        }

        return True, M2, fields
