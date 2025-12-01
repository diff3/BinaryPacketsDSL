#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal MoP 5.4.8 authentication test client.

Features:
  • DSL decoding (AUTH_LOGON_CHALLENGE_S, AUTH_LOGON_PROOF_S, REALM_LIST_S)
  • SRP6Client for SRP math
  • config.yaml for all client parameters
"""

import socket
import struct
import getpass

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger

from modules.crypto.SRP6Client import SRP6Client, H
from modules.Processor import load_case
from modules.NodeTreeParser import NodeTreeParser
from modules.DecoderHandler import DecoderHandler
from modules.Session import get_session
from modules.EncoderHandler import EncoderHandler


# ---- Helpers -------------------------------------------------------------

def to_bytes(val):
    """
    Convert DSL-decoded hexstring or raw bytes into bytes.

    Parameters
    ----------
    val : str | bytes
        Hex string (no spaces) or bytes object.

    Returns
    -------
    bytes
        Parsed byte sequence.

    Raises
    ------
    TypeError
        If value is neither bytes nor hex string.
    """
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return bytes.fromhex(val)
    raise TypeError(f"Expected bytes or hexstr, got {type(val)}")


def dsl_decode(def_name, payload):
    """
    Decode a packet using the DSL definition system.

    Parameters
    ----------
    def_name : str
        Name of the packet definition (e.g. 'AUTH_LOGON_CHALLENGE_S').
    payload : bytes
        Binary packet to decode.

    Returns
    -------
    dict
        Decoded fields as defined by DSL.
    """
    cfg = ConfigLoader.load_config()
    program = cfg["program"]
    version = cfg["version"]

    case_name, lines, _, expected = load_case(program, version, def_name)

    session = get_session()
    session.reset()

    NodeTreeParser.parse((case_name, lines, payload, expected))
    return DecoderHandler.decode((case_name, lines, payload, expected))


# ---- AUTH_LOGON_CHALLENGE_C ---------------------------------------------

def build_challenge_packet(username, cfg):
    """
    Construct AUTH_LOGON_CHALLENGE_C using config.yaml values.

    Parameters
    ----------
    username : str
        Account username.
    cfg : dict
        Global configuration structure.

    Returns
    -------
    bytes
        Encoded challenge packet.
    """
    client = cfg["client"]

    game = b"WoW\x00"
    platform = client["platform"].encode() + b"\x00"
    os_name = client["os"].encode() + b"\x00"
    country = client["country"].encode()
    timezone = client["timezone"]
    build = client["build"]

    version1, version2, version3 = 5, 4, 8

    ip_bytes = socket.inet_aton(client["ip"])
    u = username.upper().encode("ascii")
    ulen = len(u)

    tail = (
        game +
        bytes([version1, version2, version3]) +
        struct.pack("<H", build) +
        platform +
        os_name +
        country +
        struct.pack("<I", timezone) +
        ip_bytes +
        bytes([ulen]) +
        u
    )

    return b"\x00" + b"\x08" + struct.pack("<H", len(tail)) + tail


# ---- AUTH_LOGON_PROOF_C -------------------------------------------------

def build_proof_packet(srp):
    """
    Build AUTH_LOGON_PROOF_C using computed SRP values.

    Parameters
    ----------
    srp : SRP6Client
        SRP6 client state containing A, M1 and K.

    Returns
    -------
    bytes
        Encoded proof packet.

    Raises
    ------
    ValueError
        If SRP is not fully initialized.
    """
    if not (srp.A_wire and srp.M1 and srp.K):
        raise ValueError("SRP6Client not fully initialized")

    crc = H(srp.A_wire, srp.M1, srp.K)

    return (
        b"\x01" +
        srp.A_wire +
        srp.M1 +
        crc +
        b"\x00" +
        b"\x00"
    )


# ---- MAIN ---------------------------------------------------------------

def main():
    """
    Execute a full mock authentication flow:
    1. Send AUTH_LOGON_CHALLENGE_C
    2. Parse AUTH_LOGON_CHALLENGE_S
    3. Perform SRP6 math
    4. Send AUTH_LOGON_PROOF_C
    5. Parse AUTH_LOGON_PROOF_S
    6. Send REALM_LIST_C (via DSL)
    7. Decode REALM_LIST_S
    """
    cfg = ConfigLoader.load_config()
    cfg["Logging"]["logging_levels"] = "Information, Success, Script, Error"

    host = cfg["auth_proxy"]["listen_host"]
    port = cfg["auth_proxy"]["listen_port"]

    Logger.info(f"Connecting to {host}:{port}")

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ").strip()

    if not username or not password:
        Logger.error("Missing username or password.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # ---- AUTH_LOGON_CHALLENGE_C -----------------------------------------

    challenge = build_challenge_packet(username, cfg)
    Logger.info(f"[SEND] CHALLENGE_C = {challenge.hex()}")
    dsl_decode("AUTH_LOGON_CHALLENGE_C", challenge)
    sock.sendall(challenge)

    data = sock.recv(4096)
    Logger.info(f"[RECV] CHALLENGE_S = {data.hex()}")

    decoded = dsl_decode("AUTH_LOGON_CHALLENGE_S", data)

    if decoded.get("error", 1) != 0:
        Logger.error(f"Challenge failed with error {decoded['error']}")
        return

    B = to_bytes(decoded["B"])
    g = decoded["g"]
    N = to_bytes(decoded["N"])
    salt = to_bytes(decoded["s"])

    # ---- SRP6 ------------------------------------------------------------

    srp = SRP6Client(username, password)
    srp.load_challenge(B_wire=B, g=g, N_wire=N, salt=salt)
    srp.compute_A()
    srp.compute_shared_key()
    srp.compute_M1()

    # ---- AUTH_LOGON_PROOF_C ---------------------------------------------

    proof = build_proof_packet(srp)
    Logger.info(f"[SEND] PROOF_C = {proof.hex()}")
    dsl_decode("AUTH_LOGON_PROOF_C", proof)
    sock.sendall(proof)

    data = sock.recv(4096)
    Logger.info(f"[RECV] PROOF_S = {data.hex()}")

    decoded = dsl_decode("AUTH_LOGON_PROOF_S", data)

    if decoded.get("error", 1) != 0:
        Logger.error("Proof failed")
        return

    Logger.success("Logged in successfully.")

    # ---- REALM_LIST_C ---------------------------------------------------

    realm_req = EncoderHandler.encode_packet(
        "REALM_LIST_C",
        {
            "cmd": 0x10,
             "build": cfg["client"]["build"],
        },
    )

    Logger.info(f"[SEND] REALM_LIST_C = {realm_req.hex()}")
    _ = dsl_decode("REALM_LIST_C", realm_req)
    sock.sendall(realm_req)

    data = sock.recv(4096)
    Logger.info(f"[RECV] REALM_LIST_S = {data.hex()}")

    _ = dsl_decode("REALM_LIST_S", data)

    sock.close()


# ---- Entry --------------------------------------------------------------

if __name__ == "__main__":
    main()