# handlers/AuthHandler.py

import os
from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from modules.DecorderHandler import DecoderHandler
from modules.EncoderHandler import EncoderHandler
from modules.NodeTreeParser import NodeTreeParser
from modules.Processor import load_case, load_all_cases, handle_add
from modules.Session import get_session

# TODO: replace this import with your real DSL engine
# e.g. from dsl.Engine import PacketDefinition, decode, encode
# Here we define thin wrapper functions for you to hook up.

DEF_DIR = os.path.join(os.path.dirname(__file__), "..", "defs")


def dsl_encode(def_name: str, data: dict) -> bytes:
    """
    Mirror of dsl_decode(), fast åt andra hållet:
    load_case → NodeTreeParser.parse → EncoderHandler.encode
    """
    config = ConfigLoader.load_config()

    program = config["program"]
    version = config["version"]

    case = load_case(program, version, def_name)
    if not case:
        raise ValueError(f"Unable to load DSL case for: {def_name}")

    case_name, case_lines, _, _ = case

    session = get_session()
    session.reset()

    # bygg trädet som vanligt
    NodeTreeParser.parse(case)

    # använd riktiga encodern
    try:
        encoded = EncoderHandler.encode_payload(case_name, data)
    except Exception as e:
        raise RuntimeError(f"Encoding failed for {def_name}: {e}")

    return encoded


def dsl_decode(def_name: str, payload: bytes) -> dict:
    """
    Decode a packet using the full BinaryPacketsDSL pipeline:
        load_case → NodeTreeParser.parse → DecoderHandler.decode
    """

    # from modules.DecoderHandler import DecoderHandler

    config = ConfigLoader.load_config()
    program = config["program"]
    version = config["version"]

    # Ladda DSL-case (.def + ev. raw/decoded)
    case = load_case(program, version, def_name)
    if not case:
        raise ValueError(f"Unable to load DSL case for: {def_name}")

    case_name, case_lines, _, _ = case

    # Reset session
    session = get_session()
    session.reset()

    # Bygg nodträdet
    NodeTreeParser.parse(case)

    # Kör decodern
    decoded = DecoderHandler.decode_payload(case_name, payload)

    return decoded

# ====== Handlers ======

def handle_AUTH_LOGON_CHALLENGE(client_socket, opcode, payload):
    """
    Handles AUTH_LOGON_CHALLENGE_C.
    payload = [opcode][error][size_lo size_hi][data...]
    """

    peer = client_socket.getpeername()

    print("RAW AUTH LOGON_CHALLENGE_C:", payload.hex(" "))

    # ---------- DSL DECODE ----------
    try:
        decoded = dsl_decode("AUTH_LOGON_CHALLENGE_C", payload)
        Logger.info(f"[AUTH_LOGON_CHALLENGE_C] Decoded: {decoded}")
        print("DECODED DICT:", decoded)
    except Exception as e:
        Logger.warning(f"DSL decode failed: {e}")
        decoded = {}

    # ---------- BUILD CHALLENGE RESPONSE ----------
    # Den här matchar EXAKT din .def layout.
    # Detta är en ren POC – klienten accepterar formatet men inte SRP-matematiken (än).
    response_fields = {
        "cmd": 0x00,                 # AUTH_LOGON_CHALLENGE_S
        "error": 0x00,               # AUTH_OK
        "success": 0x00,             # 0=OK

        "B": b"\x22" * 32,           # server public key (dummy)
        "l": 1,                      # g length
        "g": 7,                      # typical SRP generator
        "blog": 1,                   # MoP kräver 1 här

        "N": b"\x11" * 32,           # dummy SRP modulus
        "s": b"\x33" * 32,           # salt (dummy)

        "unk3": b"\x00" * 16,        # MoP requirement
        "securityFlags": 0x00        # no security flags
    }

    # ---------- DSL ENCODE ----------
    try:
        response_bytes = dsl_encode("AUTH_LOGON_CHALLENGE_S", response_fields)
        Logger.info("Sending AUTH_LOGON_CHALLENGE_S")
        return 0, response_bytes

    except Exception as e:
        Logger.error(f"Encoding AUTH_LOGON_CHALLENGE_S failed: {e}")
        return 1, None

def handle_AUTH_LOGON_PROOF(client_socket, opcode_byte: int, header: bytes):
    """
    Handle AUTH_LOGON_PROOF_C and respond with AUTH_LOGON_PROOF_S.
    For POC we accept anything and return success.
    """
    try:
        raw_rest = client_socket.recv(256)
        raw_packet = header + raw_rest

        try:
            req = dsl_decode("AUTH_LOGON_PROOF_C.def", raw_packet)
        except NotImplementedError:
            Logger.warning("dsl_decode not implemented for AUTH_LOGON_PROOF_C, skipping strict decode")
            req = {}

        Logger.info(f"AUTH_LOGON_PROOF_C decoded: {req}")

        # Build simple success proof
        resp_struct = {
            "result": 0,  # AUTH_OK
            # Lägg in fält som din AUTH_LOGON_PROOF_S.def kräver
            # t.ex. "M2": os.urandom(20), "account_flags": 0, ...
        }

        try:
            resp_bytes = dsl_encode("AUTH_LOGON_PROOF_S.def", resp_struct)
        except NotImplementedError:
            Logger.error("dsl_encode not implemented for AUTH_LOGON_PROOF_S")
            return 1, b""

        return 0, resp_bytes

    except Exception as e:
        Logger.error(f"Exception in handle_AUTH_LOGON_PROOF: {e}")
        return 1, b""


def handle_REALM_LIST(client_socket, opcode_byte: int, header: bytes):
    """
    Handle REALM_LIST_C and respond with REALM_LIST_S using DSL.
    """
    try:
        # REALM_LIST_C är oftast bara opcode + short length + zero eller lite extra.
        raw_rest = client_socket.recv(64)
        raw_packet = header + raw_rest

        try:
            req = dsl_decode("REALM_LIST_C.def", raw_packet)
        except NotImplementedError:
            Logger.warning("dsl_decode not implemented for REALM_LIST_C, using dummy request")
            req = {}

        Logger.info(f"REALM_LIST_C decoded: {req}")

        # Bygg en minimal realm-lista:
        # Anpassa fältnamn till din REALM_LIST_S.def
        resp_struct = {
            "realms": [
                {
                    "realm_id": 1,
                    "realm_type": 0,           # Normal
                    "flags": 0,
                    "name": "DSL Test Realm",
                    "address": "192.168.11.30:8085",
                    "population": 1.0,
                    "num_chars": 0,
                    "timezone": 1,
                    "realm_id2": 1,
                }
            ]
        }

        try:
            resp_bytes = dsl_encode("REALM_LIST_S.def", resp_struct)
        except NotImplementedError:
            Logger.error("dsl_encode not implemented for REALM_LIST_S")
            return 1, b""

        return 0, resp_bytes

    except Exception as e:
        Logger.error(f"Exception in handle_REALM_LIST: {e}")
        return 1, b""


# ====== Opcode mapping ======

opcode_handlers = {
    "AUTH_LOGON_CHALLENGE_C": handle_AUTH_LOGON_CHALLENGE,
    "AUTH_LOGON_PROOF": handle_AUTH_LOGON_PROOF,
    "REALM_LIST": handle_REALM_LIST,
    # Du kan lägga till:
    # "AUTH_RECONNECT_CHALLENGE": ...
    # "AUTH_RECONNECT_PROOF": ...
}
