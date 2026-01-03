# SRP-6 Authentication Overview  
# SkyFire / WoW 5.4.8 Auth Server – Technical Notes

This document describes how SRP-6 is used in the WoW authentication process and how input is passed into SRP6Core.  
Includes all formats, transformations, and rules for compatibility.

-----------------------------------------------------------------------
1. SRP-6 Summary
-----------------------------------------------------------------------

SRP-6 is a zero-knowledge password authentication protocol.  
The server stores only:

- salt (32 bytes)
- verifier (32 bytes)

The protocol proves password correctness by deriving a shared secret S, then verifying M1 and M2.

SRP-6 uses big-endian integers internally.  
WoW uses little-endian for network transmission.  
Correct conversions are essential.

-----------------------------------------------------------------------
2. Stored Account Data (as used by SRP6Core)
-----------------------------------------------------------------------

username  → string, uppercase  
salt      → raw 32 bytes (no endian swap)  
verifier  → raw 32 bytes (represents a big-endian integer)

-----------------------------------------------------------------------
3. Server Session Values
-----------------------------------------------------------------------

server_make_B(verifier) returns:

b_value : server private exponent  
    - MUST be interpreted as big-endian hex  
    - Construct with int(b_hex, 16)

B_bytes : 32-byte little-endian public ephemeral B  
    - Already correctly formatted for WoW network packets  
    - Used as-is

-----------------------------------------------------------------------
4. Client → Server: Logon Proof Fields
-----------------------------------------------------------------------

A  = 32 bytes, little-endian  
M1 = 20 bytes

A must be converted:

    A_int = int.from_bytes(A_bytes, "little")

M1 is used raw.

-----------------------------------------------------------------------
5. Server → Client: Logon Proof Response
-----------------------------------------------------------------------

If M1 matches:

cmd     : 0x01  
error   : 0  
M2      : 20-byte proof  
unk1    : 0x8000 (32-bit LE)  
unk2    : 0 (32-bit LE)  
unk3    : 0 (16-bit LE)

-----------------------------------------------------------------------
6. Value Mapping Cheat Sheet
-----------------------------------------------------------------------

STORED DATA  
  username       → ASCII  
  salt           → bytes (no endian change)  
  verifier       → bytes, big-endian semantic  

SERVER SESSION  
  b_hex          → 64 hex chars, big-endian  
  b_value        → int(b_hex,16)  
  B_bytes        → 32-byte little-endian  

CLIENT INPUT  
  A_bytes        → 32-byte little-endian  
  M1_client      → 20 bytes  

SRP6Core INPUT  
  username, salt, verifier  
  b_value        (big-endian int)  
  b_public       (LE bytes)  
  a_public       (LE bytes)  
  m1_client      (raw)  

SRP6Core OUTPUT  
  ok, M2  

-----------------------------------------------------------------------
7. Endianness Table
-----------------------------------------------------------------------

Value      | Network | Internal Math | Notes
-----------|---------|---------------|-----------------------------------------
N          | LE      | BE            | reverse before using in core
g          | LE (1B) | BE            | trivial
salt (s)   | raw     | raw           | no swap
verifier   | raw     | BE            | represents big-int
A          | LE      | convert to BE | required
B          | LE      | use as LE in hash | DO NOT convert
b          | hex BE  | int(b_hex,16) | no from_bytes(little)
M1         | raw     | raw           |
M2         | raw     | raw           |

-----------------------------------------------------------------------
8. SRP6Core Processing Flow
-----------------------------------------------------------------------

(1) A_bytes (LE) → convert → A_int (BE meaning)  
(2) Compute scramble:

    u = SHA1(A_bytes || B_bytes)

(3) Compute shared secret:

    S = (A * v^u mod N)^b mod N

(4) Interleave S → K  
(5) Compute server M1  
(6) Compare with client M1  
(7) If match → produce M2

-----------------------------------------------------------------------
9. Correct Invocation Example
-----------------------------------------------------------------------

    ok, M2 = core.server_verify(
        username      = "USER",
        salt          = salt_bytes,
        verifier      = verifier_bytes,
        b_value       = b_value,      # big-endian int
        b_public      = B_bytes,      # LE
        a_public      = A_bytes,      # LE
        m1_client     = M1_client,    # raw bytes
    )