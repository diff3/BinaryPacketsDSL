# ARC4 World Header Encryption Overview  
# SkyFire / WoW 5.4.8 World Server – Technical Notes

This document describes how ARC4 (RC4) is used for WoW *world* packet headers.  
Payloads remain plaintext; only the 4-byte header is encrypted after auth.

-----------------------------------------------------------------------
1. ARC4 Summary
-----------------------------------------------------------------------

ARC4 is used as a stream cipher on the world channel after authentication.  
Two independent ARC4 streams exist:

- **serverEncrypt** (server → client headers)  
- **clientDecrypt** (client → server headers)

Both streams are derived from the session key **K** and fixed HMAC keys.

-----------------------------------------------------------------------
2. When ARC4 Is Active
-----------------------------------------------------------------------

World traffic starts in plaintext:

- Initial handshake: `WORLD OF WARCRAFT CONNECTION` (plaintext)  
- Pre-auth packets: plaintext headers and payloads  

After the client sends `CMSG_AUTH_SESSION`, ARC4 is initialized and the proxy
switches to **encrypted header mode**. From that point on:

- **Headers are ARC4-encrypted**  
- **Payloads remain plaintext**

-----------------------------------------------------------------------
3. Key Derivation (init_arc4)
-----------------------------------------------------------------------

`Arc4CryptoHandler.init_arc4(K)` expects a **hex string** for the session key K.  
K is produced by the SRP6 login flow.

Derivation:

```
encrypt_key = HMAC-SHA1(SERVER_ENCRYPTION_KEY, K_bytes)
decrypt_key = HMAC-SHA1(SERVER_DECRYPTION_KEY, K_bytes)
```

ARC4 is initialized with a **drop of 1024 bytes** to discard weak keystream.

-----------------------------------------------------------------------
4. Direction Semantics
-----------------------------------------------------------------------

The project uses two ARC4 streams:

- **encrypt_send()** → used for server → client header processing  
- **decrypt_recv()** → used for client → server header processing  

This mirrors WoW's directional ARC4 keys and keeps the keystream aligned.

-----------------------------------------------------------------------
5. World Header Packing Format
-----------------------------------------------------------------------

Headers are 4 bytes, little-endian, with this packed layout:

```
value = (size << 13) | (cmd & 0x1FFF)
packed = struct.pack("<I", value)
```

- **cmd**: 13 bits (0x0000–0x1FFF)  
- **size**: remaining high bits  

Unpacking reverses this logic:

```
cmd  = value & 0x1FFF
size = (value & 0xFFFFE000) >> 13
```

-----------------------------------------------------------------------
6. Encrypted Stream Parsing Rules
-----------------------------------------------------------------------

During ARC4 mode:

1. Read 4 bytes from the stream  
2. Decrypt header with ARC4 (direction-aware)  
3. Unpack cmd/size from the decrypted header  
4. Read **size** bytes of plaintext payload  

Special case used by the stream parser:

- **AUTH_RESPONSE opcode = 0x01F6**  
  The parser reduces payload size by 4 bytes.

-----------------------------------------------------------------------
7. Minimal Flow Example
-----------------------------------------------------------------------

```
K_hex = "..."                       # SRP session key (hex)
crypto.init_arc4(K_hex)

# Server → Client header
dec_header = crypto.encrypt_send(enc_header)
header = crypto.unpack_data(dec_header)
payload = recv(header.size)
```

-----------------------------------------------------------------------
8. Value Mapping Cheat Sheet
-----------------------------------------------------------------------

INPUT  
  K_hex         → hex string from SRP6 session key  
  K_bytes       → bytes.fromhex(K_hex)  

ARC4 KEYS  
  encrypt_key   → HMAC-SHA1(SERVER_ENCRYPTION_KEY, K_bytes)  
  decrypt_key   → HMAC-SHA1(SERVER_DECRYPTION_KEY, K_bytes)  

WIRE FORMAT  
  header (enc)  → 4 bytes ARC4  
  header (dec)  → 4 bytes little-endian packed (size|cmd)  
  payload       → plaintext bytes  
