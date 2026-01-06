**Purpose**
`.def` files are the single source of truth for packet layout. The DSL is declarative and structural, so you describe bytes and their meaning without embedding logic. Decode and encode share the same definitions to keep the model consistent. Examples focus on intent and expected shape rather than implementation details.



**Struct Basics (fields)**

- Fields are the core unit: `name: format`.

- Formats are Python `struct` codes, plus a few DSL extras.

- Think: "what bytes are here, and how should they be interpreted?"

  

**Example**:
    id: H
    count: B
    name: 8s



**Struct Formats (common)**

- Use standard struct codes for raw layout.

- Strings are either fixed (`Ns`) or dynamic (`€len's`).

- `R` means "read the rest of payload".

  

**Example:**
    id: I
    len: B
    name: €len's
    tail: R



**Python Struct Formats (common)**

- `B` unsigned 8-bit
- `b` signed 8-bit
- `H` unsigned 16-bit
- `h` signed 16-bit
- `I` unsigned 32-bit
- `i` signed 32-bit
- `Q` unsigned 64-bit
- `q` signed 64-bit
- `f` 32-bit float
- `d` 64-bit float
- `Ns` fixed-length bytes/string (example: `8s`)
- `x` pad byte (struct-level padding)



**Note**

- Endianness is controlled by `endian: little` / `endian: big`, not by the format.



**Variables + Expressions**

- Variables are separate from fields and do not consume bytes.
- Expressions are Python-like for arithmetic, concat, and slicing.
- Use them to define lengths or computed values.



**Example:**
    foo = 42
    bar = "foobar"
    sum = €foo + 1
    join = €bar + "!"
    part = €bar[2:5]



**Optional Fields (`?:`)**

- Optional fields are for tolerant decoding.
- If bytes are missing, the value becomes `None` and decoding continues.
- Encode skips optional fields when the value is `None`.
- Decode-only effect: optional changes how the decoder handles missing bytes.



**Example:**
    opt?: B
    maybe?: S



**Visibility and Ignore**

- Visibility affects decode output; payload affects encode output.
- `-name` hides the field in decode output and also excludes it from payload.
- `+name` forces visibility and payload.
- `_` (or `_t`) ignores the field in output but still consumes bytes in both decode and encode.

**Example:**
    -hidden: B
    +shown: B
    _: B

Decode output:
    {"shown": "..."}
Encode payload:
    includes bytes for `+shown` and `_`, excludes `-hidden`



**Modifiers (decode vs encode)**

- Modifiers are transformations applied to values.
- You can specify decode modifiers and encode modifiers separately.
- Syntax: `field: fmt, dec_mods | enc_mods`.
- Modifiers should be pure, local transforms with no dependency on external state.



**Example:**
    name: S, tU | 0
    ip: 4s, W



**Decode Modifiers (examples)**

- These transform decoded values.
- Useful for cleaning, formatting, or converting types.
- Keep modifiers simple: they are data transforms, not control flow.

**Example:**
    hex_id: I, H
    upper: S, U
    trimmed: S, t
    bits: bits, 3B, 5b, I



**Encode Modifiers (examples)**

- These transform values before encoding.
- Useful for null-termination, bytes conversion, or mirrors.
- Encode mods are separated by `|`.



**Example:**
    name: S | 0
    raw: S | Q
    mirror: 4s | M



**Modifiers (decode / encode)**

- Decode modifiers are applied before `|`.

- Encode modifiers are applied after `|`.

  

**Decode modifiers**

- `B` / `b` read bits (MSB / LSB). Used in `bits` mode, e.g. `bits, 3B, 5b`.
- `I` to int (lists/bits/bytes → int)
- `H` to hex
- `G` to guid (little-endian)
- `W` to dotted IP string
- `s` to string
- `t` trim string
- `U` upper-case
- `u` lower-case
- `N` capitalized
- `M` mirror/reverse
- `C` combine (sum list)
- `X` rotate tail to front
- `J` join list into string
- `r` raw string (bytes → string, keep raw-ish)
- `T` clean text (strip control codes)



**Encode modifiers**

- `Q` to bytes

- `0` null-terminate

- `M` mirror/reverse

- `N` capitalized

- `U` upper-case

- `u` lower-case

- `t` trim string

- `s` to string

  

**Bits**

- Bits are read with explicit bit-length modifiers.
- `B` = MSB-first, `b` = LSB-first.
- This keeps bit-level parsing explicit and deterministic.



**Example:**
    flags: bits, 3B, 5b



**Padding and Alignment**

- `padding N` inserts N zero bytes.
- `flushbit` aligns to next byte boundary.
- These exist to match real-world packet layouts.



**Example:**
    padding 4
    flushbit



**Seek (absolute)**

- `seek N` jumps to an absolute offset.
- It is explicit and deterministic, not a search.
- Encode fills gaps with zeros.



**Example:**
    seek 0x20



**Seek Next Match (decode-only)**

- `seek next` scans forward for a byte pattern.
- It is for sentinel-based layouts.
- `seek?` makes it optional (no warning on miss).



**Example:**
    seek next 0xDE AD BE EF
    seek? next "foobar"



**Loop**

- Loops declare repeated structures, not runtime control flow.
- You can use a constant or a variable for count.
- The result is always a list of items.

  

**Example:**
    loop 3 to items:
        val: B
        
    count: B
    loop €count to items:
        val: B




**If / Elif / Else**

- Conditions are Python-like and evaluate against current values.
- Supports `==`, `!=`, `<`, `<=`, `>`, `>=`, plus `and` / `or`.

- This is declarative branching for structural differences.

- Use it to model variant layouts.

  

**Example:**
    flag: B
    if €flag == 1:
        a: B
    elif €flag == 2:
        a: H
    else:
        a: I



**Debug Print (no payload)**

- `print(...)` writes to the debug log without affecting decode or encode output.
- Works in both decode and encode to trace values at any point.
- Default level is `debug`, override with `print[level](...)`.

**Example:**
    print("start")
    print("user:", €username)
    print[info]("count:", €count, "items:", €items)


**Match / Case**

- Match is syntactic sugar for structured branching.
- It keeps “dispatch by value” readable.
- Supports single values, lists, ranges, and default.



**Example:**
    code: B
    match €code:
        case 1, 0x01, "win":
            a: B
        case 0x10..0x1F:
            a: H
        case _:
            a: I



**Blocks and Include**

- Blocks are reusable fragments.
- Include keeps definitions DRY and consistent.
- It is compile-time composition, not runtime logic.



**Example:**
    block header:
        id: H
        size: H

   include header



**Buffers (alloc / IO / assign)**

- Buffers let you model indexed byte arrays.
- `[]` allocates, `[i]:` reads, `[i] <-` assigns.
- This makes indexed payloads explicit.

Example:
    buf[]: 4B
    buf[0]: B
    buf[1] <- B


**Index Shorthand (bytes)**

- `name: idx 1, 2, 3` expands to `name[1]: B`, `name[2]: B`, `name[3]: B`.
- Useful for unordered byte reassembly (e.g., digests) while keeping byte order explicit.

**Example:**
    digest: idx 18, 14, 3 4 0


**Bits Shorthand**

- `bits 1BI: a, b, c` expands to `a: bits, 1BI` etc.
- Keeps long bit-mask sequences readable without changing order.

**Example:**
    bits 1BI: guildguid_4_mask, guid_0_mask, boosted
    bits 6BI: name_len



**Combine**

- Combine is for derived values like GUIDs.
- It references existing fields to compute a result.
- Keeps the “raw parts” still visible.



**Example:**
    guid_mask: B
    guid_0: B
    guid: combine guid_mask



**Packed GUID**

- A special case for WoW-style packed GUIDs.
- The mask controls which bytes are present.
- Exposes both GUID value and mask.



**Example:**
    guid: packed_guid



**Uncompress**

- Models compressed segments inside packets.
- Decode inflates, then parses children.
- Keeps compression handling declarative.



**Example:**
    len: H
    uncompress zlib €len:
        data: 4B



**Raw Slice (payload)**

- `slice[...]` reads raw bytes from the payload.
- It is explicit and separate from variable slicing.
- Use for grabbing opaque chunks.



**Example:**
    size: B
    chunk = slice[2:2+€size]



**Example: AUTH_LOGON_CHALLANGE_C**

endian: little
header:
   cmd: B
   error: B
data:
   size: H
   gamename: 4s, sM | MQ
   version1: B
   version2: B
   version3: B
   build: H
   platform: 4s, sM | MQ
   os: 4s, sM | MQ
   country: 4s, sM | MQ
   timezone_bias: I
   ip: 4s, W
   I_len: B
   username: €I_len's

Result:
{
  "cmd": 0,
  "error": 8,
  "size": 34,
  "gamename": "WoW",
  "version1": 5,
  "version2": 4,
  "version3": 8,
  "build": 18414,
  "platform": "x86",
  "os": "Win",
  "country": "enGB",
  "timezone_bias": 60,
  "ip": "192.168.11.30",
  "I_len": 4,
  "username": "MAPE"
}


**Example: REALM_LIST_S**

endian: little
header:
    cmd: B
    size: H
    unk1: I
    realm_list_size: H
data:
    loop €realm_list_size to €realmlist:
        icon: B
        lock: B
        flag: B
        name: S | Q
        address: S | Q
        pop: f
        characters: B
        timezone: B
        realmid: B
    unk2: B
    unk3: B

Result:
{
  "cmd": 16,
  "size": 48,
  "unk1": 0,
  "realm_list_size": 1,
  "realmlist": [
    {
      "icon": 0,
      "lock": 0,
      "flag": 32,
      "name": "PyPandaria",
      "address": "192.168.11.30:8084",
      "pop": 0.0,
      "characters": 3,
      "timezone": 1,
      "realmid": 1
    }
  ],
  "unk2": 16,
  "unk3": 0
}
