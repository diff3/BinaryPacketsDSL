# Proxy Overview

The proxy is a transparent TCP relay with advanced features. It forwards bytes unchanged and can optionally decode packets with the DSL to log or dump captures. This keeps the network path clean while making packet inspection easy. The auth/world proxies described below are WoW-specific implementations.
The proxy design is modular, so you can implement program-specific proxies when needed.

## High-Level Flow
1) Client connects to the proxy.
2) Proxy connects to the real server.
3) Traffic is forwarded in both directions.
4) When enabled, packets are decoded and logged/dumped.

## Auth Proxy (WoW)
- Handles the auth server stream.
- Auth opcodes are 1 byte, so framing is simple.
- DSL decode runs only when dump/focus is enabled.
- Captures are written per opcode name.

## World Proxy (WoW)
- Handles the world server stream.
- Pre-AUTH traffic is plaintext; post-AUTH traffic switches to ARC4 stream mode.
- DSL decode happens per packet via the packet interpreter.
- Filters and focus lists control what gets logged.

## Control Server (Optional)
- Simple telnet-style control interface.
- Toggles dump, filters, and visibility at runtime.
- Shares a single ControlState between auth and world proxies.
- Connect with `telnet localhost 1337` (unless overridden in config).

## Telnet Functionality
- `help` shows the full command list.
- `status` prints current dump/raw/debug/focus/filter state.
- `dump on|off` toggles capture dumping.
- `raw on|off` toggles raw payload logging.
- `debug on|off` toggles decoded JSON logging.
- `focus on|off` enables/disables focus filtering.
- `focus add|rm|clear|list <opcode>` manages the focus set.
- `focus promote <opcode>` promotes focused captures into protocol files.
- `filter add|remove|clear|list <pattern>` manages display filters (e.g. `CMSG_*`).
- `filter ignore add|rm|clear|list <opcode>` runtime blacklist.
- `filter whitelist add|rm|clear|list <opcode>` runtime allow-list override.
- `protocol add|rm|list|sync <opcode>` promotes or lists protocol artifacts.
- `protocol view def|debug|json <opcode>` shows stored artifacts.
- `promot ...` legacy alias for protocol promotion/removal.
- `capture delete all` wipes captures and recreates folders.
- `reset` restores runtime defaults.
- `clear` clears the screen.
- `quit` / `exit` closes the session.
- Tab completion works for commands and opcode names.

## Configuration Touchpoints
- `etc/config.yaml` (and optional per-program overlays).
- `auth_proxy` / `world_proxy`: listen and target endpoints.
- `control_server`: host/port and optional credentials.
- `program` / `expansion` / `version`: selects the DSL definitions.

## Entry Point
- `servers/proxyserver.py` starts the control server, the auth proxy, and the world proxy.
