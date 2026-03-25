#!/usr/bin/env python3

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.modules.handlers.worldLogin.packets import (
    format_first_login_update_object_capture,
    format_update_object_player_create_diff_with_expected,
)


def main() -> None:
    session = SimpleNamespace(
        map_id=1,
        char_guid=2,
        x=16228.0,
        y=16290.8,
        z=31.7148,
        orientation=1.5811,
        walk_speed=2.5,
        run_speed=7.0,
        run_back_speed=4.5,
        swim_speed=4.5,
        swim_back_speed=2.5,
        fly_speed=7.0,
        fly_back_speed=4.5,
        turn_speed=3.1415926,
        pitch_speed=3.1415926,
        health=103,
        max_health=103,
        power_primary=100,
        max_power_primary=100,
        level=1,
        player_bytes=198401,
        player_bytes2=16777224,
    )
    print(format_first_login_update_object_capture())
    print()
    print(format_update_object_player_create_diff_with_expected(session))


if __name__ == "__main__":
    main()
