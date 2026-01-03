from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

SOURCE_DIR = Path("/home/magnus/projects/Webtorkel")
OUT_DIR = Path("/home/magnus/projects/BinaryPacketsDSL/webtorkel_sql")

TEXT_TABLES = 226
TEXT_LINES_PER_TABLE = 8
OPTIONS_PER_TABLE = 6
PROP_COLUMNS = 38


def read_lines(path: Path, encoding: str) -> List[str]:
    with path.open("r", encoding=encoding, newline="") as handle:
        raw_lines = handle.readlines()
    # Preserve empty lines and trailing spaces; strip only newline characters.
    return [line.rstrip("\n").rstrip("\r") for line in raw_lines]


def sql_escape(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def write_schema(out_path: Path) -> None:
    lines: List[str] = [
        "CREATE DATABASE IF NOT EXISTS webtorkel CHARACTER SET utf8mb4 COLLATE utf8mb4_swedish_ci;",
        "USE webtorkel;",
        "",
        "CREATE TABLE IF NOT EXISTS table_text (",
        "  table_id INT NOT NULL,",
        "  label TEXT,",
        "  title TEXT,",
        "  option_1 TEXT,",
        "  option_2 TEXT,",
        "  option_3 TEXT,",
        "  option_4 TEXT,",
        "  option_5 TEXT,",
        "  option_6 TEXT,",
        "  PRIMARY KEY (table_id)",
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_swedish_ci;",
        "",
        "CREATE TABLE IF NOT EXISTS table_option_properties (",
        "  table_id INT NOT NULL,",
        "  option_index INT NOT NULL,",
    ]
    for idx in range(PROP_COLUMNS):
        suffix = "," if idx < PROP_COLUMNS - 1 else ","
        lines.append(f"  c{idx} INT NOT NULL{suffix}")
    lines.extend(
        [
            "  PRIMARY KEY (table_id, option_index)",
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_swedish_ci;",
            "",
            "CREATE TABLE IF NOT EXISTS opponents (",
            "  opponent_id INT NOT NULL,",
            "  correction INT NOT NULL,",
            "  xp INT NOT NULL,",
            "  PRIMARY KEY (opponent_id)",
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_swedish_ci;",
            "",
            "CREATE TABLE IF NOT EXISTS combat_texts (",
            "  combat_id INT NOT NULL,",
            "  text TEXT,",
            "  PRIMARY KEY (combat_id)",
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_swedish_ci;",
            "",
            "CREATE TABLE IF NOT EXISTS info_lines (",
            "  line_index INT NOT NULL,",
            "  text TEXT,",
            "  PRIMARY KEY (line_index)",
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_swedish_ci;",
            "",
        ]
    )
    out_path.write_text("\n".join(lines), encoding="utf-8")


def write_text_import(out_path: Path) -> None:
    lines = read_lines(SOURCE_DIR / "text.txt", encoding="iso-8859-1")
    expected = TEXT_TABLES * TEXT_LINES_PER_TABLE
    if len(lines) != expected:
        raise ValueError(f"text.txt has {len(lines)} lines, expected {expected}")

    output: List[str] = ["USE webtorkel;"]
    idx = 0
    for table_id in range(TEXT_TABLES):
        chunk = lines[idx : idx + TEXT_LINES_PER_TABLE]
        idx += TEXT_LINES_PER_TABLE
        label = chunk[0]
        title = chunk[1]
        options = chunk[2:8]
        values = [
            str(table_id),
            sql_escape(label),
            sql_escape(title),
        ] + [sql_escape(value) for value in options]
        columns = "table_id, label, title, option_1, option_2, option_3, option_4, option_5, option_6"
        output.append(
            f"INSERT INTO table_text ({columns}) VALUES ({', '.join(values)});"
        )
    output.append("")
    out_path.write_text("\n".join(output), encoding="utf-8")


def write_properties_import(out_path: Path) -> None:
    raw_lines = read_lines(SOURCE_DIR / "egenskaper.txt", encoding="ascii")
    data_rows: List[List[int]] = []
    for line in raw_lines:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != PROP_COLUMNS:
            raise ValueError(
                f"egenskaper.txt line has {len(parts)} columns, expected {PROP_COLUMNS}: {line!r}"
            )
        data_rows.append([int(value) for value in parts])

    expected = (TEXT_TABLES - 1) * OPTIONS_PER_TABLE
    if len(data_rows) != expected:
        raise ValueError(
            f"egenskaper.txt has {len(data_rows)} data rows, expected {expected} (tables 1-225)"
        )

    output: List[str] = ["USE webtorkel;"]
    for index, row in enumerate(data_rows):
        table_id = (index // OPTIONS_PER_TABLE) + 1
        option_index = (index % OPTIONS_PER_TABLE) + 1
        columns = ["table_id", "option_index"] + [f"c{i}" for i in range(PROP_COLUMNS)]
        values = [str(table_id), str(option_index)] + [str(value) for value in row]
        output.append(
            f"INSERT INTO table_option_properties ({', '.join(columns)}) VALUES ({', '.join(values)});"
        )
    output.append("")
    out_path.write_text("\n".join(output), encoding="utf-8")


def write_opponents_import(out_path: Path) -> None:
    raw_lines = read_lines(SOURCE_DIR / "motstandare.txt", encoding="ascii")
    data_rows: List[List[int]] = []
    for line in raw_lines:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ValueError(
                f"motstandare.txt line has {len(parts)} columns, expected 2: {line!r}"
            )
        data_rows.append([int(value) for value in parts])

    output: List[str] = ["USE webtorkel;"]
    for opponent_id, (correction, xp) in enumerate(data_rows):
        output.append(
            "INSERT INTO opponents (opponent_id, correction, xp) "
            f"VALUES ({opponent_id}, {correction}, {xp});"
        )
    output.append("")
    out_path.write_text("\n".join(output), encoding="utf-8")


def write_combat_texts_import(out_path: Path) -> None:
    lines = read_lines(SOURCE_DIR / "stridtext.txt", encoding="iso-8859-1")
    output: List[str] = ["USE webtorkel;"]
    for combat_id, text in enumerate(lines):
        output.append(
            "INSERT INTO combat_texts (combat_id, text) "
            f"VALUES ({combat_id}, {sql_escape(text)});"
        )
    output.append("")
    out_path.write_text("\n".join(output), encoding="utf-8")


def write_info_import(out_path: Path) -> None:
    lines = read_lines(SOURCE_DIR / "info.txt", encoding="utf-8")
    output: List[str] = ["USE webtorkel;"]
    for line_index, text in enumerate(lines):
        output.append(
            "INSERT INTO info_lines (line_index, text) "
            f"VALUES ({line_index}, {sql_escape(text)});"
        )
    output.append("")
    out_path.write_text("\n".join(output), encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_schema(OUT_DIR / "schema.sql")
    write_text_import(OUT_DIR / "import_text.sql")
    write_properties_import(OUT_DIR / "import_egenskaper.sql")
    write_opponents_import(OUT_DIR / "import_motstandare.sql")
    write_combat_texts_import(OUT_DIR / "import_stridtext.sql")
    write_info_import(OUT_DIR / "import_info.sql")


if __name__ == "__main__":
    main()
