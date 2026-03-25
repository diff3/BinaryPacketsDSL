import json
from pathlib import Path

from DSL.tools import packet_diff


def _write_packet(
    path: Path,
    *,
    name: str,
    hex_compact: str | None = None,
    raw_data_hex: str | None = None,
    raw_header_hex: str | None = None,
) -> None:
    payload = {"name": name}
    if hex_compact is not None:
        payload["hex_compact"] = hex_compact
    if raw_data_hex is not None:
        payload["raw_data_hex"] = raw_data_hex
    if raw_header_hex is not None:
        payload["raw_header_hex"] = raw_header_hex
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_load_packet_prefers_hex_compact_payload(tmp_path):
    path = tmp_path / "packet.json"
    _write_packet(
        path,
        name="TEST_PACKET",
        hex_compact="AABBCC",
        raw_data_hex="FF AABBCC",
        raw_header_hex="FF",
    )

    packet = packet_diff.load_packet(str(path))

    assert packet["source_key"] == "hex_compact"
    assert packet["bytes"] == bytes.fromhex("AABBCC")
    assert packet["includes_header"] is False


def test_normalize_packet_bytes_ignores_header_for_raw_data_hex(tmp_path):
    path = tmp_path / "packet.json"
    _write_packet(
        path,
        name="TEST_PACKET",
        raw_data_hex="AA BB CC DD",
        raw_header_hex="AA",
    )

    packet = packet_diff.load_packet(str(path))
    normalized = packet_diff.normalize_packet_bytes(packet, ignore_header=True, offset=1)

    assert normalized == bytes.fromhex("CCDD")


def test_build_comparison_pairs_supports_pairwise_and_cross_compare():
    pairwise = packet_diff.build_comparison_pairs(
        ["a1", "a2"],
        ["b1", "b2", "b3"],
    )
    cross = packet_diff.build_comparison_pairs(
        ["a1", "a2"],
        ["b1", "b2"],
        cross_compare=True,
    )

    assert pairwise == [("a1", "b1"), ("a2", "b2")]
    assert cross == [("a1", "b1"), ("a1", "b2"), ("a2", "b1"), ("a2", "b2")]


def test_diff_bytes_and_analyze_positions():
    diffs = packet_diff.diff_bytes(bytes.fromhex("AABBCC"), bytes.fromhex("AABD"))
    analysis = packet_diff.analyze_positions(
        [
            (bytes.fromhex("AABB"), bytes.fromhex("AABC")),
            (bytes.fromhex("1122"), bytes.fromhex("1133")),
        ]
    )

    assert diffs == [1, 2]
    assert analysis == {
        "stable_positions": [0],
        "variable_positions": [1],
    }


def test_run_batch_mode_pairwise_and_global_analysis(tmp_path, capsys):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()

    _write_packet(dir_a / "AUTH_001.json", name="AUTH", hex_compact="AABB")
    _write_packet(dir_a / "AUTH_002.json", name="AUTH", hex_compact="AACC")
    _write_packet(dir_b / "AUTH_001.json", name="AUTH", hex_compact="AABC")
    _write_packet(dir_b / "AUTH_002.json", name="AUTH", hex_compact="AADD")

    result = packet_diff.run_batch_mode(
        [
            str(dir_a / "*.json"),
            str(dir_b / "*.json"),
            "--analyze",
        ]
    )
    output = capsys.readouterr().out

    assert result == 0
    assert "=== COMPARISON 1 ===" in output
    assert "=== COMPARISON 2 ===" in output
    assert "=== GLOBAL ANALYSIS ===" in output
    assert "Total comparisons: 2" in output
