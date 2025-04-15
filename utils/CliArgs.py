import argparse

def parse_args():
    """
    Parse command-line arguments for BinaryPacketsDSL.

    Returns:
        argparse.Namespace: Parsed CLI arguments.
    """
    parser = argparse.ArgumentParser(description="BinaryPacketsDSL CLI")
    parser.add_argument("--update", action="store_true", help="Update .json output from .bin + .def")
    parser.add_argument("--add", action="store_true", help="Create new empty packet definition set")
    parser.add_argument("--file", type=str, required=False, help="Specify the packet file name (without extension)")
    parser.add_argument("--dry-run", action="store_true", help="Run without writing any files")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging output")

    return parser.parse_args()
