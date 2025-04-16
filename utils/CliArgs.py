import argparse

def parse_args():
    """
    Parse command-line arguments for BinaryPacketsDSL.

    Returns:
        argparse.Namespace: Parsed CLI arguments.
    """
    parser = argparse.ArgumentParser(description="BinaryPacketsDSL CLI")
    parser.add_argument("-u", "--update", action="store_true", help="Update .json output from .bin + .def")
    parser.add_argument("-a", "--add", action="store_true", help="Create new empty packet definition set")
    parser.add_argument("-f", "--file", type=str, required=False, help="Specify the packet file name (without extension)")
    parser.add_argument("-p", "--program", type=str, required=False, help="")
    parser.add_argument("-V", "--version", type=str, required=False, help="")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging output")
    parser.add_argument("-b", "--bin", type=str, help="Path to binary file to add")

    return parser.parse_args()
