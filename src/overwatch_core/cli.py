# src/overwatch_core/cli.py
import argparse

from overwatch_core.brain.fake_llm_client import FakeLLMClient
from overwatch_core.config import settings
from overwatch_core.scanners.nmap_parser import parse_nmap_xml
from overwatch_core.scanners.nmap_runner import run_nmap_scan


def main():
    parser = argparse.ArgumentParser(prog="ow", description="Overwatch CLI")
    subparsers = parser.add_subparsers(dest="command")

    # nmap subcommand
    nmap_parser = subparsers.add_parser("nmap", help="Run Nmap through Overwatch")
    nmap_parser.add_argument("profile", help="Scan profile name (e.g. safe, balanced)")
    nmap_parser.add_argument("target", help="Target host or network")

    args = parser.parse_args()

    if args.command == "nmap":
        profile = args.profile
        target = args.target

        xml_path = run_nmap_scan(target, profile, settings)
        summary = parse_nmap_xml(xml_path)

        llm = FakeLLMClient()
        suggestions = llm.suggest_next_steps(summary)

        print("\n=== Scan Summary ===")
        print(summary)
        print("\n=== Suggested Next Steps ===")
        print(suggestions)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
