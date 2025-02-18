#!/usr/bin/env python3
import os
import sys
import logging
import argparse

from config import config
from tools.hcxtools.hcxtool import Hcxtool

def setup_logging():
    log_file = config.LOG_FILE
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename=log_file,
        filemode='a'  # Append mode
    )

def parse_args():
    parser = argparse.ArgumentParser(description="kali-pi tools main script")
    parser.add_argument("--tool", type=str, choices=["hcxtool"],
                        help="Select the tool to run (if non-interactive mode is desired)")
    parser.add_argument("--profile", type=str,
                        help="Specify the scan profile to run (e.g. 1, 2, etc.)")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Run in non-interactive mode using provided options")
    return parser.parse_args()

def main():
    args = parse_args()
    setup_logging()
    logging.info("Starting kali-pi tools")

    # By default, run in interactive mode.
    if not args.non_interactive:
        try:
            from utils.toolmenus import display_main_menu
            display_main_menu()
        except ImportError:
            logging.error("Interactive menu not available.")
            sys.exit(1)
    else:
        # Non-interactive mode: require --tool to be specified.
        if not args.tool:
            logging.error("In non-interactive mode, you must specify a tool using --tool")
            sys.exit(1)
        if args.tool == "hcxtool":
            tool = Hcxtool(config_file="config/hcxtool.yaml")
            tool.run(profile=args.profile)
        else:
            logging.error(f"Tool '{args.tool}' not recognized.")
            sys.exit(1)

if __name__ == "__main__":
    main()
