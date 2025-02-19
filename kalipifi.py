#!/usr/bin/env python3
import os
import sys
import logging
import argparse

from config.config import LOG_FILE
from tools.hcxtool.hcxtool import Hcxtool
from utils.toolmenus import display_main_menu, EscapeSequenceFilter, cleanup_all_tools


def setup_logging():
    # Configure the root logger so that all logging calls use the same configuration.
    logger = logging.getLogger()  # root logger
    logger.setLevel(logging.DEBUG)

    # Stream handler with ANSI escape sequence filtering.
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    ch.addFilter(EscapeSequenceFilter())
    logger.addHandler(ch)

    # Add a FileHandler to log messages to the file specified in config.py.
    fh = logging.FileHandler(LOG_FILE)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)


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
    setup_logging()
    logging.info("Starting kali-pi tools")

    args = parse_args()

    if not args.non_interactive:
        try:
            display_main_menu()
        except Exception as e:
            logging.exception("Fatal error in interactive menu: %s", e)
            sys.exit(1)
    else:
        if not args.tool:
            logging.error("In non-interactive mode, you must specify a tool using --tool")
            sys.exit(1)
        if args.tool == "hcxtool":
            try:
                tool = Hcxtool(config_file="configs/hcxtool.yaml")
                tool.run(profile=args.profile)
            except Exception as e:
                logging.exception("Error running hcxtool: %s", e)
                sys.exit(1)
        else:
            logging.error(f"Tool '{args.tool}' not recognized.")
            sys.exit(1)

        # stop tool processes & release locked interfaces
        cleanup_all_tools()


if __name__ == "__main__":
    main()
