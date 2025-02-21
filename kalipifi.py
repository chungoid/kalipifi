#!/usr/bin/env python3
import sys
import os
import logging
import argparse

import utils.tool_registry
from config.config import LOG_FILE, LOG_DIR
from utils import helper
from tools.hcxtool import hcxtool

def setup_logging():
    # Ensure the log directory exists.
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Configure the root logger so that all logging calls use the same configuration.
    logger = logging.getLogger()  # root logger
    logger.setLevel(logging.DEBUG)

    # Stream handler with ANSI escape sequence filtering.
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    #ch.addFilter(EscapeSequenceFilter())
    logger.addHandler(ch)

    # Add a FileHandler to log messages to the file specified in config.py.
    fh = logging.FileHandler(LOG_FILE)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)


def parse_args():
    parser = argparse.ArgumentParser(description="kali-pi tools main script")
    parser.add_argument("--user", action="store_true", default=False,
                        help="Run tool as non-root user. (effects tmux))")

    return parser.parse_args()

def main():
    setup_logging()
    logging.info("Starting kalipify.py")

    args = parse_args()

    if args.user:
        try:
            if os.getuid() != 0:
                logging.info(f"Running as non-root, will limit functionality.")
                utils.tool_registry.main_menu()
            elif os.getuid() == 0:
                logging.warning("Running as root with --user option. "
                                "Run without sudo if using --user option. Exiting...")
                sys.exit(0)
        except Exception as e:
            logging.error(e)
    else:
        try:
            utils.helper.set_root()
            if os.getuid() == 0:
                logging.info(f"Running as Root: {bool(helper.check_root)}")
                utils.tool_registry.main_menu()
            else:
                if not args.user and os.getuid() != 0:
                    logging.error("Unable to set root. Please run with sudo if not using --user option.")
        except PermissionError:
            logging.error("Kalipifi.py defaults to root, either run with sudo or enable --user option to disable "
                          "root permissions. Exiting...")
        except Exception as e:
            logging.error(f"Error: {e}")

    helper.cleanup_all_tools()

if __name__ == "__main__":
    main()
