#!/usr/bin/env python3
import sys
import os
import logging
import argparse

from config.config import LOG_FILE, LOG_DIR
from utils import helper
from utils.tool_registry import main_menu
from tools.hcxtool import hcxtool


def setup_logging():
    """Sets up logging to file and console output."""
    # Ensure log directory exists
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Configure root logger
    logger = logging.getLogger()  # Root logger
    logger.setLevel(logging.DEBUG)

    # Stream handler (console)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler (logs to file)
    fh = logging.FileHandler(LOG_FILE)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)


def parse_args():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Kali-Pi Tools Main Script")
    parser.add_argument("--user", action="store_true", default=False,
                        help="Run tool as non-root user. (affects tmux))")
    return parser.parse_args()


def main():
    """Main execution function."""
    setup_logging()
    logging.info("Starting KaliPi Tools...")

    args = parse_args()

    # DEBUG: Print config file path before passing it
    config_path = "configs/config.yaml"
    print(f"DEBUG: Passing config file to main_menu(): {config_path}")

    if args.user:
        try:
            if os.getuid() != 0:
                logging.info("Running as non-root, limited functionality enabled.")
                main_menu(config_file=config_path)  # Explicitly pass config file
            else:
                logging.warning("Running as root with --user option. Exiting...")
                sys.exit(0)
        except Exception as e:
            logging.error(f"Error in user mode: {e}")
    else:
        try:
            helper.set_root()
            if os.getuid() == 0:
                logging.info(f"Running as Root: {bool(helper.check_root())}")
                main_menu(config_file=config_path)  # Explicitly pass config file
            else:
                logging.error("Unable to set root. Please run with sudo or use --user option.")
        except PermissionError:
            logging.error("Root privileges required. Run with sudo or enable --user mode. Exiting...")
        except Exception as e:
            logging.error(f"Error: {e}")


if __name__ == "__main__":
    main()
