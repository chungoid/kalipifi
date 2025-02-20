import os
import re
import select
import subprocess
import logging
import sys
import time

import yaml
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from utils.tool_registry import tool_registry


logger = logging.getLogger(__name__)
logger.propagate = True

global_root = False

def set_root():
    os.setuid(0)
    global global_root
    global_root = True

def check_root():
    return global_root

def run_command(command: str) -> Optional[str]:
    """
    Execute a shell command and return its output.

    Parameters:
        command (str): The command to execute.

    Returns:
        Optional[str]: The command output if successful; otherwise, None.
    """
    try:
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT, text=True
        )
        return output.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command '{command}': {e.output}")
        return None


def generate_default_prefix() -> str:
    """
    Generate a default output prefix based on the current date and time.
    The same timestamp is used for both NMEA and PCAPNG for easier pairing.

    Returns:
        str: The generated prefix string.
    """
    return datetime.now().strftime("%d-%m_%H:%M")


def get_mac_address(interface: str) -> Optional[str]:
    """
    Retrieve the MAC address of a given interface by reading from sysfs.
    This is generally more stable than parsing ip output.

    Parameters:
        interface (str): The name of the interface.

    Returns:
        Optional[str]: The MAC address if found; otherwise, None.
    """
    try:
        with open(f"/sys/class/net/{interface}/address", "r") as f:
            mac = f.read().strip()
            return mac
    except Exception as e:
        logger.warning(f"Could not read MAC address from /sys/class/net/{interface}/address: {e}")
        return None


def check_client_macs(interfaces: List[str]) -> List[str]:
    """
    Scan the provided interfaces for associated client MAC addresses.

    For each interface, uses 'sudo iw dev <iface> station dump'
    to extract connected client MAC addresses.

    Parameters:
        interfaces (List[str]): A list of interface names.

    Returns:
        List[str]: A unique list of client MAC addresses.
    """
    client_macs = set()
    for iface in interfaces:
        output = run_command(f"sudo iw dev {iface} station dump")
        if output:
            for line in output.splitlines():
                if line.startswith("Station "):
                    parts = line.split()
                    if len(parts) >= 2:
                        client_macs.add(parts[1])
        else:
            logger.warning(f"Warning: Could not retrieve station dump for interface {iface}")
    logger.info(f"Found associated client MAC(s): {client_macs}")
    return list(client_macs)

def create_bpf_filter(
        scan_interface: str,
        filter_path: Path,
        prefilter_path: Path,  # This may become unused if we pass filter_expr directly.
        interfaces: List[str],
        extra_macs: Optional[List[str]] = None
) -> bool:
    """
    Generate a BPF filter that excludes packets from all interfaces except the scanning interface.
    Also includes MAC addresses of clients on non-scanning interfaces and any additional MAC addresses.

    The filter expression is passed directly to hcxdumptool for compilation.

    Parameters:
        scan_interface (str): The interface being used for scanning.
        filter_path (Path): Path to write the compiled BPF filter.
        prefilter_path (Path): Unused now; kept for backward compatibility.
        interfaces (List[str]): List of all wireless interface names.
        extra_macs (Optional[List[str]]): Additional MAC addresses to exclude.

    Returns:
        bool: True if the filter was generated and applied successfully; otherwise, False.
    """
    # Exclude the scanning interface.
    other_interfaces = [iface for iface in interfaces if iface != scan_interface]

    macs: List[str] = []
    for iface in other_interfaces:
        mac = get_mac_address(iface)
        if mac:
            macs.append(mac)
        else:
            logger.warning(f"Warning: Could not retrieve MAC address for {iface}")

    # Include client MACs.
    client_macs = check_client_macs(other_interfaces)
    if client_macs:
        print(f"Found client MACs: {client_macs}")
        macs.extend(client_macs)

    # Include any additional MAC addresses.
    if extra_macs:
        print(f"Found extra MACs: {extra_macs}")
        macs.extend(extra_macs)

    if not macs:
        print(f"No MAC addresses found; aborting BPF filter generation to avoid interfering with own connections.")
        return False

    # Build filter expression using grouped OR inside a NOT.
    clauses = [f"wlan addr2 {mac}" for mac in macs]
    filter_expr = "not (" + " or ".join(clauses) + ")"

    print(f"Generated BPF filter expression: {filter_expr}")

    # Optionally, you can still write the filter expression to a prefilter file for logging.
    try:
        with prefilter_path.open("w") as f:
            f.write(filter_expr)
        print(f"BPF prefilter written to {prefilter_path}")
    except IOError as e:
        print(f"Error writing to {prefilter_path}: {e}")
        return False

    # Backup existing filter file if it exists.
    if filter_path.exists():
        backup_file = filter_path.with_suffix(".bak")
        try:
            filter_path.rename(backup_file)
            print(f"BPF filter already exists, backed up to {backup_file}")
        except Exception as e:
            logger.error(f"Error backing up existing filter file: {e}")
            return False

    # Now pass the filter expression directly to hcxdumptool.
    try:
        cmd = f'hcxdumptool --bpfc="{filter_expr}" > {filter_path}'
        if run_command(cmd) is None:
            print("hcxdumptool failed to compile the BPF filter")
            return False
    except Exception as e:
        print(f"Error generating BPF filter file: {e}")
        return False

    print(f"BPF filter generated: {filter_path.resolve()}")
    return True


def load_interfaces_config(config_file: Path) -> Dict[str, Any]:
    """
    Load and return the interface configuration from a YAML file.

    Parameters:
        config_file (Path): The path to the configuration file.

    Returns:
        Dict[str, Any]: The loaded YAML configuration.
    """
    with config_file.open("r") as f:
        return yaml.safe_load(f)

def cleanup_all_tools():
    for tool in tool_registry:
        try:
            tool.cleanup()
        except Exception as e:
            logger.exception("Error cleaning up tool %s: %s", tool.name, e)

def flush_stdin(timeout=0.1):
    """Flush any pending input from stdin."""
    time.sleep(timeout)
    while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
        sys.stdin.read(1)


class EscapeSequenceFilter(logging.Filter):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')

    def filter(self, record):
        # Remove ANSI escape sequences from the message.
        record.msg = self.ansi_escape.sub('', record.msg)
        return True

''''''''''
def run_command_with_root(cmd: list, prompt: bool = True, **kwargs) -> "subprocess.Popen":

    Runs the given command with root privileges.
    If not running as root and prompt is True, prompts the user to run the command with sudo.

    Parameters:
        cmd (list): The command to run (as a list of arguments).
        prompt (bool): Whether to prompt the user before prepending 'sudo'.
        **kwargs: Additional keyword arguments passed to subprocess.Popen.

    Returns:
        subprocess.Popen: The process handle.

    Raises:
        PermissionError: If the user declines to run with sudo.
    
    
    if os.geteuid() != 0:
        if prompt:
            answer = input("This tool requires root privileges. Run command with sudo? (y/n): ").strip().lower()
            if answer != "y":
                raise PermissionError("Tool requires root privileges. Aborting command.")
        # Prepend sudo -E to preserve the current environment (e.g., virtualenv settings)
        cmd = ["sudo", "-E"] + cmd
    return subprocess.Popen(cmd, **kwargs)
'''''''''