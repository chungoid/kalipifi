import fcntl
import logging
import os
import select
import shlex
import subprocess
import time
from logging import exception
from pathlib import Path

from utils.helper import load_interfaces_config


class Tool:
    def __init__(self, name, description, base_dir, interfaces=None, settings=None):
        self.name = name
        self.description = description
        self.base_dir = Path(base_dir)
        self.interfaces = interfaces if interfaces else []
        self.settings = settings if settings is not None else {}
        self.load_interfaces()
        self.interface_locks = {}
        self.running_processes = {}
        self.require_root = True

        # Define standard subdirectories
        self.config_dir = self.base_dir / "configs"
        self.defaults_dir = self.base_dir / "defaults"
        self.results_dir = self.base_dir / "results"
        self.setup_directories()

        # Setup logger
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(logging.DEBUG)  # Adjust log level as needed
        handler = logging.StreamHandler()
        formatter = logging.Formatter(f"[{self.name}] %(levelname)s: %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.info(f"Initialized tool: {self.name}")


    @staticmethod
    def _interface_exists(iface):
        try:
            output = subprocess.check_output(["ip", "link", "show", iface], text=True)
            return iface in output
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    def cmd_to_string(cmd_list: list) -> str:
        print(f"received command list: {cmd_list}")
        cmd_str = None
        try:

            cmd_str = shlex.join(cmd_list)
            print(f"converted to command string: {cmd_str}")
        except Exception as e:
            print(f"failed to convert to command string: {e}")

        return cmd_str


    @staticmethod
    def check_uid():
        return os.geteuid()

    def get_require_root(self):
        return bool(self.require_root)

    def setup_directories(self):
        # Create directories if they do not exist.
        for d in [self.config_dir, self.defaults_dir, self.results_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def get_path(self, category, filename=""):
        """
        Retrieve a filepath for a given category.

        :param category: one of "config", "defaults", or "results"
        :param filename: optional filename to append
        :return: a pathlib.Path object
        """
        if category == "configs":
            base = self.config_dir
        elif category == "defaults":
            base = self.defaults_dir
        elif category == "results":
            base = self.results_dir
        else:
            raise ValueError(f"Unknown category: {category}")
        return base / filename

    def load_interfaces(self):
        # Build the config file path based on the tool's name.
        config_file = self.base_dir / "configs" / f"{self.name}.yaml"
        if config_file.exists():
            config_data = load_interfaces_config(config_file)
            # Assume that the YAML file has an 'interfaces' key with subcategories.
            self.interfaces = config_data.get("interfaces", {})
        else:
            self.interfaces = {}

    def validate_interfaces(self):
        # Iterate over each interface in each category.
        for category, iface_list in self.interfaces.items():
            for iface_info in iface_list:
                iface_name = iface_info.get("name") or iface_info.get("device")
                if category == "wlan":
                    # For wlan, check that the interface exists.
                    if not self._interface_exists(iface_name):
                        print(f"Error: {iface_name} does not exist.")
                # Optionally add validations for bluetooth or gpsd if needed.
        return True

    def reserve_interface(self, iface):
        """Attempt to reserve an interface exclusively."""
        lock = InterfaceLock(iface)
        if lock.acquire():
            self.interface_locks[iface] = lock
            return True
        else:
            print(f"Interface {iface} is already in use.")
            return False

    def setup_tmux_session(self, tool_name: str):
        """
        Creates a named tmux session for the tool if not already running.
        Returns True if tmux session is enabled, False otherwise.
        """

        # Check if the tmux session exists; if not, create it
        check_session_cmd = f"tmux has-session -t {tool_name} 2>/dev/null"
        try:
            if subprocess.call(check_session_cmd, shell=True) != 0:
                self.logger.info(f"Creating new tmux session for {tool_name}")
                subprocess.call(f"tmux new-session -d -s {tool_name}", shell=True)
        except subprocess.CalledProcessError:
            self.logger.critical(f"Failed to create new tmux session for {tool_name}")
            return False
        except Exception as e:
            self.logger.critical(f"Failed to create new tmux session for {tool_name} \n Error: {e}")
            return False

        return

    def run_in_shell(self, cmd: str):
        """
        Runs a command directly in the shell (non-tmux mode).
        """
        cmd_str = shlex.join(cmd)  # Safer string conversion for shell execution
        self.logger.info(f"Executing in shell: {cmd_str}")

        try:
            process = subprocess.Popen(cmd_str, shell=True)
            return process  # Return process object for monitoring if needed
        except Exception as e:
            self.logger.error(f"Failed to execute command in shell: {e}")
            return None

    def run_in_tmux(self, tool_name: str, window_id: str, cmd_str: str):
        """
        Runs a command inside a new tmux window attached to the tool's session and returns the window name.
        """
        window = f"{tool_name}:{window_id}"
        if self.setup_tmux_session(tool_name):
            try:
                tmux_cmd = f'tmux new-window -t {tool_name} -n {window_id} "{cmd_str}"'
                self.logger.info(f"Creating new tmux window: {window}")

                subprocess.Popen(tmux_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True)

            except Exception as e:
                self.logger.critical(f"Failed to create new tmux window: {window} \n Error: {e}")
                return None

        return window

    import time
    import subprocess

    def _monitor_process(self, process_or_tmux, profile) -> None:
        """
        Monitors either a normal process or a tmux window.
        """
        if isinstance(process_or_tmux, str):  # It's a tmux window name
            self.logger.info(f"Monitoring tmux window: {process_or_tmux}")

            while True:
                try:
                    # Check if tmux window exists
                    result = subprocess.run(f"tmux list-windows -F '#I' -t {process_or_tmux.split(':')[0]}",
                                            shell=True, capture_output=True, text=True)

                    if process_or_tmux.split(":")[1] not in result.stdout.split():
                        self.logger.info(f"Tmux window {process_or_tmux} has closed.")
                        break  # Exit monitoring when the window disappears

                except Exception as e:
                    self.logger.error(f"Error monitoring tmux window: {e}")
                    break  # Exit on failure

                time.sleep(2)  # Avoid high CPU usage

        else:  # Normal process monitoring
            self.logger.info(f"Monitoring process for profile '{profile}'...")

            while process_or_tmux.poll() is None:
                time.sleep(1)

            if process_or_tmux.returncode != 0:
                self.logger.error(
                    f"Process for profile '{profile}' failed with exit code {process_or_tmux.returncode}.")
            else:
                self.logger.info(f"Process for profile '{profile}' finished successfully.")

        self.release_interfaces()
        self.running_processes.pop(profile, None)
        self.logger.info(f"Released interface locks for profile '{profile}'.")

    def stop(self, profile) -> None:
        """
        Stop a running scan process for the given profile.
        If it's a subprocess, terminate it.
        """
        if hasattr(self, "running_processes") and profile in self.running_processes:
            proc = self.running_processes[profile]
            if proc.poll() is None:
                proc.terminate()

    def release_interfaces(self):
        """Release any reserved interfaces."""
        for lock in self.interface_locks.values():
            lock.release()
        self.interface_locks = {}

    def run(self):
        if self.get_require_root() and self.check_uid != 0:
            self.logger.warning(f"Root is required to run this tool.")
            return False

        return

    def cleanup(self):
        # Terminate all running processes for this tool.
        for profile, proc in list(self.running_processes.items()):
            if proc.poll() is None:  # still running
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception as e:
                    print(f"Error terminating process for profile {profile}: {e}")
        self.running_processes.clear()
        # Release any reserved interfaces.
        self.release_interfaces()


class InterfaceLock:
    def __init__(self, iface, lock_dir="/var/lock"):
        self.iface = iface
        self.lock_file = os.path.join(lock_dir, f"{iface}.lock")
        self.fd = None

    def acquire(self):
        try:
            self.fd = os.open(self.lock_file, os.O_CREAT | os.O_RDWR)
            # Try to acquire an exclusive lock (non-blocking).
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Write our PID into the file (optional).
            os.write(self.fd, str(os.getpid()).encode())
            return True
        except OSError:
            return False

    def release(self):
        if self.fd:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
                os.close(self.fd)
                os.remove(self.lock_file)
            except Exception as e:
                print(f"Error releasing lock for {self.iface}: {e}")
