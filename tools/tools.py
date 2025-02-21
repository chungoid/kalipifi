import errno
import fcntl
import logging
import os
import shlex
import subprocess
import time
from pathlib import Path

from utils.helper import load_interfaces_config


class Tool:
    def __init__(self, name, description, base_dir, interfaces=None, settings=None):
        self.name = name

        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(logging.DEBUG)
        # Only add a handler if none exist yet.
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(f"[{self.name}] %(levelname)s: %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.logger.propagate = False
        self.logger.info(f"Initialized tool: {self.name}")

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

    def menu(self):
        return self.submenu()

    def submenu(self):
        logging.error("submenu not implemented")
        pass

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
        config_file = self.base_dir / "configs" / f"config.yaml"
        if config_file.exists():
            config_data = load_interfaces_config(config_file)
            # Assume that the YAML file has an 'interfaces' key with subcategories.
            self.interfaces = config_data.get("interfaces", {})
        else:
            self.interfaces = {}

        self.check_interface_locks()

    def check_interface_locks(self, lock_dir="/var/lock"):
        """
        Iterates over known interfaces and clears any stale lock files.
        """
        for iface in self.interfaces:
            iface_name = iface if isinstance(iface, str) else iface.get("name", "")
            lock = InterfaceLock(iface_name, lock_dir=lock_dir)
            if os.path.exists(lock.lock_file):
                if lock.is_stale():
                    self.logger.info(f"Stale lock detected for interface {iface_name}. Removing stale lock.")
                    try:
                        os.remove(lock.lock_file)
                    except Exception as e:
                        self.logger.error(f"Error removing stale lock for {iface_name}: {e}")
                else:
                    self.logger.info(f"Interface {iface_name} is currently locked by an active process.")
            else:
                self.logger.debug(f"No lock file exists for interface {iface_name}.")

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
                self.logger.info(f"Creating new tmux session named: {tool_name}")
                subprocess.call(f"tmux new-session -d -s {tool_name}", shell=True)
        except subprocess.CalledProcessError:
            self.logger.critical(f"Failed to create new tmux session named: {tool_name}")
            return False
        except Exception as e:
            self.logger.critical(f"Failed to create new tmux session for {tool_name} \n Error: {e}")
            return False

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
        window = f"{tool_name}:{window_id}"
        if self.setup_tmux_session(tool_name):
            try:
                # Wrap the command in a bash -c call. 'exec bash' ensures the window remains open after the command finishes.
                tmux_cmd = f'tmux new-window -t {tool_name} -n {window_id} "bash -c \'{cmd_str}; exec bash\'"'
                self.logger.info(f"Creating new tmux window named: {window} for session named: {tool_name}")
                subprocess.Popen(tmux_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            except Exception as e:
                self.logger.critical(f"Failed to create new tmux window: {window} \n Error: {e}")
                return None
        return window

    def _monitor_tmux_window(self, tmux_window: str, profile) -> None:
        """
        Monitors a tmux window given its identifier (e.g., "hcxtool:wlan1").
        Waits until the window no longer exists, then cleans up.
        """
        self.logger.info(f"Monitoring tmux window: {tmux_window}")
        session, window_name = tmux_window.split(":")

        while True:
            try:
                # List window names using the '#W' format (one per line)
                result = subprocess.run(
                    f"tmux list-windows -F '#W' -t {session}",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                # Log the raw output for debugging
                self.logger.debug(f"tmux list-windows output: {result.stdout!r}")

                # Split and strip each line to remove extraneous whitespace
                window_list = [w.strip() for w in result.stdout.splitlines()]
                self.logger.debug(f"Window list for session {session}: {window_list}")

                if window_name.strip() not in window_list:
                    self.logger.info(f"Tmux window {tmux_window} has closed.")
                    break  # Exit monitoring when the window is gone
            except Exception as e:
                self.logger.error(f"Error monitoring tmux window: {e}")
                break  # Exit on failure

            time.sleep(2)  # Avoid busy waiting

        self.release_interfaces()
        self.running_processes.pop(profile, None)
        self.logger.info(f"Released interface locks for profile '{profile}'.")

    def _monitor_shell_process(self, process: subprocess.Popen, profile) -> None:
        """
        Monitors a normal shell process until it exits.
        Logs the process result and performs cleanup.
        """
        self.logger.info(f"Monitoring process for profile '{profile}'...")
        while process.poll() is None:
            time.sleep(1)

        if process.returncode != 0:
            self.logger.error(
                f"Process for profile '{profile}' failed with exit code {process.returncode}."
            )
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

    def is_stale(self):
        """Return True if the lock file contains a PID that is no longer running."""
        try:
            with open(self.lock_file, 'r') as f:
                pid_str = f.read().strip()
                if pid_str:
                    pid = int(pid_str)
                    # os.kill(pid, 0) will raise an OSError if the PID is not running.
                    os.kill(pid, 0)
                    # Process is still running.
                    return False
        except (OSError, ValueError):
            # Either the file can't be read, the PID is invalid, or the process is dead.
            return True
        return True

    def acquire(self):
        # If a lock file exists, check if it's stale.
        if os.path.exists(self.lock_file):
            if self.is_stale():
                print(f"Stale lock detected for interface {self.iface}. Removing stale lock.")
                try:
                    os.remove(self.lock_file)
                except Exception as e:
                    print(f"Error removing stale lock for {self.iface}: {e}")
                    return False
            else:
                print(f"Interface {self.iface} is already locked.")
                return False

        try:
            self.fd = os.open(self.lock_file, os.O_CREAT | os.O_RDWR)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Clear file contents and write our PID.
            os.ftruncate(self.fd, 0)
            os.write(self.fd, str(os.getpid()).encode())
            return True
        except OSError as e:
            if e.errno in (errno.EACCES, errno.EAGAIN):
                print(f"Interface {self.iface} is already locked (EAGAIN).")
            else:
                print(f"Error acquiring lock for {self.iface}: {e}")
            return False

    def release(self):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
                os.close(self.fd)
                os.remove(self.lock_file)
                self.fd = None
            except Exception as e:
                print(f"Error releasing lock for {self.iface}: {e}")





