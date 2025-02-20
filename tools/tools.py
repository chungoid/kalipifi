import fcntl
import logging
import os
import select
import shlex
import subprocess
import time
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

        if self.setup_tmux_session(tool_name):
            tmux_window = f"{tool_name}:{window_id}"
            tmux_cmd = f'tmux new-window -t {tool_name} -n {window_id} "{cmd_str}"'
            self.logger.info(f"Creating new tmux window_id: {window_id}")

            # Run the command and check for errors
            result = subprocess.run(tmux_cmd, shell=True, capture_output=True, text=True)

            if result.returncode != 0:
                self.logger.critical(f"Tmux command failed: {result.stderr}")
                return None  # Prevent scan from running

            return tmux_window  # Return window ID if successful

        else:
            self.logger.critical(f"Failed to create new tmux window for {tool_name} \n {cmd_str}")
            return None

    def _monitor_process(self, process: subprocess.Popen, profile) -> None:
        """
        Monitors the process, logs output, and handles process termination cleanly.
        """
        max_lines = 10  # Limit buffer size
        stdout_buffer, stderr_buffer = [], []

        # Ensure process streams are available
        streams = []
        if process.stdout:
            streams.append(process.stdout)
        if process.stderr:
            streams.append(process.stderr)

        self.logger.info(f"Monitoring process for profile '{profile}'...")

        while process.poll() is None:  # While process is running
            readable, _, _ = select.select(streams, [], [], 0.1)

            for stream in readable:
                try:
                    line = stream.readline().strip()
                    if line:
                        if stream == process.stdout:
                            stdout_buffer.append(line)
                            self.logger.debug(f"[{profile} STDOUT] {line}")
                        else:
                            stderr_buffer.append(line)
                            self.logger.error(f"[{profile} STDERR] {line}")

                        # Trim buffer size
                        if len(stdout_buffer) > max_lines:
                            stdout_buffer.pop(0)
                        if len(stderr_buffer) > max_lines:
                            stderr_buffer.pop(0)

                except Exception as e:
                    self.logger.error(f"Error reading from process stream: {e}")

            time.sleep(0.1)  # Prevent CPU overuse

        # Capture remaining output after process termination
        for stream, buffer, log_level in [(process.stdout, stdout_buffer, self.logger.debug),
                                          (process.stderr, stderr_buffer, self.logger.error)]:
            try:
                remaining_output = stream.read().strip().split("\n")
                for line in remaining_output:
                    if line:
                        buffer.append(line)
                        log_level(f"[{profile} OUTPUT] {line}")
                        if len(buffer) > max_lines:
                            buffer.pop(0)
            except Exception as e:
                self.logger.error(f"Error reading remaining output: {e}")

        # Final process status logging
        if process.returncode != 0:
            self.logger.error(
                f"Process for profile '{profile}' failed. Last stderr lines:\n" + "\n".join(stderr_buffer))
        else:
            self.logger.info(f"Process for profile '{profile}' finished successfully.")

        # Clean up
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
