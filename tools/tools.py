import fcntl
import os
import subprocess
from pathlib import Path

import libtmux

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
        self.tmux_session = None

        # Define standard subdirectories
        self.config_dir = self.base_dir / "configs"
        self.defaults_dir = self.base_dir / "defaults"
        self.results_dir = self.base_dir / "results"
        self.setup_directories()
        self.check_root()

        # Defaults true, non-root tools set to false.
        require_root = True

    @staticmethod
    def _interface_exists(iface):
        try:
            output = subprocess.check_output(["ip", "link", "show", iface], text=True)
            return iface in output
        except subprocess.CalledProcessError:
            return False

    def check_root(self):
        if os.geteuid() != 0:
            raise PermissionError("This tool must be run as root.")

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

    def create_tmux_session(self, session_name: str) -> libtmux.Session:
        """
        Create or attach to a tmux session with the given name.
        """
        server = libtmux.Server()
        session = server.find_where({"session_name": session_name})
        if session is None:
            session = server.new_session(session_name=session_name, kill_session=True, attach=False)
        self.tmux_session = session
        return session

    def attach_tmux_session(self, session_name: str) -> None:
        """
        Attach the current terminal to the tmux session.
        """
        os.system(f"tmux attach-session -t {session_name}")

    def load_interfaces(self):
        # Build the config file path based on the tool's name.
        # Here, self.base_dir is the tool's base directory (e.g. tools/hcxtool)
        config_file = self.base_dir / "configs" / f"{self.name}.yaml"
        if config_file.exists():
            config_data = load_interfaces_config(config_file)
            # Assume that the YAML file has an 'interfaces' key with subcategories.
            self.interfaces = config_data.get("interfaces", {})
        else:
            self.interfaces = {}

    def validate_interfaces(self):
        # You can iterate over each interface in each category,
        # and for wlan interfaces, check if they're in the correct mode.
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

    def stop(self, profile) -> None:
        """
        Stop a running scan process for the given profile.
        If the stored object is a tmux session (string), kill that tmux session.
        Otherwise, if it's a subprocess, terminate it.
        """
        if hasattr(self, "running_processes") and profile in self.running_processes:
            proc_or_session = self.running_processes[profile]
            if isinstance(proc_or_session, str):
                os.system(f"tmux kill-session -t {proc_or_session}")
            else:
                if proc_or_session.poll() is None:
                    proc_or_session.terminate()

    def release_interfaces(self):
        """Release any reserved interfaces."""
        for lock in self.interface_locks.values():
            lock.release()
        self.interface_locks = {}

    def run(self):
        # Placeholder for common run logic.
        # Subclasses should override this with their specific behavior.
        self.check_root()
        raise NotImplementedError

    def cleanup(self):
        # Placeholder for cleanup logic.
        pass


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