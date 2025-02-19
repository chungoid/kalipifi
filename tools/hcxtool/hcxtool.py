import base64
import subprocess
import threading
import logging
import requests
import yaml
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from tools.tools import Tool
from utils.helper import generate_default_prefix, run_command_with_root
from utils.toolmenus import register_tool


class Hcxtool(Tool):
    DEFAULT_OPTIONS = {
        "--disable_deauthentication": False,
        "--disable_proberequest": False,
        "--disable_association": False,
        "--disable_reassociation": False,
        "--disable_beacon": False,
        "--proberesponsetx": None,
        "--essidlist": None,
        "--errormax": None,
        "--watchdogmax": None,
        "--attemptclientmax": None,
        "--attemptapmax": None,
        "--tot": None,
        "--exitoneapol": None,
        "--onsigterm": None,
        "--ongpiobutton": None,
        "--ontot": None,
        "--onwatchdog": None,
        "--onerror": None,
        "--gpio_button": None,
        "--gpio_statusled": None,
        "--nmea_dev": None,
        "--rcascan": None,
        "--rds": None,
    }

    def __init__(self, config_file: str = None):
        # Initialize logging
        self.logger = logging.getLogger("hcxtool")
        self.logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        # __file__ is "tools/hcxtool/hcxtool.py", so base_dir will be "tools/hcxtool"
        base_dir = Path(__file__).resolve().parent

        # If no config_file is provided, default to "tools/hcxtool/config/hcxtool.yaml"
        if config_file is None:
            config_file = base_dir / "configs" / "hcxtool.yaml"
        else:
            # If a relative path is given, resolve it relative to base_dir.
            config_file = Path(config_file)
            if not config_file.is_absolute():
                config_file = base_dir / config_file

        # Check if the configuration file exists.
        if not config_file.exists():
            self.logger.error(f"Configuration file {config_file} does not exist. Please create it.")
            raise FileNotFoundError(f"{config_file} not found.")

        # Load the YAML configuration.
        try:
            with config_file.open("r") as f:
                self.config_data = yaml.safe_load(f)
        except Exception as e:
            self.logger.exception(f"Failed to load configuration file {config_file}: {e}")
            raise

        # Extract interface configuration and scan profiles.
        interfaces_config = self.config_data.get("interfaces", {})
        scans_config = self.config_data.get("scans", {})
        self.config_data["scans"] = scans_config

        # Default scan settings (empty dict for now)
        scan_settings = {}

        # Merge default options with any provided in scan_settings (currently empty)
        self.options = self.DEFAULT_OPTIONS.copy()
        self.options.update(scan_settings.get("options", {}))

        # Initialize the parent Tool class.
        super().__init__(
            name="hcxtool",
            description="Enhanced hcxtool focused on headless rpi usage.",
            base_dir=base_dir,
            interfaces=interfaces_config,
            settings=scan_settings
        )

        # Register tool for global process tracking.
        register_tool(self)

        # Save scan settings.
        self.scan_settings = scan_settings

    def get_scan_interface(self) -> str:
        """
        Determine the scan interface.
        First, try to get it from the scan profile (self.scan_settings).
        If not provided, default to the first available WLAN interface with role "monitor"
        from the global interfaces configuration.
        """
        # Try to get interface from scan settings.
        scan_interface = self.scan_settings.get("interface")
        if scan_interface:
            return scan_interface

        # Otherwise, default to the first available monitor interface.
        wlan_list = self.interfaces.get("wlan", [])
        for iface in wlan_list:
            if iface.get("role", "").lower() == "monitor":
                self.logger.info(
                    f"No interface defined in scan profile; defaulting to monitor interface: {iface.get('name')}"
                )
                return iface.get("name")
        raise ValueError("No interface defined in scan profile and no monitor interface found in configuration.")

    def build_command(self) -> list:
        cmd = ["hcxdumptool"]

        # Use the scan interface determined by get_scan_interface()
        scan_interface = self.get_scan_interface()
        cmd.extend(["-i", scan_interface])

        # Process output prefix and corresponding pcap file.
        output_prefix_val = self.scan_settings.get("output_prefix")
        if output_prefix_val in (None, "", "none"):
            self.logger.info("No output_prefix defined in configuration.")
        elif output_prefix_val == "default":
            # Generate a default prefix and place it in the results folder.
            default_prefix = self.results_dir / generate_default_prefix()
            self.scan_settings["output_prefix"] = default_prefix
            cmd.extend(["-w", str(default_prefix.with_suffix('.pcapng'))])
        else:
            # Ensure output_prefix is a Path and interpret it as relative to results_dir if it's not absolute.
            output_prefix = output_prefix_val if isinstance(output_prefix_val, Path) else Path(output_prefix_val)
            if not output_prefix.is_absolute():
                output_prefix = self.results_dir / output_prefix
            cmd.extend(["-w", str(output_prefix.with_suffix('.pcapng'))])

        # Add GPS mode if enabled.
        if self.scan_settings.get("gpsd", False):
            cmd.append("--gpsd")
            cmd.append("--nmea_pcapng")
            out_prefix = self.scan_settings.get("output_prefix")
            out_prefix = out_prefix if isinstance(out_prefix, Path) else Path(out_prefix)
            nmea_file = str(out_prefix.with_suffix('.nmea'))
            cmd.append(f"--nmea_out={nmea_file}")

        # Handle channel option (allowing single or multiple channels).
        if "channel" in self.scan_settings:
            channel_value = self.scan_settings["channel"]
            if isinstance(channel_value, list):
                channel_str = ",".join(str(ch) for ch in channel_value)
            else:
                channel_str = str(channel_value).strip()
                if " " in channel_str:
                    channel_str = ",".join(channel_str.split())
            cmd.extend(["-c", channel_str])

        # Handle BPF file: use default from defaults_dir if bpf_file is set to "default"
        bpf_setting = self.scan_settings.get("bpf_file", "default")
        if bpf_setting in (None, "", "none"):
            self.logger.info("No BPF filter will be applied as per configuration.")
        else:
            if bpf_setting == "default":
                bpf_file = self.defaults_dir / "filter.bpf"
            else:
                bpf_file = Path(bpf_setting)
            cmd.append(f"--bpf={bpf_file}")

        # Append additional options.
        for option, value in self.options.items():
            if isinstance(value, bool):
                if value:
                    cmd.append(option)
            elif value is not None:
                if option.startswith("--"):
                    cmd.append(f"{option}={value}")
                else:
                    cmd.extend([option, str(value)])

        self.logger.debug("Built command: " + " ".join(cmd))
        return cmd

    def run(self, profile=None) -> None:
        """
        Asynchronously run the hcxdumptool scan based on a selected scan profile from the YAML configuration.
        If the scan profile does not specify an interface, default to the first monitor interface in the global config.
        """
        scans = self.config_data.get("scans", {})
        if scans:
            if profile is None:
                profile = next(iter(scans))
                self.logger.info(f"No scan profile specified. Using default profile: '{profile}'.")
            if isinstance(profile, str) and profile.isdigit():
                profile = int(profile)
            if profile not in scans:
                available = ", ".join(
                    f"{k} ({scans[k].get('description', 'No description')})" for k in scans
                )
                self.logger.error(f"Scan profile '{profile}' not found. Available profiles: {available}.")
                return
            self.scan_settings = scans[profile]
            # Update options from the scan profile.
            self.options.update(self.scan_settings.get("options", {}))
        else:
            self.logger.warning("No scan profiles defined under 'scans'. Falling back to single scan configuration.")

        # Determine the scan interface using the helper; update scan_settings accordingly.
        try:
            scan_interface = self.get_scan_interface()
            self.scan_settings["interface"] = scan_interface
        except ValueError as e:
            self.logger.error(e)
            return

        if not self.reserve_interface(scan_interface):
            self.logger.error(f"Interface {scan_interface} is already in use; aborting scan.")
            return

        # Auto BPF filter generation, if enabled.
        if self.scan_settings.get("auto_bpf", False):
            wlan_list = self.interfaces.get("wlan", [])
            interface_names = [iface["name"] for iface in wlan_list if "name" in iface]
            from utils.helper import create_bpf_filter
            if not create_bpf_filter(
                    scan_interface,
                    filter_path=self.get_path("defaults", "filter.bpf"),
                    prefilter_path=self.get_path("defaults", "prefilter.txt"),
                    interfaces=interface_names
            ):
                self.logger.error("Failed to generate BPF filter; aborting scan.")
                self.release_interfaces()
                return

        try:
            cmd = self.build_command()
            self.logger.info("Executing command: " + " ".join(cmd))
            process = run_command_with_root(
                cmd, prompt=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if not hasattr(self, "running_processes"):
                self.running_processes = {}
            self.running_processes[profile] = process

            monitor_thread = threading.Thread(target=self._monitor_process, args=(process, profile), daemon=True)
            monitor_thread.start()

            self.logger.info(f"Started scan for profile {profile}.")
        except Exception as e:
            self.logger.exception(f"Exception occurred during hcxtool execution: {e}")
            self.release_interfaces()

    def _monitor_process(self, process: subprocess.Popen, profile) -> None:
        """
        Monitor a running process in a separate thread.
        Logs output, handles errors, and cleans up interface locks when the process finishes.
        """
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            self.logger.error(f"hcxdumptool for profile {profile} returned error: {stderr}")
        else:
            self.logger.info(f"hcxdumptool for profile {profile} finished successfully: {stdout}")

        # Release reserved interfaces and remove the process from running_processes.
        self.release_interfaces()
        if hasattr(self, "running_processes") and profile in self.running_processes:
            del self.running_processes[profile]
        self.logger.info(f"Released interface locks for profile {profile}.")

    def stop(self, profile) -> None:
        """
        Stop a running scan process for the given profile.
        """
        if hasattr(self, "running_processes") and profile in self.running_processes:
            process = self.running_processes[profile]
            if process.poll() is None:
                process.terminate()
                self.logger.info(f"Terminated scan for profile {profile}.")
            else:
                self.logger.info(f"Scan for profile {profile} already completed.")
        else:
            self.logger.warning(f"No running scan found for profile {profile}.")

    def upload_selected_pcapng(self) -> None:
        """
        Lists available .pcapng files for selection and uploads the chosen file.
        The user can either choose a file by number or type "all" to bulk-upload.
        """
        results_dir = self.get_path("results")
        files = self.list_pcapng_files(results_dir)
        if not files:
            self.logger.error("No PCAPNG files found in the results directory.")
            print("No PCAPNG files found.")
            return

        print("Available PCAPNG files:")
        for idx, file in enumerate(files, start=1):
            print(f"{idx}: {file.name}")
        print("Type 'all' to upload all files.")

        choice = input("Select a file to upload (number or 'all'): ").strip().lower()
        if choice == "all":
            for file in files:
                self.logger.info(f"Uploading {file.name}...")
                success = self.upload_to_wpasec(file)
                if success:
                    print(f"Uploaded {file.name} successfully.")
                else:
                    print(f"Failed to upload {file.name}.")
        elif choice.isdigit():
            index = int(choice) - 1
            if index < 0 or index >= len(files):
                print("Invalid selection.")
                return
            selected_file = files[index]
            success = self.upload_to_wpasec(selected_file)
            if success:
                print(f"Uploaded {selected_file.name} successfully.")
            else:
                print(f"Failed to upload {selected_file.name}.")
        else:
            print("Invalid selection. Please enter a number or 'all'.")

    def upload_to_wpasec(self, pcap_path: Path) -> bool:
        """
        Upload the pcapng file to WPA-sec using the API key from the YAML configuration.
        The API key is stored encrypted and is decrypted at runtime.

        Parameters:
            pcap_path (Path): Path to the pcapng file to upload.

        Returns:
            bool: True if the upload was successful, False otherwise.
        """
        try:
            # Retrieve and decrypt the API key using the static method.
            api_key = Hcxtool.get_decrypted_api_key(self.config_data)
        except Exception as e:
            self.logger.error(f"Error decrypting API key: {e}")
            return False

        # Replace with the actual WPA-sec endpoint.
        url = "https://api.wpa-sec.org/upload"
        try:
            with pcap_path.open("rb") as f:
                files = {"file": f}
                data = {"api_key": api_key}
                response = requests.post(url, files=files, data=data)
            if response.status_code == 200:
                self.logger.info("PCAPNG file uploaded successfully.")
                return True
            else:
                self.logger.error(f"Upload failed with status {response.status_code}: {response.text}")
        except Exception as e:
            self.logger.exception(f"Exception occurred during upload: {e}")
        return False

    @staticmethod
    def list_pcapng_files(results_dir: Path) -> list:
        """
        Return a sorted list of all .pcapng files in the results directory.
        """
        return sorted(results_dir.glob("*.pcapng"))

    @staticmethod
    def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        return key

    @staticmethod
    def get_decrypted_api_key(config_data: dict) -> str:
        user_cfg = config_data.get("user", {})
        encrypted_key = user_cfg.get("wpasec-key")
        salt_b64 = user_cfg.get("salt")
        if not encrypted_key or not salt_b64:
            raise ValueError("Encrypted API key or salt not found in configuration.")
        salt = base64.urlsafe_b64decode(salt_b64.encode())

        passphrase = input("Enter passphrase to decrypt WPA-sec API key: ")
        # Correctly reference the static method.
        derived_key = Hcxtool.derive_key_from_passphrase(passphrase, salt)
        cipher_suite = Fernet(derived_key)
        try:
            decrypted_key = cipher_suite.decrypt(encrypted_key.encode()).decode()
            return decrypted_key
        except Exception as e:
            raise ValueError("Failed to decrypt API key. Check your passphrase.") from e




