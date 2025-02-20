import base64
import threading
import requests
import yaml
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from tools.tools import Tool
from utils.toolmenus import register_tool
from utils.helper import generate_default_prefix
from utils.helper import create_bpf_filter

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
        base_dir = Path(__file__).resolve().parent
        if config_file is None:
            config_file = base_dir / "configs" / "hcxtool.yaml"
        else:
            config_file = Path(config_file)
            if not config_file.is_absolute():
                config_file = base_dir / config_file

        if not config_file.exists():
            self.logger.error(f"Configuration file {config_file} does not exist. Please create it.")
            raise FileNotFoundError(f"{config_file} not found.")

        try:
            with config_file.open("r") as f:
                self.config_data = yaml.safe_load(f)
        except Exception as e:
            self.logger.exception(f"Failed to load configuration file {config_file}: {e}")
            raise

        # Populates scan & interface Dicts from config/hcxtool.yaml
        interfaces_config = self.config_data.get("interfaces", {})
        scans_config = self.config_data.get("scans", {})
        self.config_data["scans"] = scans_config

        # Initialize scan_settings to empty; it will be populated in run().
        scan_settings = {}
        self.options = self.DEFAULT_OPTIONS.copy()
        self.options.update(scan_settings.get("options", {}))

        super().__init__(
            name="hcxtool",
            description="Enhanced hcxtool focused on headless rpi usage.",
            base_dir=base_dir,
            interfaces=interfaces_config,
            settings=scan_settings
        )

        register_tool(self)
        self.scan_settings = scan_settings

    def get_scan_interface(self) -> str:
        scan_interface = self.scan_settings.get("interface")
        if scan_interface:
            return scan_interface
        wlan_list = self.interfaces.get("wlan", [])
        for iface in wlan_list:
            if iface.get("role", "").lower() == "monitor":
                self.logger.info(f"No interface defined in scan profile; defaulting to monitor interface: {iface.get('name')}")
                return iface.get("name")
        raise ValueError("No interface defined in scan profile and no monitor interface found in configuration.")

    def build_command(self) -> list:
        cmd = ["hcxdumptool"]
        scan_interface = self.get_scan_interface()
        cmd.extend(["-i", scan_interface])

        # setting up file prefixes
        prefix = self.scan_settings.get("output_prefix")
        try:
            if prefix == "default" or  (None, "", "none"):
                prefix = self.results_dir / generate_default_prefix()
                self.scan_settings["output_prefix"] = prefix
            else:
                prefix = prefix if isinstance(prefix, Path) else Path(prefix)
                if not prefix.is_absolute():
                    prefix = self.results_dir / prefix
        except Exception as e:
            self.logger.error(f"Failed to generate output prefix for scan profile: {e}")
            return []

        # setting pcapng filepath
        pcap_path = cmd.extend([f"-w", str(prefix.with_suffix('.pcapng'))])
        self.logger.debug(f"setting pcapng filepath: {pcap_path}")

        # setting gpsd filepath
        if self.scan_settings.get("gpsd", False):
            cmd.append("--gpsd")
            cmd.append("--nmea_pcapng")
            nmea_path = cmd.extend([f"--nmea_out=", str(prefix.with_suffix('.pcapng'))])
            self.logger.debug(f"setting nmea filepath: {nmea_path}")


        if "channel" in self.scan_settings:
            channel_value = self.scan_settings["channel"]
            if isinstance(channel_value, list):
                channel_str = ",".join(str(ch) for ch in channel_value)
            else:
                channel_str = str(channel_value).strip()
                if " " in channel_str:
                    channel_str = ",".join(channel_str.split())
            cmd.extend(["-c", channel_str])

        bpf_setting = self.scan_settings.get("bpf_file", "default")
        if bpf_setting in (None, "", "none"):
            self.logger.info("No BPF filter will be applied as per configuration.")
        else:
            if bpf_setting == "default":
                bpf_file = self.defaults_dir / "filter.bpf"
                self.logger.debug(f"Using BPF filter from self.defaults_dir: {bpf_file}")
            else:
                bpf_file = Path(bpf_setting)
                self.logger.debug(f"Using BPF filter from Path(bpf_setting): {bpf_file}")
            cmd.append(f"--bpf={bpf_file}")
            self.logger.debug(f"appended --bpf: {cmd}")


        for option, value in self.options.items():
            if isinstance(value, bool):
                if value:
                    cmd.append(option)
            elif value is not None:
                if option.startswith("--"):
                    cmd.append(f"{option}={value}")
                else:
                    cmd.extend([option, str(value)])
            # debug what options are added
            self.logger.debug(f"appended {option}: {value}")



        self.logger.debug("Built command: " + " ".join(cmd))
        return cmd

    def run(self, profile=None) -> None:
        process = None # default value used to ensure process creation
        # Process the scan profile configuration.
        scans = self.config_data.get("scans", {})
        if scans:
            if profile is None:
                profile = next(iter(scans))
                self.logger.info(f"No scan profile specified. Using default profile: '{profile}'.")
            if isinstance(profile, str) and profile.isdigit():
                profile = int(profile)
            if profile not in scans:
                available = ", ".join(f"{k} ({scans[k].get('description', 'No description')})" for k in scans)
                self.logger.error(f"Scan profile '{profile}' not found. Available profiles: {available}.")
                return
            self.scan_settings = scans[profile]
            self.options.update(self.scan_settings.get("options", {}))
        else:
            self.logger.warning("No scan profiles defined under 'scans'. Falling back to single scan configuration.")

        try:
            scan_interface = self.get_scan_interface()
            self.scan_settings["interface"] = scan_interface
        except ValueError as e:
            self.logger.error(e)
            return

        if not self.reserve_interface(scan_interface):
            self.logger.error(f"Interface {scan_interface} is already in use; aborting scan.")
            return

        if self.scan_settings.get("auto_bpf", False):
            wlan_list = self.interfaces.get("wlan", [])
            interface_names = [iface["name"] for iface in wlan_list if "name" in iface]

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
            cmd_list = self.build_command()
            if cmd_list is None: # debug build_command()
                self.logger.critical("Error: build_command() returned None.")
                return

            self.logger.debug(f"Raw command list before conversion: {cmd_list}") # debug tools/cmd_to_string()
            cmd_str = self.cmd_to_string(cmd_list)

            if cmd_str:
                if self.scan_settings.get("tmux", False):
                    self.logger.info(f"Launching in tmux: {cmd_str}")
                    self.run_in_tmux(self.name, self.scan_settings.get("interface"), cmd_str)
                    process = None  # Tmux does not return a process

                else:
                    self.logger.info(f"Launching in shell: {cmd_str}")
                    process = self.run_in_shell(cmd_str)
                    if process:
                        self.running_processes[profile] = process

        except Exception as e:
            self.logger.critical(f"Error launching scan: {e}")
            self.release_interfaces()
            return

        # Process Monitoring
        if process:
            monitor_thread = threading.Thread(target=self._monitor_process, args=(process, profile), daemon=True)
            monitor_thread.start()
        else:
            self.logger.critical(f"Failed to create process for scan profile {profile}.")
            self.release_interfaces()

    def upload_selected_pcapng(self) -> None:
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

    def bulk_upload_pcapng(self) -> None:
        results_dir = self.get_path("results")
        files = self.list_pcapng_files(results_dir)
        if not files:
            self.logger.error("No PCAPNG files found in the results directory.")
            print("No PCAPNG files found.")
            return
        for file in files:
            self.logger.info(f"Uploading {file.name}...")
            success = self.upload_to_wpasec(file)
            if success:
                print(f"Uploaded {file.name} successfully.")
            else:
                print(f"Failed to upload {file.name}.")

    def upload_to_wpasec(self, pcap_path: Path) -> bool:
        try:
            api_key = Hcxtool.get_decrypted_api_key(self.config_data)
        except Exception as e:
            self.logger.error(f"Error decrypting API key: {e}")
            return False
        url = "https://wpa-sec.stanev.org/?api&upload"
        headers = {"Cookie": f"key={api_key}"}
        try:
            self.logger.info(f"Uploading {pcap_path} to WPA-SEC...")
            with pcap_path.open("rb") as f:
                files = {"file": f}
                response = requests.post(url, headers=headers, files=files)
                response.raise_for_status()
            self.logger.info(f"Upload successful: {response.text}")
            return True
        except requests.RequestException as e:
            self.logger.exception(f"Error uploading PCAP file: {e}")
            return False

    @staticmethod
    def list_pcapng_files(results_dir: Path) -> list:
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
        derived_key = Hcxtool.derive_key_from_passphrase(passphrase, salt)
        cipher_suite = Fernet(derived_key)
        try:
            decrypted_key = cipher_suite.decrypt(encrypted_key.encode()).decode()
            return decrypted_key
        except Exception as e:
            raise ValueError("Failed to decrypt API key. Check your passphrase.") from e

