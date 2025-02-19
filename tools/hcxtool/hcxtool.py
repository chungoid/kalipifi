import subprocess
import threading
import logging
import yaml
from pathlib import Path


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
        First, try to get it from the scan profile; if not provided,
        default to the first available WLAN interface with role "monitor" from self.interfaces.
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
                    f"No interface defined in scan profile; defaulting to monitor interface: {iface.get('name')}")
                return iface.get("name")
        raise ValueError("No interface defined in scan profile and no monitor interface found in configuration.")

    def build_command(self) -> list:
        cmd = ["hcxdumptool"]

        # Use the scan profile's interface (determined by get_scan_interface())
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
        else:
            self.logger.warning("No scan profiles defined under 'scans'. Falling back to single scan configuration.")

        # Determine the scan interface using the helper; update scan_settings if missing.
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
            # Store the process in a dictionary keyed by profile.
            if not hasattr(self, "running_processes"):
                self.running_processes = {}
            self.running_processes[profile] = process

            # Launch a separate thread to monitor process output and cleanup.
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

