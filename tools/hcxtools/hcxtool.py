import subprocess
import threading
import logging
import yaml
from pathlib import Path
from tools.tools import Tool
from utils.helper import generate_default_prefix
from utils.toolmenus import register_tool

class Hcxtool(Tool):
    # Default command-line options for hcxdumptool
    DEFAULT_OPTIONS = {
        "--disable_deauthentication": False,
        "--disable_proberequest": False,
        "--disable_association": False,
        "--disable_reassociation": False,
        "--disable_beacon": False,
        "--proberesponsetx": None,
        "--essidlist": None,
        "--errormax": 100,
        "--watchdogmax": 600,
        "--attemptclientmax": 10,
        "--attemptapmax": 4,
        "--tot": None,
        "--exitoneapol": None,
        "--onsigterm": None,
        "--ongpiobutton": None,
        "--ontot": None,
        "--onwatchdog": None,
        "--onerror": None,
        "--gpio_button": 0,
        "--gpio_statusled": 0,
        "--nmea_dev": None,
        "--rcascan": None,
        "--rds": None,
    }

    def __init__(self, config_file: str = "config/hcxtool.yaml"):
        # Register tool; cli-menu process tracking
        register_tool(self)
        # Initialize logging
        self.logger = logging.getLogger("hcxtool")
        self.logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        # Load the YAML configuration
        try:
            with open(config_file, "r") as f:
                self.config_data = yaml.safe_load(f)
        except Exception as e:
            self.logger.exception(f"Failed to load configuration file {config_file}: {e}")
            raise

        # Extract interface configuration and scan profiles.
        interfaces_config = self.config_data.get("interfaces", {})
        scans_config = self.config_data.get("scans", {})
        # Store scans_config back so later we always refer to "scans"
        self.config_data["scans"] = scans_config

        # For now, default scan settings is an empty dict; it will be replaced when a profile is selected.
        scan_settings = {}

        # Merge default options with any provided in the (currently empty) scan settings.
        self.options = self.DEFAULT_OPTIONS.copy()
        self.options.update(scan_settings.get("options", {}))

        # Determine base directory.
        base_dir = Path("tools/hcxtools")

        # Initialize the parent Tool class.
        super().__init__(
            name="hcxtool",
            description="Enhanced hcxtool focused on headless rpi usage.",
            base_dir=base_dir,
            interfaces=interfaces_config,
            settings=scan_settings
        )
        # Save our scan settings for later use.
        self.scan_settings = scan_settings

    def build_command(self) -> list:
        cmd = ["hcxdumptool"]

        # Determine the interface (default: first WLAN interface)
        wlan_interfaces = self.interfaces.get("wlan", [])
        if not wlan_interfaces:
            self.logger.error("No WLAN interfaces defined in configuration.")
            raise ValueError("No WLAN interfaces defined.")
        iface = wlan_interfaces[0].get("name")
        cmd.extend(["-i", iface])

        # Process output prefix and corresponding pcap file.
        output_prefix_val = self.scan_settings.get("output_prefix")
        if output_prefix_val in (None, "", "none"):
            self.logger.info("No output_prefix defined in configuration.")
        elif output_prefix_val == "default":
            # Generate a default prefix and convert it to a Path.
            default_prefix = Path(generate_default_prefix())
            self.scan_settings["output_prefix"] = default_prefix
            cmd.extend(["-w", str(default_prefix.with_suffix('.pcapng'))])
        else:
            # Ensure output_prefix is a Path
            output_prefix = output_prefix_val if isinstance(output_prefix_val, Path) else Path(output_prefix_val)
            cmd.extend(["-w", str(output_prefix.with_suffix('.pcapng'))])

        # Add GPS mode if enabled.
        if self.scan_settings.get("gpsd", False):
            cmd.append("--gpsd")
            cmd.append("--nmea_pcapng")
            out_prefix = self.scan_settings.get("output_prefix")
            # Ensure it is a Path
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
        The scan is launched in a separate thread so that the interactive menu remains responsive.
        """
        scans = self.config_data.get("scans", {})
        if scans:
            if profile is None:
                # Select the first available profile if none specified.
                profile = next(iter(scans))
                self.logger.info(f"No scan profile specified. Using default profile: '{profile}'.")
            if isinstance(profile, str) and profile.isdigit():
                profile = int(profile)
            if profile not in scans:
                available = ", ".join(
                    str(k) + " (" + scans[k].get("description", "No description") + ")" for k in scans)
                self.logger.error(f"Scan profile '{profile}' not found. Available profiles: {available}.")
                return
            self.scan_settings = scans[profile]
        else:
            self.logger.warning("No scan profiles defined under 'scans'. Falling back to single scan configuration.")

        # Validate interfaces.
        if not self.validate_interfaces():
            self.logger.error("Interface validation failed.")
            return

        # Determine which interface to use (profile may override this).
        scan_interface = self.scan_settings.get("interface")
        if not scan_interface:
            wlan_interfaces = self.interfaces.get("wlan", [])
            if not wlan_interfaces:
                self.logger.error("No WLAN interfaces available in configuration.")
                return
            scan_interface = wlan_interfaces[0].get("name")

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
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

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

