import logging
import select
import sys
import time
import re

# Set up a basic logger for the menu module.
global_tools = {}
logger = logging.getLogger(__name__)

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    ch.addFilter(EscapeSequenceFilter())
    logger.addHandler(ch)

def flush_stdin(timeout=0.1):
    """Flush any pending input from stdin."""
    time.sleep(timeout)
    while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
        sys.stdin.read(1)

def register_tool(tool_instance):
    global_tools[tool_instance.name] = tool_instance

def list_all_active_processes():
    print("\n=== Active Processes Across All Tools ===")
    for tool_name, tool_instance in global_tools.items():
        if hasattr(tool_instance, "running_processes") and tool_instance.running_processes:
            print(f"Tool: {tool_name}")
            for profile, process in tool_instance.running_processes.items():
                try:
                    status = "Running" if process.poll() is None else "Completed"
                except Exception as ex:
                    status = f"Error checking status: {ex}"
                print(f"  Profile {profile}: {status}")
        else:
            print(f"Tool: {tool_name} has no active processes.")

def display_main_menu():
    time.sleep(0.1)
    if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
        sys.stdin.read(1)
    while True:
        print("\n=== Main Menu ===")
        print("1: Select a tool")
        print("2: Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            select_tool_menu()
        elif choice == "2" or choice.lower() == "exit":
            print("Exiting.")
            break
        else:
            print("Invalid option. Please try again.")

def select_tool_menu():
    print("\n=== Tools Menu ===")
    print("1: Hcxtool")
    print("0: Return to Main Menu")
    choice = input("Select a tool: ").strip()
    if choice == "1":
        try:
            hcxtool_submenu()
        except Exception as ex:
            logger.exception("Error in Hcxtool submenu: %s", ex)
    elif choice == "0":
        return
    else:
        print("Invalid option.")
        logger.debug("select_tool_menu invalid option: %s", choice)

def hcxtool_submenu():
    try:
        from tools.hcxtool.hcxtool import Hcxtool
    except Exception as ex:
        logger.exception("Error importing Hcxtool: %s", ex)
        return

    try:
        tool = Hcxtool(config_file="configs/hcxtool.yaml")
    except Exception as ex:
        logger.exception("Error instantiating Hcxtool: %s", ex)
        print("Failed to launch Hcxtool. Check logs for details.")
        return

    # For convenience, cache the scan profiles
    scans = tool.config_data.get("scans", {})

    while True:
        print("\n=== Hcxtool Menu ===")
        print("1: Launch scan")
        print("2: View scan (attach to tmux session)")
        print("3: Stop a running scan")
        print("4: Upload results to WPA-sec")
        print("0: Return to Main Menu")
        choice = input("Select an option: ").strip()
        if choice == "0":
            break
        elif choice == "1":
            if scans:
                print("\n=== Hcxtool Scan Profiles ===")
                for key, profile in scans.items():
                    desc = profile.get("description", "No description")
                    print(f"{key}: {desc}")
                selection = input("Select a scan profile by number: ").strip()
                if not selection.isdigit():
                    print("Invalid selection, please enter a numeric profile key.")
                    continue
                selected_profile = int(selection)
                if selected_profile not in scans:
                    print("Invalid profile selection.")
                    continue
                print(f"Launching scan profile: {selected_profile} ({scans[selected_profile].get('description')})")
                try:
                    tool.run(profile=selected_profile)
                    print(f"Scan profile {selected_profile} launched asynchronously.")
                except Exception as ex:
                    logger.exception("Error launching scan for profile %s: %s", selected_profile, ex)
                    print("Error launching scan. See logs for details.")
            else:
                print("No scan profiles defined in the configuration.")
        elif choice == "2":
            session = input("Enter the tmux session name to attach (or press enter for default): ").strip()
            if not session:
                session_num = input("Enter scan profile number to view: ").strip()
                session = f"{tool.name}_scan_{session_num}"
            try:
                tool.attach_tmux_session(session)
            except Exception as ex:
                logger.exception("Error attaching to tmux session %s: %s", session, ex)
        elif choice == "3":
            profile = input("Enter scan profile number to stop: ").strip()
            if profile.isdigit():
                try:
                    tool.stop(int(profile))
                except Exception as ex:
                    logger.exception("Error stopping scan for profile %s: %s", profile, ex)
            else:
                print("Invalid profile.")
        elif choice == "4":
            try:
                upload_wpasec_menu(tool)
            except Exception as ex:
                logger.exception("Error in upload menu: %s", ex)
        else:
            print("Invalid option. Please try again.")
            logger.debug("Hcxtool submenu invalid option: %s", choice)

def upload_wpasec_menu(tool) -> None:
    """
    Presents an upload menu for WPA-sec. The user can choose to upload a single PCAPNG file or all files.
    """
    print("\n=== WPA-sec Upload Menu ===")
    print("1: Upload a single PCAPNG file")
    print("2: Upload all PCAPNG files")
    print("0: Return to Hcxtool Menu")
    choice = input("Select an option: ").strip().lower()
    if choice == "0":
        return
    elif choice == "1":
        try:
            tool.upload_selected_pcapng()
        except Exception as ex:
            logger.exception("Error during single file upload: %s", ex)
    elif choice == "2":
        try:
            tool.bulk_upload_pcapng()
        except Exception as ex:
            logger.exception("Error during bulk upload: %s", ex)
    else:
        print("Invalid selection.")
        logger.debug("upload_wpasec_menu invalid option: %s", choice)


class EscapeSequenceFilter(logging.Filter):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')

    def filter(self, record):
        # Remove escape sequences from the message
        record.msg = self.ansi_escape.sub('', record.msg)
        return True
