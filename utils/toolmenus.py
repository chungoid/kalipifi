import logging
import select
import sys
import time
from pathlib import Path

from tools.hcxtool.hcxtool import Hcxtool

global_tools = {}

def register_tool(tool_instance):
    global_tools[tool_instance.name] = tool_instance

def list_all_active_processes():
    print("\n=== Active Processes Across All Tools ===")
    for tool_name, tool_instance in global_tools.items():
        if hasattr(tool_instance, "running_processes") and tool_instance.running_processes:
            print(f"Tool: {tool_name}")
            for profile, process in tool_instance.running_processes.items():
                status = "Running" if process.poll() is None else "Completed"
                print(f"  Profile {profile}: {status}")
        else:
            print(f"Tool: {tool_name} has no active processes.")

def display_main_menu():
    # Flush any initial control sequences.
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
    # For now, we only have hcxtool; later you can add more tools.
    print("\n=== Tools Menu ===")
    print("1: Hcxtool")
    print("0: Return to Main Menu")
    choice = input("Select a tool: ").strip()

    if choice == "1":
        hcxtool_submenu()
    elif choice == "0":
        return
    else:
        print("Invalid option.")
        return

############ HCXTOOL MENU FUNCTIONS ############
def hcxtool_submenu():
    from tools.hcxtool.hcxtool import Hcxtool
    tool = Hcxtool(config_file="configs/hcxtool.yaml")

    while True:
        print("\n=== Hcxtool Menu ===")
        print("1: Launch scan in tmux")
        print("2: View scan (attach to tmux session)")
        print("3: Stop a running scan")
        print("4: Upload results to WPA-sec")
        print("0: Return to Main Menu")
        choice = input("Select an option: ").strip()

        if choice == "0":
            break
        elif choice == "1":
            profile = input("Enter scan profile number to launch: ").strip()
            if not profile.isdigit():
                print("Invalid profile. Please enter a numeric profile key.")
                continue
            profile = int(profile)
            tool.run(profile)
        elif choice == "2":
            session = input("Enter the tmux session name to attach (or press enter for default): ").strip()
            if not session:
                session = f"{tool.name}_scan_{input('Enter scan profile number to view: ').strip()}"
            tool.attach_tmux_session(session)
        elif choice == "3":
            profile = input("Enter scan profile number to stop: ").strip()
            if profile.isdigit():
                profile = int(profile)
                tool.stop(profile)
            else:
                print("Invalid profile.")
        elif choice == "4":
            upload_wpasec_menu(tool)
        else:
            print("Invalid option. Please try again.")

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
        tool.upload_selected_pcapng()
    elif choice == "2":
        tool.bulk_upload_pcapng()
    else:
        print("Invalid selection.")

def run_hcxtool_scan_menu(tool):
    scans = tool.config_data.get("scans", {})
    if not scans:
        print("No scan profiles defined in the configuration.")
        return

    print("\n=== Hcxtool Scan Profiles ===")
    for key, profile in scans.items():
        desc = profile.get("description", "No description")
        print(f"{key}: {desc}")
    choice = input("Select a scan profile by number: ").strip()
    if not choice.isdigit():
        print("Invalid selection, please enter a numeric profile key.")
        return
    logging.debug(
        f"Selected scan profile {choice} -- Key: {scans[int(choice)]} Description: {scans[int(choice)]['description']}")
    selected_profile = int(choice)
    if selected_profile not in scans:
        print("Invalid profile selection.")
        return

    print(f"Launching scan profile: {selected_profile} ({scans[selected_profile].get('description')})")
    tool.run(profile=selected_profile)
    print(f"Scan profile {selected_profile} launched asynchronously.")

def list_running_scans(tool):
    if hasattr(tool, "running_processes") and tool.running_processes:
        print("\nActive Scans for Hcxtool:")
        for profile, process in tool.running_processes.items():
            status = "Running" if process.poll() is None else "Completed"
            print(f"Profile {profile}: {status}")
    else:
        print("\nNo active scans for Hcxtool.")

def stop_running_scan(tool):
    list_running_scans(tool)
    choice = input("Enter the profile number to stop: ").strip()
    if not choice.isdigit():
        print("Invalid input. Please enter a numeric profile key.")
        return
    profile = int(choice)
    tool.stop(profile)


if __name__ == "__main__":
    display_main_menu()
