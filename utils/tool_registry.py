class ToolRegistry:
    def __init__(self):
        self._registry = {}

    def register(self, tool_name, tool_class):
        """Register a tool by name with its class."""
        self._registry[tool_name] = tool_class

    def get_tool_names(self):
        """Return a list of registered tool names."""
        return list(self._registry.keys())

    def instantiate_tool(self, tool_name, **override_kwargs):
        """Instantiate a tool by name, ensuring it receives the correct config file."""
        if tool_name not in self._registry:
            raise ValueError(f"Tool '{tool_name}' is not registered.")

        tool_class = self._registry[tool_name]

        # Auto-detect tool-specific config path
        tool_config_path = f"tools/{tool_name.lower()}/configs/config.yaml"

        # ✅ Only pass `config_file` if not already provided
        if "config_file" not in override_kwargs:
            override_kwargs["config_file"] = tool_config_path

        return tool_class(**override_kwargs)


    def __iter__(self):
        """Iterate over the registered tool classes."""
        return iter(self._registry.values())

tool_registry = ToolRegistry()
def register_tool(tool_name):
    """Register a tool by name."""
    def decorator(cls):
        tool_registry.register(tool_name, cls)
        return cls
    return decorator

def main_menu(config_file="configs/config.yaml"):
    """Displays the main menu for tool selection and instantiates the selected tool."""
    while True:
        print("\n=== Tool Menu ===")
        tool_names = tool_registry.get_tool_names()

        # Print available tools
        for i, name in enumerate(tool_names, start=1):
            print(f"{i}: {name}")
        print("0: Exit")

        # Get user input
        choice = input("Select a tool: ").strip()

        if choice == "0":
            print("Exiting...")
            break

        try:
            index = int(choice) - 1
            selected_tool = tool_names[index]

            # Explicitly pass the config file when instantiating the tool
            print(f"DEBUG: Instantiating tool {selected_tool} with config file {config_file}")
            tool_instance = tool_registry.instantiate_tool(selected_tool, config_file=config_file)
            tool_instance.submenu()
        except (IndexError, ValueError):
            print("Invalid selection. Please try again.")




