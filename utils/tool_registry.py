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
        """Instantiate a tool by name. The tool class's __init__ will load its own config."""
        if tool_name not in self._registry:
            raise ValueError(f"Tool '{tool_name}' is not registered.")
        tool_class = self._registry[tool_name]
        return tool_class(**override_kwargs)

tool_registry = ToolRegistry()
def register_tool(tool_name):
    """Register a tool by name."""
    def decorator(cls):
        tool_registry.register(tool_name, cls)
        return cls
    return decorator

def main_menu():
    while True:
        print("=== Tool Menu ===")
        tool_names = tool_registry.get_tool_names()
        for i, name in enumerate(tool_names, start=1):
            print(f"{i}: {name}")
        print("0: Exit")
        choice = input("Select a tool: ")

        if choice == "0":
            break

        try:
            index = int(choice) - 1
            selected_tool = tool_names[index]
            tool_instance = tool_registry.instantiate_tool(selected_tool)
            tool_instance.submenu()
        except (IndexError, ValueError) as e:
            print("Invalid selection. Please try again.")

