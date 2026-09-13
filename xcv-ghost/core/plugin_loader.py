import importlib.util
import sys
from pathlib import Path
from rich.console import Console

console = Console()

class PluginLoader:
    def __init__(self, plugin_dir="plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.plugins = {}

    def discover_plugins(self):
        if not self.plugin_dir.exists():
            return self.plugins

        for file_path in self.plugin_dir.glob("*.py"):
            if file_path.name.startswith("__"):
                continue
            self.load_plugin(file_path)

        return self.plugins

    def load_plugin(self, file_path):
        module_name = file_path.stem
        try:
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                if hasattr(module, "register"):
                    plugin_info = module.register()
                    self.plugins[module_name] = plugin_info
                else:
                    self.plugins[module_name] = {"module": module}

        except Exception as e:
            console.print(f"[red]Failed to load plugin {module_name}: {e}[/red]")

