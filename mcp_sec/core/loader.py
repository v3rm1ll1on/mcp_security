import os
import importlib.util
import sys

class PluginLoader:
    def __init__(self, plugin_dir: str, exclude_plugins: list = None):
        self.plugin_dir = plugin_dir
        self.exclude_plugins = exclude_plugins or []
        
    def load_plugins(self):
        plugins = []
        if not os.path.exists(self.plugin_dir):
            print(f"[!] Warnung: Plugin-Verzeichnis {self.plugin_dir} nicht gefunden.")
            return plugins
            
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                plugin_name = filename[:-3]
                filepath = os.path.join(self.plugin_dir, filename)
                
                # Modul dynamisch laden (Filedrop System)
                spec = importlib.util.spec_from_file_location(plugin_name, filepath)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[plugin_name] = module
                    spec.loader.exec_module(module)
                    
                    # Überprüfen ob das Modul die nötigen Schnittstellen hat
                    if hasattr(module, "run_test") and hasattr(module, "info"):
                        info = module.info()
                        plugin_id = info.get("name")
                        
                        # Überprüfen ob der Name nur Buchstaben und Underscores enthält
                        import re
                        if not plugin_id or not re.match(r"^[a-zA-Z_]+$", plugin_id):
                            print(f"[!] Warnung: {filename} ignoriert. Plugin-Name '{plugin_id}' darf nur Buchstaben und Underscores enthalten.")
                            continue
                            
                        required_keys = ["name", "description", "severity", "author", "contact", "version"]
                        if all(k in info for k in required_keys):
                            if plugin_id in self.exclude_plugins or plugin_name in self.exclude_plugins:
                                module._excluded = True
                            else:
                                module._excluded = False
                            plugins.append(module)
                        else:
                            missing = [k for k in required_keys if k not in info]
                            print(f"[!] Warnung: {filename} ignoriert. Fehlende Metadaten: {missing}")
                    else:
                        print(f"[!] Warnung: {filename} fehlt 'info()' oder 'run_test()'")
        return plugins
