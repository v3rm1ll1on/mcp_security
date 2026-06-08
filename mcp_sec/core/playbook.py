import json
import os

class PlaybookValidationError(Exception):
    pass

class Playbook:
    def __init__(self):
        self.mcpserver = None
        self.tools = {}

    @staticmethod
    def load_and_validate(playbook_path: str) -> "Playbook":
        if not os.path.exists(playbook_path):
            raise PlaybookValidationError(f"Playbook file not found: {playbook_path}")
            
        try:
            with open(playbook_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise PlaybookValidationError(f"Invalid JSON format: {str(e)}")
            
        if not isinstance(data, dict):
            raise PlaybookValidationError("Playbook root must be a JSON object.")
            
        playbook = Playbook()
        
        if "mcpserver" in data:
            if not isinstance(data["mcpserver"], str):
                raise PlaybookValidationError("'mcpserver' must be a string.")
            playbook.mcpserver = data["mcpserver"]
            
        if "tools" in data:
            if not isinstance(data["tools"], dict):
                raise PlaybookValidationError("'tools' must be an object mapping tool names to lists of plugins.")
            for tool_name, plugins_list in data["tools"].items():
                if not isinstance(plugins_list, list) or not all(isinstance(x, str) for x in plugins_list):
                    raise PlaybookValidationError(f"'tools.{tool_name}' must be a list of strings.")
            playbook.tools = data["tools"]
            
        return playbook
