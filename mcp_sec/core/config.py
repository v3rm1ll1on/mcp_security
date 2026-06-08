import json
import os
import sys

class ConfigValidationError(Exception):
    pass

class Config:
    def __init__(self):
        # Default values
        self.target = None
        self.plugin_dir = None
        self.format = "text"
        self.verbose = False
        self.env = {}
        
        self.allow_destructive = False
        self.unsafe_keywords = [
            "write", "delete", "remove", "create", "update", "patch", "put", 
            "destroy", "rm", "mkdir", "upload", "send", "publish", "insert", 
            "add", "set", "modify", "save", "append", "touch", "post"
        ]
        self.call_timeout = 10.0
        self.max_concurrent_calls = 5
        self.log_level = "WARNING"
        
        self.exclude_tools = []
        self.include_only_tools = []
        self.exclude_plugins = []
        self.playbook = {}

    @staticmethod
    def load_and_validate(config_path: str) -> "Config":
        if not os.path.exists(config_path):
            raise ConfigValidationError(f"Configuration file not found: {config_path}")
            
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigValidationError(f"Invalid JSON format: {str(e)}")
            
        config = Config()
        config.validate_and_apply(data)
        return config

    def validate_and_apply(self, data: dict):
        if not isinstance(data, dict):
            raise ConfigValidationError("Root of configuration must be a JSON object.")
            
        # Top-level keys validation
        if "target" in data:
            if not isinstance(data["target"], str):
                raise ConfigValidationError("'target' must be a string.")
            self.target = data["target"]
            
        if "plugin_dir" in data:
            if not isinstance(data["plugin_dir"], str):
                raise ConfigValidationError("'plugin_dir' must be a string.")
            self.plugin_dir = data["plugin_dir"]
            
        if "format" in data:
            if data["format"] not in ["text", "json", "html", "markdown"]:
                raise ConfigValidationError("'format' must be one of 'text', 'json', 'html', or 'markdown'.")
            self.format = data["format"]
            
        if "verbose" in data:
            if not isinstance(data["verbose"], bool):
                raise ConfigValidationError("'verbose' must be a boolean.")
            self.verbose = data["verbose"]

        # Global section
        if "global" in data:
            glob = data["global"]
            if not isinstance(glob, dict):
                raise ConfigValidationError("'global' section must be an object.")
                
            if "allow_destructive" in glob:
                if not isinstance(glob["allow_destructive"], bool):
                    raise ConfigValidationError("'global.allow_destructive' must be a boolean.")
                self.allow_destructive = glob["allow_destructive"]
                
            if "unsafe_keywords" in glob:
                if not isinstance(glob["unsafe_keywords"], list) or not all(isinstance(x, str) for x in glob["unsafe_keywords"]):
                    raise ConfigValidationError("'global.unsafe_keywords' must be a list of strings.")
                self.unsafe_keywords = glob["unsafe_keywords"]
                
            if "env" in glob:
                if not isinstance(glob["env"], dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in glob["env"].items()):
                    raise ConfigValidationError("'global.env' must be an object with string keys and values.")
                self.env = glob["env"]
                
            if "verbose" in glob:
                if not isinstance(glob["verbose"], bool):
                    raise ConfigValidationError("'global.verbose' must be a boolean.")
                self.verbose = glob["verbose"]

            if "call_timeout" in glob:
                if not isinstance(glob["call_timeout"], (int, float)):
                    raise ConfigValidationError("'global.call_timeout' must be a number.")
                self.call_timeout = float(glob["call_timeout"])

            if "max_concurrent_calls" in glob:
                if not isinstance(glob["max_concurrent_calls"], int):
                    raise ConfigValidationError("'global.max_concurrent_calls' must be an integer.")
                self.max_concurrent_calls = glob["max_concurrent_calls"]

            if "log_level" in glob:
                if glob["log_level"] not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
                    raise ConfigValidationError("'global.log_level' must be a valid logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).")
                self.log_level = glob["log_level"]

        # Tools section
        if "tools" in data:
            tools = data["tools"]
            if not isinstance(tools, dict):
                raise ConfigValidationError("'tools' section must be an object.")
                
            if "exclude" in tools:
                if not isinstance(tools["exclude"], list) or not all(isinstance(x, str) for x in tools["exclude"]):
                    raise ConfigValidationError("'tools.exclude' must be a list of strings.")
                self.exclude_tools = tools["exclude"]
                
            if "include_only" in tools:
                if not isinstance(tools["include_only"], list) or not all(isinstance(x, str) for x in tools["include_only"]):
                    raise ConfigValidationError("'tools.include_only' must be a list of strings.")
                self.include_only_tools = tools["include_only"]

        # Plugins section
        if "plugins" in data:
            plugins = data["plugins"]
            if not isinstance(plugins, dict):
                raise ConfigValidationError("'plugins' section must be an object.")
                
            if "exclude" in plugins:
                if not isinstance(plugins["exclude"], list) or not all(isinstance(x, str) for x in plugins["exclude"]):
                    raise ConfigValidationError("'plugins.exclude' must be a list of strings.")
                self.exclude_plugins = plugins["exclude"]
