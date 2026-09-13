import json
import os
from pathlib import Path

class Config:
    def __init__(self, config_path=None):
        self.config_path = config_path or Path(__file__).parent.parent / "settings.json"
        self.data = self._load_defaults()
        self.load()

    def _load_defaults(self):
        return {
            "app": {
                "name": "XCV-GHOST",
                "version": "1.1.0",
                "author": "xcv",
                "social": "@fatih_onee"
            },
            "output": {
                "directory": "outputs",
                "format": "txt",
                "save_logs": True
            },
            "logging": {
                "enabled": True,
                "level": "INFO",
                "file": "outputs/logs/ghost.log"
            },
            "modules": {
                "forensics": {"enabled": True},
                "crypto": {"enabled": True},
                "pwn": {"enabled": True},
                "reverse": {"enabled": True},
                "ai": {"enabled": True}
            },
            "plugins": {
                "directory": "plugins",
                "auto_load": True
            },
            "wordlists": {
                "directory": "wordlists"
            },
            "theme": {
                "primary_color": "cyan",
                "secondary_color": "yellow",
                "error_color": "red",
                "success_color": "green"
            }
        }

    def load(self):
        try:
            if self.config_path.exists():
                with open(self.config_path) as f:
                    user_config = json.load(f)
                    self._merge(user_config)
        except Exception as e:
            pass

    def _merge(self, user_config):
        for key, value in user_config.items():
            if key in self.data and isinstance(self.data[key], dict) and isinstance(value, dict):
                self.data[key].update(value)
            else:
                self.data[key] = value

    def save(self):
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.data, f, indent=4)
        except Exception as e:
            pass

    def get(self, *keys, default=None):
        current = self.data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def set(self, value, *keys):
        current = self.data
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value
        self.save()

