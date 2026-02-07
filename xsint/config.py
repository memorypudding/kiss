import json
import os
from typing import Optional

CONFIG_FILE = "config.json"


class ConfigManager:
    def __init__(self):
        self.data = {}
        self.load()

    def load(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    self.data = json.load(f)
            except:
                self.data = {}

    def save(self):
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.data, f, indent=2)

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def set(self, key: str, value):
        self.data[key] = value
        self.save()

    def get_api_key(self, service: str) -> Optional[str]:
        # Check environment variable first (XSINT_HIBP_API_KEY)
        env_key = os.environ.get(f"XSINT_{service.upper()}_API_KEY")
        if env_key and env_key.strip():
            return env_key
        # Check local config
        config_key = self.data.get(f"{service}_key")
        if config_key and config_key.strip():
            return config_key
        return None


# Singleton instance
_config = ConfigManager()


def get_config():
    return _config
