"""Tests for configuration management."""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch

from xsint.config import Config, get_config, reload_config


class TestConfig:
    """Tests for Config class."""

    @pytest.fixture
    def temp_config_dir(self, tmp_path):
        """Create a temporary config directory."""
        config_dir = tmp_path / ".xsint"
        config_dir.mkdir()
        return config_dir

    @pytest.fixture
    def config_with_temp_path(self, temp_config_dir):
        """Create a Config instance with temp path."""
        config_path = temp_config_dir / "config.json"
        return Config(config_path=config_path)

    def test_default_config(self, config_with_temp_path):
        """Test that default config values are set."""
        config = config_with_temp_path

        assert config.timeout == 5
        assert config.hibp_rate_limit == 1.6
        assert config.theme == "Ocean"
        assert config.animations_enabled is True

    def test_get_api_key_empty(self, config_with_temp_path):
        """Test getting API key that's not configured."""
        config = config_with_temp_path

        assert config.get_api_key("HIBP") == ""
        assert config.is_api_key_configured("HIBP") is False

    def test_set_api_key(self, config_with_temp_path):
        """Test setting an API key."""
        config = config_with_temp_path

        config.set_api_key("HIBP", "test_key_123")

        assert config.get_api_key("HIBP") == "test_key_123"
        assert config.is_api_key_configured("HIBP") is True

    def test_is_api_key_configured_placeholder(self, config_with_temp_path):
        """Test that placeholder values are not considered configured."""
        config = config_with_temp_path

        config.set_api_key("HIBP", "INSERT_KEY_HERE")
        assert config.is_api_key_configured("HIBP") is False

    def test_get_set_values(self, config_with_temp_path):
        """Test getting and setting arbitrary values."""
        config = config_with_temp_path

        config.set("ui", "theme", "Matrix")
        assert config.get("ui", "theme") == "Matrix"

    def test_get_default_value(self, config_with_temp_path):
        """Test getting value with default."""
        config = config_with_temp_path

        assert config.get("nonexistent", "key", "default") == "default"

    def test_save_config(self, temp_config_dir):
        """Test saving configuration to file."""
        config_path = temp_config_dir / "config.json"
        config = Config(config_path=config_path)

        config.set_api_key("HIBP", "my_secret_key")
        config.save()

        assert config_path.exists()

        with open(config_path) as f:
            saved = json.load(f)

        assert saved["api_keys"]["HIBP"] == "my_secret_key"

    def test_load_config_from_file(self, temp_config_dir):
        """Test loading configuration from file."""
        config_path = temp_config_dir / "config.json"

        # Write config file
        config_data = {
            "api_keys": {"HIBP": "loaded_key"},
            "ui": {"theme": "Fire"},
        }
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        # Load config
        config = Config(config_path=config_path)

        assert config.get_api_key("HIBP") == "loaded_key"
        assert config.theme == "Fire"

    def test_env_override(self, config_with_temp_path):
        """Test that environment variables override config file."""
        with patch.dict(os.environ, {"XSINT_HIBP_API_KEY": "env_key"}):
            config = Config(config_path=config_with_temp_path.config_path)

            assert config.get_api_key("HIBP") == "env_key"

    def test_api_keys_property(self, config_with_temp_path):
        """Test getting all API keys."""
        config = config_with_temp_path

        keys = config.api_keys
        assert "HIBP" in keys
        assert "IPSTACK" in keys

    def test_invalid_json_file(self, temp_config_dir):
        """Test handling of invalid JSON config file."""
        config_path = temp_config_dir / "config.json"

        with open(config_path, "w") as f:
            f.write("not valid json {{{")

        # Should not raise, just use defaults
        config = Config(config_path=config_path)
        assert config.timeout == 5


class TestDotEnv:
    """Tests for .env file loading."""

    def test_load_dotenv(self, tmp_path, monkeypatch):
        """Test loading .env file."""
        # Change to temp directory
        monkeypatch.chdir(tmp_path)

        # Create .env file
        env_file = tmp_path / ".env"
        env_file.write_text("XSINT_HIBP_API_KEY=dotenv_key\n")

        config = Config(config_path=tmp_path / "config.json")

        assert config.get_api_key("HIBP") == "dotenv_key"

    def test_dotenv_with_quotes(self, tmp_path, monkeypatch):
        """Test .env file with quoted values."""
        monkeypatch.chdir(tmp_path)

        env_file = tmp_path / ".env"
        env_file.write_text('XSINT_HIBP_API_KEY="quoted_key"\n')

        config = Config(config_path=tmp_path / "config.json")

        assert config.get_api_key("HIBP") == "quoted_key"

    def test_dotenv_comments(self, tmp_path, monkeypatch):
        """Test .env file with comments."""
        monkeypatch.chdir(tmp_path)

        env_file = tmp_path / ".env"
        env_file.write_text("# This is a comment\nXSINT_HIBP_API_KEY=key\n")

        config = Config(config_path=tmp_path / "config.json")

        assert config.get_api_key("HIBP") == "key"


class TestGlobalConfig:
    """Tests for global config functions."""

    def test_get_config_singleton(self):
        """Test that get_config returns same instance."""
        # Reset global
        import xsint.config
        xsint.config._config = None

        config1 = get_config()
        config2 = get_config()

        assert config1 is config2

    def test_reload_config(self):
        """Test that reload_config creates new instance."""
        import xsint.config
        xsint.config._config = None

        config1 = get_config()
        config2 = reload_config()

        assert config1 is not config2
