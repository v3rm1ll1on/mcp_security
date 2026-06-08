import os
import json
import tempfile
import pytest
from mcp_sec.core.config import Config, ConfigValidationError

def test_load_valid_config():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
        config_data = {
            "target": "python3 mock_server.py",
            "format": "json",
            "verbose": True,
            "global": {
                "allow_destructive": True,
                "unsafe_keywords": ["delete", "drop"],
                "env": {
                    "TEST_VAR": "value"
                }
            },
            "tools": {
                "exclude": ["tool_a"],
                "include_only": ["tool_b"]
            },
            "plugins": {
                "exclude": ["ping"]
            }
        }
        json.dump(config_data, f)
        f.flush()
        
    try:
        config = Config.load_and_validate(f.name)
        assert config.target == "python3 mock_server.py"
        assert config.format == "json"
        assert config.verbose is True
        assert config.allow_destructive is True
        assert config.unsafe_keywords == ["delete", "drop"]
        assert config.env == {"TEST_VAR": "value"}
        assert config.exclude_tools == ["tool_a"]
        assert config.include_only_tools == ["tool_b"]
        assert config.exclude_plugins == ["ping"]
    finally:
        os.remove(f.name)

def test_validation_invalid_json():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
        f.write("{ invalid json }")
        f.flush()
        
    try:
        with pytest.raises(ConfigValidationError) as excinfo:
            Config.load_and_validate(f.name)
        assert "Invalid JSON format" in str(excinfo.value)
    finally:
        os.remove(f.name)

def test_validation_type_mismatch():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
        config_data = {
            "global": {
                "allow_destructive": "yes_please"  # Should be boolean
            }
        }
        json.dump(config_data, f)
        f.flush()
        
    try:
        with pytest.raises(ConfigValidationError) as excinfo:
            Config.load_and_validate(f.name)
        assert "'global.allow_destructive' must be a boolean" in str(excinfo.value)
    finally:
        os.remove(f.name)

def test_validation_unsafe_keywords_type_mismatch():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
        config_data = {
            "global": {
                "unsafe_keywords": [123, "delete"]  # Contains int
            }
        }
        json.dump(config_data, f)
        f.flush()
        
    try:
        with pytest.raises(ConfigValidationError) as excinfo:
            Config.load_and_validate(f.name)
        assert "'global.unsafe_keywords' must be a list of strings" in str(excinfo.value)
    finally:
        os.remove(f.name)

def test_load_html_markdown_config():
    for fmt in ["html", "markdown"]:
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
            config_data = {
                "target": "python3 mock_server.py",
                "format": fmt,
            }
            json.dump(config_data, f)
            f.flush()
            
        try:
            config = Config.load_and_validate(f.name)
            assert config.format == fmt
        finally:
            os.remove(f.name)

def test_config_defaults():
    config = Config()
    assert config.target is None
    assert config.format == "text"
    assert config.verbose is False
    assert config.allow_destructive is False
    assert len(config.unsafe_keywords) > 0
    assert config.exclude_tools == []
    assert config.include_only_tools == []
    assert config.exclude_plugins == []


