import os
import json
import tempfile
import pytest
from mcp_sec.core.playbook import Playbook, PlaybookValidationError

def test_load_valid_playbook():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
        playbook_data = {
            "mcpserver": "node server.js",
            "tools": {
                "read_file": ["path_traversal"],
                "fetch_webpage": ["*"]
            }
        }
        json.dump(playbook_data, f)
        f.flush()
        
    try:
        playbook = Playbook.load_and_validate(f.name)
        assert playbook.mcpserver == "node server.js"
        assert playbook.tools["read_file"] == ["path_traversal"]
        assert playbook.tools["fetch_webpage"] == ["*"]
    finally:
        os.remove(f.name)

def test_validation_invalid_json():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
        f.write("{ invalid json }")
        f.flush()
        
    try:
        with pytest.raises(PlaybookValidationError) as excinfo:
            Playbook.load_and_validate(f.name)
        assert "Invalid JSON format" in str(excinfo.value)
    finally:
        os.remove(f.name)

def test_validation_not_dict():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
        json.dump(["not", "a", "dict"], f)
        f.flush()
        
    try:
        with pytest.raises(PlaybookValidationError) as excinfo:
            Playbook.load_and_validate(f.name)
        assert "Playbook root must be a JSON object" in str(excinfo.value)
    finally:
        os.remove(f.name)

def test_validation_mcpserver_type():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
        playbook_data = {
            "mcpserver": 123
        }
        json.dump(playbook_data, f)
        f.flush()
        
    try:
        with pytest.raises(PlaybookValidationError) as excinfo:
            Playbook.load_and_validate(f.name)
        assert "'mcpserver' must be a string" in str(excinfo.value)
    finally:
        os.remove(f.name)

def test_validation_tools_type():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
        playbook_data = {
            "tools": "not-a-dict"
        }
        json.dump(playbook_data, f)
        f.flush()
        
    try:
        with pytest.raises(PlaybookValidationError) as excinfo:
            Playbook.load_and_validate(f.name)
        assert "'tools' must be an object mapping tool names" in str(excinfo.value)
    finally:
        os.remove(f.name)

def test_validation_tools_list_type():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
        playbook_data = {
            "tools": {
                "read_file": [123, "path_traversal"]
            }
        }
        json.dump(playbook_data, f)
        f.flush()
        
    try:
        with pytest.raises(PlaybookValidationError) as excinfo:
            Playbook.load_and_validate(f.name)
        assert "'tools.read_file' must be a list of strings" in str(excinfo.value)
    finally:
        os.remove(f.name)
