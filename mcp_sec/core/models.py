from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional

class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Vulnerability:
    title: str
    description: str
    severity: Severity
    tool_name: Optional[str] = None
    payload: Optional[str] = None

@dataclass
class PluginResult:
    plugin_name: str
    success: bool
    message: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
