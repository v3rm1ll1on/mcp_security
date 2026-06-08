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
    cwe: Optional[str] = None
    owasp: Optional[str] = None

@dataclass
class PluginResult:
    plugin_name: str
    success: bool
    message: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    skipped: bool = False

    @classmethod
    def from_vulnerabilities(cls, plugin_name: str, vulnerabilities: List[Vulnerability], success_message: str = "No issues found.", skipped: bool = False) -> "PluginResult":
        success = len(vulnerabilities) == 0
        message = f"Found {len(vulnerabilities)} vulnerabilities." if not success else success_message
        return cls(
            plugin_name=plugin_name,
            success=success,
            message=message,
            vulnerabilities=vulnerabilities,
            skipped=skipped
        )
