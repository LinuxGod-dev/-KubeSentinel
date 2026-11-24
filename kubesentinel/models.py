"""Core data models shared by checks and reporters."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    resource: str
    message: str
    remediation: str = ""
    cis: str = ""
    mitre: str = ""
    detection: List[str] = field(default_factory=list)  # linked Falco rule names
    evidence: List[str] = field(default_factory=list)
    location: str = "cluster"

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "category": self.category,
            "resource": self.resource,
            "message": self.message,
            "remediation": self.remediation,
            "cis": self.cis,
            "mitre": self.mitre,
            "detection": self.detection,
            "evidence": self.evidence,
            "location": self.location,
        }
