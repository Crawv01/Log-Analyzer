"""
Event Data Models

Defines the normalized data structures used throughout the log analyzer.
All parsers convert their specific log formats into these common structures.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List
from enum import Enum


class EventType(Enum):
    LOGON_SUCCESS = "logon_success"
    LOGON_FAILURE = "logon_failure"
    LOGOFF = "logoff"
    USER_LOGOFF = "user_logoff"
    EXPLICIT_CREDLOGON = "explicit_credential_logon"
    SPECIAL_PRIV = "special_privileges_assigned"
    NTLM_AUTH_ATTEMPT = "ntlm_authentication_attempt"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_OPEN = "session_open"
    SESSION_CLOSED = "session_closed"


class LogonType(Enum):
    INTERACTIVE = "interactive"
    NETWORK = "network"
    BATCH = "batch"
    SERVICE = "service"
    UNLOCK = "unlock"
    NETWORK_CLEARTEXT = "network_cleartext"
    NEW_CREDENTIALS = "new_credentials"
    REMOTE_INTERACTIVE = "remote_interactive"
    CACHED_INTERACTIVE = "cached_interactive"


class SourceType(Enum):
    WINDOWS_SECURITY = "windows_security"
    LINUX_AUTH = "linux_auth"
    SSH = "ssh"


@dataclass
class AuthEvent:
    """
    Normalized authentication event.
    All parsers should convert their specific log formats into this structure.
    """

    # Core Fields
    timestamp: datetime
    event_type: EventType
    source_type: SourceType
    username: str
    success: bool = False

    # Identity Fields
    domain: Optional[str] = None
    source_ip: Optional[str] = None
    source_hostname: Optional[str] = None

    # Target Fields
    target_hostname: Optional[str] = None
    target_ip: Optional[str] = None

    # Authentication Details
    logon_type: Optional[LogonType] = None
    auth_method: Optional[str] = None
    failure_reason: Optional[str] = None

    # Metadata
    raw_event_id: Optional[str] = None
    raw_message: Optional[str] = None

    # Analysis Fields (populated by analyzers)
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = asdict(self)
        if result['timestamp'] is not None:
            result['timestamp'] = result['timestamp'].isoformat()
        if result['event_type'] is not None:
            result['event_type'] = result['event_type'].value
        if result['source_type'] is not None:
            result['source_type'] = result['source_type'].value
        if result['logon_type'] is not None:
            result['logon_type'] = result['logon_type'].value
        return result

    @classmethod
    def from_dict(cls, data: dict) -> 'AuthEvent':
        converted = data.copy()
        if converted['timestamp'] is not None:
            converted['timestamp'] = datetime.fromisoformat(converted['timestamp'])
        if converted['event_type'] is not None:
            converted['event_type'] = EventType(converted['event_type'])
        if converted['source_type'] is not None:
            converted['source_type'] = SourceType(converted['source_type'])
        if converted['logon_type'] is not None:
            converted['logon_type'] = LogonType(converted['logon_type'])
        return cls(**converted)


@dataclass
class DetectionAlert:
    """
    Represents a security detection alert.
    Created by analyzers when suspicious activity is detected.
    """
    alert_id: str
    detection_name: str
    severity: str  # "low", "medium", "high", "critical"
    related_events: List[AuthEvent]
    mitre_technique: str
    description: str
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            'alert_id': self.alert_id,
            'detection_name': self.detection_name,
            'severity': self.severity,
            'related_events': [e.to_dict() for e in self.related_events],
            'mitre_technique': self.mitre_technique,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
        }


@dataclass
class AnalysisSummary:
    """
    Summary statistics for a set of analyzed logs.
    """
    total_events: int
    success_count: int
    failure_count: int
    unique_users: int
    unique_ips: int
    unique_hosts: int
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    alerts_generated: int = 0

    def to_dict(self) -> dict:
        return {
            'total_events': self.total_events,
            'success_count': self.success_count,
            'failure_count': self.failure_count,
            'unique_users': self.unique_users,
            'unique_ips': self.unique_ips,
            'unique_hosts': self.unique_hosts,
            'time_range_start': self.time_range_start.isoformat() if self.time_range_start else None,
            'time_range_end': self.time_range_end.isoformat() if self.time_range_end else None,
            'alerts_generated': self.alerts_generated,
        }
