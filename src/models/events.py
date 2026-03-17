"""
Event Data Models

This module defines the data structures used throughout the log analyzer.
Your job: Implement these classes to represent normalized log events.

HINTS:
- Use dataclasses or regular classes with __init__
- Consider using Enum for event_type and logon_type
- Think about what fields are required vs optional
- Consider how you'll serialize these to JSON for the frontend
"""

from dataclasses import dataclass, field
from dataclasses import dataclass, asdict
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
    """
    TODO: Define the possible event types
    
    Think about:
    - What are the main categories of authentication events?
    - Reference the DOMAIN_KNOWLEDGE.md for guidance
    
    Example:
        LOGON_SUCCESS = "logon_success"
        LOGON_FAILURE = "logon_failure"
        ... add more
    """


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
    """
    TODO: Define the logon types (especially important for Windows)
    
    Reference Windows logon types from DOMAIN_KNOWLEDGE.md:
    - Interactive (2)
    - Network (3)
    - Remote Interactive (10)
    - etc.
    """


class SourceType(Enum):
    WINDOWS_SECURITY = "windows_security"
    LINUX_AUTH = "linux_auth"
    SSH = "ssh"


@dataclass
class AuthEvent:
    # Core Feilds
    timestamp: datetime
    event_type: EventType
    source_type: SourceType
    username: str

    #Identity Feilds
    domain: Optional[str] = None
    source_ip: Optional[str] = None
    source_hostname: Optional[str] = None

    # Target Feilds
    target_hostname: Optional[str] = None
    target_ip: Optional[str] = None

    # Authentication Details
    logon_type: Optional[LogonType] = None 
    auth_method: Optional[str] = None
    failure_reason: Optional[str] = None

    # Meta Data
    raw_event_id: Optional[str] = None
    raw_message: Optional[str] = None

    #Analysis Feilds
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    """
    Normalized authentication event.
    
    This is the CORE data structure of your analyzer. All parsers should
    convert their specific log formats into this common structure.
    
    TODO: Add all necessary fields. Reference the normalized schema in
    DOMAIN_KNOWLEDGE.md (Part 4).
    
    Required fields to consider:
    - timestamp: When did this event occur?
    - event_type: What kind of event is this?
    - source_type: What log format did this come from?
    - username: Who is this event about?
    - source_ip: Where did the connection come from?
    - target_hostname: What system was accessed?
    - success: Did the authentication succeed?
    
    Optional fields to consider:
    - domain: Windows domain (null for Linux)
    - logon_type: Type of logon (interactive, network, etc.)
    - auth_method: How did they authenticate? (password, key, etc.)
    - failure_reason: Why did it fail? (if applicable)
    - raw_message: Original log line for debugging
    
    Analysis fields (populated by analyzers):
    - risk_score: 0-100 calculated risk
    - risk_factors: List of reasons for the risk score
    - tags: Custom tags like "brute_force", "off_hours"
    """
    
    def to_dict(self) -> dict:
        result = asdict(self)
        if result['timestamp'] is not None:
            result['timestamp'] = result["timestamp"].isoformat()
        if result["event_type"] is not None:
            result["event_type"] = result["event_type"].value
        if result["source_type"] is not None:
            result["source_type"] = result["source_type"].value
        if result["logon_type"] is not None:
            result["logon_type"] = result["logon_type"].value
        
        return result
    
    @classmethod
    def from_dict(cls, data: dict) -> 'AuthEvent':
        converted = data.copy()

        if converted["timestamp"] is not None:
            converted["timestamp"] = datetime.fromisoformat(converted["timestamp"])
        if converted["event_type"] is not None:
            converted["event_type"]= EventType(converted["event_type"])
        if converted["source_type"] is not None:
            converted["source_type"] = SourceType(converted["source_type"])
        if converted["logon_type"] is not None:
            converted["logon_type"] = LogonType(converted["logon_type"])
        
        return cls(**converted)
    


@dataclass
class DetectionAlert:
    alert_id: str
    detection_name: str
    severity: str
    related_events: List[AuthEvent]
    mitre_technique: str
    description:str
    timestamp: datetime

    """
    Represents a security detection/alert.
    
    When your analyzers detect something suspicious (brute force, anomaly, etc.),
    they should create one of these.
    
    TODO: Define the fields needed for an alert
    
    Consider:
    - What detection rule triggered this?
    - What events are involved?
    - How severe is it?
    - What's the MITRE ATT&CK mapping?
    """
    



@dataclass  
class AnalysisSummary:
    total_events: int
    success_count: int
    failure_count: int
    unique_users: int
    unique_ips: int
    unique_hosts: int
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    alerts_generated: int = 0

    """
    Summary statistics for a set of analyzed logs.
    
    TODO: Define fields for summary statistics
    
    Consider:
    - Total events analyzed
    - Success vs failure counts
    - Unique users, IPs, hosts
    - Time range covered
    - Alerts generated
    """
    


# =============================================================================
# TESTING YOUR IMPLEMENTATION
# =============================================================================
# 
# Once you've implemented the classes above, you should be able to run:
#
# ```python
# from src.models.events import AuthEvent, EventType, LogonType
# 
# event = AuthEvent(
#     timestamp=datetime.now(),
#     event_type=EventType.LOGON_SUCCESS,
#     username="jsmith",
#     source_ip="192.168.1.100",
#     # ... other fields
# )
# 
# print(event.to_dict())
# ```
#
# Write tests in tests/test_models.py to verify your implementation!
# =============================================================================
