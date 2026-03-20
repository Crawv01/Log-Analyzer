"""
Linux Auth Log Parser

Parses Linux authentication logs (auth.log, secure) into normalized AuthEvent objects.
Handles SSH logins, sudo commands, su attempts, and session events.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .base_parser import BaseParser, ParseError
from src.models.events import AuthEvent, EventType, SourceType, LogonType


class LinuxAuthParser(BaseParser):
    """
    Parser for Linux auth.log / secure log files.

    Handles:
    - SSH authentication (success and failure, including invalid users)
    - Sudo commands (success and failure)
    - Su (user switching) success and failure
    - Session open/close events
    - PAM authentication events
    """

    def __init__(self):
        self._ssh_accepted = re.compile(
            r'sshd\[(\d+)\]: Accepted (\w+) for (\S+) from ([\d.]+) port (\d+)'
        )
        self._ssh_failed_invalid = re.compile(
            r'sshd\[(\d+)\]: Failed password for invalid user (\S+) from ([\d.]+) port (\d+)'
        )
        self._ssh_failed = re.compile(
            r'sshd\[(\d+)\]: Failed password for (\S+) from ([\d.]+) port (\d+)'
        )
        self._sudo_success = re.compile(
            r'sudo:\s+(\S+)\s+:.*?USER=(\S+)\s*;\s*COMMAND=(.*)'
        )
        self._sudo_failed_notallowed = re.compile(
            r'sudo:\s+(\S+)\s+: command not allowed'
        )
        self._sudo_failed_badpass = re.compile(
            r'sudo:\s+(\S+)\s+: \d+ incorrect password attempts'
        )
        self._su_success = re.compile(
            r'su\[(\d+)\]: Successful su for (\S+) by (\S+)'
        )
        self._su_failed = re.compile(
            r'su\[(\d+)\]: FAILED su for (\S+) by (\S+)'
        )
        self._session_open = re.compile(
            r'pam_unix\(\w+:session\): session opened for user (\S+)'
        )
        self._session_closed = re.compile(
            r'pam_unix\(\w+:session\): session closed for user (\S+)'
        )

    @property
    def parser_name(self) -> str:
        return "Linux Auth Log Parser"

    def get_supported_extensions(self) -> List[str]:
        return ['.log', '']

    def parse_file(self, filepath: Path) -> List[AuthEvent]:
        """
        Parse an entire auth.log file and return a list of AuthEvents.
        Skips lines that don't match any known pattern.
        Logs warnings for lines that fail to parse but continues processing.
        """
        events = []
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    event = self.parse_line(line.strip())
                    if event:
                        events.append(event)
                except Exception as e:
                    print(f"Warning: Could not parse line {line_num}: {e}")
        return events

    def parse_line(self, line: str) -> Optional[AuthEvent]:
        """
        Parse a single log line into an AuthEvent.
        Returns None if the line doesn't match any known auth event pattern.
        """
        if not line or line.startswith('#'):
            return None

        match = self._ssh_accepted.search(line)
        if match:
            return self._create_ssh_success_event(line, match)

        # Check invalid user before valid user — more specific pattern must come first
        match = self._ssh_failed_invalid.search(line)
        if match:
            return self._create_ssh_failure_event(line, match, invalid_user=True)

        match = self._ssh_failed.search(line)
        if match:
            return self._create_ssh_failure_event(line, match, invalid_user=False)

        match = self._sudo_failed_notallowed.search(line)
        if match:
            return self._create_sudo_event(line, match, success=False)

        match = self._sudo_failed_badpass.search(line)
        if match:
            return self._create_sudo_event(line, match, success=False)

        match = self._sudo_success.search(line)
        if match:
            return self._create_sudo_event(line, match, success=True)

        match = self._su_success.search(line)
        if match:
            return self._create_su_event(line, match, success=True)

        match = self._su_failed.search(line)
        if match:
            return self._create_su_event(line, match, success=False)

        match = self._session_open.search(line)
        if match:
            return self._create_session_event(line, match, opened=True)

        match = self._session_closed.search(line)
        if match:
            return self._create_session_event(line, match, opened=False)

        return None

    def _parse_syslog_timestamp(self, line: str) -> Optional[datetime]:
        """
        Extract timestamp from syslog format: "Jan 15 08:00:01 hostname ..."
        Year is not included in syslog format so current year is assumed.
        """
        try:
            current_year = datetime.now().year
            timestamp_str = f"{current_year} {line[:15]}"
            return datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
        except ValueError:
            return None

    def _create_ssh_success_event(self, line: str, match: re.Match) -> AuthEvent:
        _, auth_method, username, source_ip, _ = match.groups()
        return AuthEvent(
            timestamp=self._parse_syslog_timestamp(line),
            event_type=EventType.LOGON_SUCCESS,
            source_type=SourceType.SSH,
            username=username,
            source_ip=source_ip,
            logon_type=LogonType.NETWORK,
            auth_method=auth_method,
            success=True,
            raw_message=line,
        )

    def _create_ssh_failure_event(self, line: str, match: re.Match, invalid_user: bool = False) -> AuthEvent:
        """
        invalid_user=True indicates the username doesn't exist on the system,
        which is significant for detecting enumeration attacks.
        """
        _, username, source_ip, _ = match.groups()
        return AuthEvent(
            timestamp=self._parse_syslog_timestamp(line),
            event_type=EventType.LOGON_FAILURE,
            source_type=SourceType.SSH,
            username=username,
            source_ip=source_ip,
            logon_type=LogonType.NETWORK,
            auth_method='password',
            failure_reason='Invalid user' if invalid_user else 'Bad password',
            success=False,
            tags=['invalid_user'] if invalid_user else [],
            raw_message=line,
        )

    def _create_sudo_event(self, line: str, match: re.Match, success: bool) -> AuthEvent:
        username = match.group(1)
        target_user = match.group(2) if success and len(match.groups()) >= 2 else None
        command = match.group(3).strip() if success and len(match.groups()) >= 3 else None
        return AuthEvent(
            timestamp=self._parse_syslog_timestamp(line),
            event_type=EventType.PRIVILEGE_ESCALATION,
            source_type=SourceType.LINUX_AUTH,
            username=username,
            target_hostname=target_user,
            auth_method='sudo',
            success=success,
            failure_reason=None if success else 'Command not allowed or bad password',
            raw_message=line,
            tags=['sudo', f'command:{command}'] if command else ['sudo'],
        )

    def _create_su_event(self, line: str, match: re.Match, success: bool) -> AuthEvent:
        _, target_user, username = match.groups()
        return AuthEvent(
            timestamp=self._parse_syslog_timestamp(line),
            event_type=EventType.LOGON_SUCCESS if success else EventType.LOGON_FAILURE,
            source_type=SourceType.LINUX_AUTH,
            username=username,
            target_hostname=target_user,
            auth_method='su',
            logon_type=LogonType.INTERACTIVE,
            success=success,
            failure_reason=None if success else 'Authentication failure',
            raw_message=line,
            tags=['su'],
        )

    def _create_session_event(self, line: str, match: re.Match, opened: bool) -> AuthEvent:
        return AuthEvent(
            timestamp=self._parse_syslog_timestamp(line),
            event_type=EventType.SESSION_OPEN if opened else EventType.SESSION_CLOSED,
            source_type=SourceType.LINUX_AUTH,
            username=match.group(1),
            success=True,
            raw_message=line,
        )
