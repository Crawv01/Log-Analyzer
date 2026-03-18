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
        # SSH successful login
        # Matches: "sshd[1234]: Accepted publickey for admin from 192.168.1.10 port 52413 ssh2"
        self._ssh_accepted = re.compile(
            r'sshd\[(\d+)\]: Accepted (\w+) for (\S+) from ([\d.]+) port (\d+)'
        )

        # SSH failed login - invalid user
        # Matches: "sshd[2100]: Failed password for invalid user admin123 from 198.51.100.25 port 60001 ssh2"
        self._ssh_failed_invalid = re.compile(
            r'sshd\[(\d+)\]: Failed password for invalid user (\S+) from ([\d.]+) port (\d+)'
        )

        # SSH failed login - valid user
        # Matches: "sshd[2001]: Failed password for root from 203.0.113.50 port 55001 ssh2"
        self._ssh_failed = re.compile(
            r'sshd\[(\d+)\]: Failed password for (\S+) from ([\d.]+) port (\d+)'
        )

        # Sudo success
        # Matches: "sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/systemctl status nginx"
        self._sudo_success = re.compile(
            r'sudo:\s+(\S+)\s+:.*?USER=(\S+)\s*;\s*COMMAND=(.*)'
        )

        # Sudo failure - command not allowed
        # Matches: "sudo: developer : command not allowed ; TTY=pts/1 ..."
        self._sudo_failed_notallowed = re.compile(
            r'sudo:\s+(\S+)\s+: command not allowed'
        )

        # Sudo failure - incorrect password attempts
        # Matches: "sudo: developer : 3 incorrect password attempts ..."
        self._sudo_failed_badpass = re.compile(
            r'sudo:\s+(\S+)\s+: \d+ incorrect password attempts'
        )

        # Su success
        # Matches: "su[4001]: Successful su for root by admin"
        self._su_success = re.compile(
            r'su\[(\d+)\]: Successful su for (\S+) by (\S+)'
        )

        # Su failure
        # Matches: "su[4002]: FAILED su for root by developer"
        self._su_failed = re.compile(
            r'su\[(\d+)\]: FAILED su for (\S+) by (\S+)'
        )

        # Session opened
        # Matches: "sshd[1234]: pam_unix(sshd:session): session opened for user admin by (uid=0)"
        self._session_open = re.compile(
            r'pam_unix\(\w+:session\): session opened for user (\S+)'
        )

        # Session closed
        # Matches: "sshd[1234]: pam_unix(sshd:session): session closed for user admin"
        self._session_closed = re.compile(
            r'pam_unix\(\w+:session\): session closed for user (\S+)'
        )

    @property
    def parser_name(self) -> str:
        return "Linux Auth Log Parser"

    def get_supported_extensions(self) -> List[str]:
        return ['.log', '']  # auth.log has .log extension, 'secure' has none

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

        # SSH accepted (success)
        match = self._ssh_accepted.search(line)
        if match:
            return self._create_ssh_success_event(line, match)

        # SSH failed - check invalid user first (more specific pattern)
        match = self._ssh_failed_invalid.search(line)
        if match:
            return self._create_ssh_failure_event(line, match, invalid_user=True)

        # SSH failed - valid user
        match = self._ssh_failed.search(line)
        if match:
            return self._create_ssh_failure_event(line, match, invalid_user=False)

        # Sudo failure - command not allowed
        match = self._sudo_failed_notallowed.search(line)
        if match:
            return self._create_sudo_event(line, match, success=False)

        # Sudo failure - bad password
        match = self._sudo_failed_badpass.search(line)
        if match:
            return self._create_sudo_event(line, match, success=False)

        # Sudo success
        match = self._sudo_success.search(line)
        if match:
            return self._create_sudo_event(line, match, success=True)

        # Su success
        match = self._su_success.search(line)
        if match:
            return self._create_su_event(line, match, success=True)

        # Su failure
        match = self._su_failed.search(line)
        if match:
            return self._create_su_event(line, match, success=False)

        # Session opened
        match = self._session_open.search(line)
        if match:
            return self._create_session_event(line, match, opened=True)

        # Session closed
        match = self._session_closed.search(line)
        if match:
            return self._create_session_event(line, match, opened=False)

        return None

    def _parse_syslog_timestamp(self, line: str) -> Optional[datetime]:
        try:
            current_year = datetime.now().year
            timestamp_str = f"{current_year} {line[:15]}"
            dt = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
            return dt
        except ValueError:
            return None

    def _create_ssh_success_event(self, line: str, match: re.Match) -> AuthEvent:
        """
        Create an AuthEvent from a successful SSH login.
        Groups: (pid, auth_method, username, source_ip, port)
        """
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
        Create an AuthEvent from a failed SSH login.
        Groups: (pid, username, source_ip, port)
        invalid_user=True means the username doesn't exist on the system (enumeration attempt).
        """
        _, username, source_ip, _ = match.groups()
        tags = ['invalid_user'] if invalid_user else []
        failure_reason = 'Invalid user' if invalid_user else 'Bad password'
        return AuthEvent(
            timestamp=self._parse_syslog_timestamp(line),
            event_type=EventType.LOGON_FAILURE,
            source_type=SourceType.SSH,
            username=username,
            source_ip=source_ip,
            logon_type=LogonType.NETWORK,
            auth_method='password',
            failure_reason=failure_reason,
            success=False,
            tags=tags,
            raw_message=line,
        )

    def _create_sudo_event(self, line: str, match: re.Match, success: bool) -> AuthEvent:
        """
        Create an AuthEvent from a sudo command attempt.
        Success groups: (username, target_user, command)
        Failure groups: (username,)
        Sudo is a privilege escalation event.
        """
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
        """
        Create an AuthEvent from a su (switch user) attempt.
        Groups: (pid, target_user, username)
        """
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
        """
        Create an AuthEvent from a PAM session open/close event.
        Groups: (username,)
        """
        username = match.group(1)
        return AuthEvent(
            timestamp=self._parse_syslog_timestamp(line),
            event_type=EventType.SESSION_OPEN if opened else EventType.SESSION_CLOSED,
            source_type=SourceType.LINUX_AUTH,
            username=username,
            success=True,
            raw_message=line,
        )
