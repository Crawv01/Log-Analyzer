"""
Linux Auth Log Parser

This module parses Linux authentication logs (auth.log, secure).

YOUR TASK: Implement the LinuxAuthParser class to parse auth.log files.

HINTS:
1. Study the sample auth.log file to understand the format
2. Use regular expressions - they're your friend here
3. Handle different event types: SSH success/failure, sudo, su, session events
4. Don't forget to handle edge cases like "invalid user" messages
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
    - SSH authentication (success and failure)
    - Sudo commands (success and failure)
    - Su (user switching)
    - Session open/close events
    - PAM authentication events
    """
    
    def __init__(self):
        """
        Initialize the parser.
        
        TODO: Set up your regex patterns here.
        
        You'll need patterns for:
        - SSH successful login
        - SSH failed login (valid user)
        - SSH failed login (invalid user)
        - Sudo success
        - Sudo failure
        - Su success
        - Su failure
        - Session open
        - Session close
        
        HINT: Compile your regexes here for better performance:
        self._ssh_success_pattern = re.compile(r'...')
        """
        
        # TODO: Define your regex patterns
        # 
        # Example SSH success pattern (you need to finish this):
        # Pattern should match: "sshd[1234]: Accepted publickey for admin from 192.168.1.10 port 52413 ssh2"
        #
        # self._ssh_accepted_pattern = re.compile(
        #     r'sshd\[(\d+)\]: Accepted (\w+) for (\w+) from ([\d.]+) port (\d+)'
        # )
        #
        # Groups would be: (pid, auth_method, username, ip, port)
        
        pass  # DELETE THIS AND IMPLEMENT
    
    @property
    def parser_name(self) -> str:
        return "Linux Auth Log Parser"
    
    def get_supported_extensions(self) -> List[str]:
        return ['.log', '']  # auth.log has .log, 'secure' has no extension
    
    def parse_file(self, filepath: Path) -> List['AuthEvent']:
        """
        Parse an entire auth.log file.
        
        TODO: Implement this method
        
        Steps:
        1. Open the file
        2. Iterate through each line
        3. Call parse_line() for each line
        4. Collect non-None results into a list
        5. Return the list
        
        Handle errors gracefully - log parsing errors but don't crash.
        """
        
        # TODO: Implement
        # 
        # events = []
        # with open(filepath, 'r') as f:
        #     for line_num, line in enumerate(f, 1):
        #         try:
        #             event = self.parse_line(line.strip())
        #             if event:
        #                 events.append(event)
        #         except Exception as e:
        #             # Log the error but continue parsing
        #             print(f"Warning: Could not parse line {line_num}: {e}")
        # return events
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def parse_line(self, line: str) -> Optional['AuthEvent']:
        """
        Parse a single log line.
        
        TODO: Implement this method
        
        Steps:
        1. Skip empty lines and comments
        2. Extract the timestamp (beginning of line)
        3. Try to match against each of your regex patterns
        4. If a pattern matches, create an AuthEvent with the extracted data
        5. If no patterns match, return None (not an auth event we care about)
        
        IMPORTANT: The year is NOT included in syslog timestamps!
        You'll need to assume the current year (or make it configurable).
        """
        
        # TODO: Implement
        #
        # if not line or line.startswith('#'):
        #     return None
        #
        # # Try SSH accepted pattern
        # match = self._ssh_accepted_pattern.search(line)
        # if match:
        #     return self._create_ssh_success_event(line, match)
        #
        # # Try SSH failed pattern
        # match = self._ssh_failed_pattern.search(line)
        # if match:
        #     return self._create_ssh_failure_event(line, match)
        #
        # # ... try other patterns
        #
        # return None
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _parse_syslog_timestamp(self, line: str) -> Optional[datetime]:
        """
        Extract timestamp from a syslog-format line.
        
        TODO: Implement this method
        
        Syslog format: "Jan 15 14:22:01 hostname ..."
        
        HINT: 
        - Use datetime.strptime() with format "%b %d %H:%M:%S"
        - Handle the missing year (assume current year)
        - Watch out for year boundary issues (Dec 31 -> Jan 1)
        
        Returns:
            datetime object, or None if parsing fails
        """
        
        # TODO: Implement
        #
        # try:
        #     # Extract first 15 characters (timestamp portion)
        #     timestamp_str = line[:15]
        #     dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        #     # Add current year
        #     dt = dt.replace(year=datetime.now().year)
        #     return dt
        # except ValueError:
        #     return None
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _create_ssh_success_event(self, line: str, match: re.Match) -> 'AuthEvent':
        """
        Create an AuthEvent from a successful SSH login.
        
        TODO: Implement this method
        
        Extract from match groups:
        - pid (for reference)
        - auth_method (password, publickey)
        - username
        - source_ip
        - port
        
        Return a properly populated AuthEvent.
        """
        
        # TODO: Implement
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _create_ssh_failure_event(self, line: str, match: re.Match, invalid_user: bool = False) -> 'AuthEvent':
        """
        Create an AuthEvent from a failed SSH login.
        
        TODO: Implement this method
        
        Similar to success, but:
        - event_type should be LOGON_FAILURE
        - Note whether it's an "invalid user" attempt
        - This distinction is important for detecting enumeration attacks
        """
        
        # TODO: Implement
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _create_sudo_event(self, line: str, match: re.Match, success: bool) -> 'AuthEvent':
        """
        Create an AuthEvent from a sudo command.
        
        TODO: Implement this method
        
        Sudo logs contain:
        - Username
        - TTY
        - PWD (working directory)
        - Target user (usually root)
        - Command executed
        
        This is PRIVILEGE_ESCALATION type event.
        """
        
        # TODO: Implement
        
        pass  # DELETE THIS AND IMPLEMENT


# =============================================================================
# TESTING YOUR IMPLEMENTATION
# =============================================================================
#
# Once implemented, test with:
#
# ```python
# from src.parsers.linux_parser import LinuxAuthParser
# from pathlib import Path
#
# parser = LinuxAuthParser()
# events = parser.parse_file(Path("sample-data/auth.log"))
#
# for event in events:
#     print(f"{event.timestamp} - {event.event_type} - {event.username} from {event.source_ip}")
# ```
#
# Expected output should show:
# - SSH logins (success and failure)
# - The brute force attack events
# - Sudo commands
# - Session events
#
# =============================================================================


# =============================================================================
# REGEX HINTS (Don't look unless stuck!)
# =============================================================================
#
# SSH Accepted:
#   r'sshd\[(\d+)\]: Accepted (\w+) for (\S+) from ([\d.]+) port (\d+)'
#
# SSH Failed (valid user):
#   r'sshd\[(\d+)\]: Failed password for (\S+) from ([\d.]+) port (\d+)'
#
# SSH Failed (invalid user):
#   r'sshd\[(\d+)\]: Failed password for invalid user (\S+) from ([\d.]+) port (\d+)'
#
# Sudo success:
#   r'sudo:\s+(\S+)\s+:.*USER=(\S+)\s+;\s+COMMAND=(.*)'
#
# Sudo failure:
#   r'sudo:\s+(\S+)\s+: command not allowed'
#
# =============================================================================
