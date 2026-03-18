"""
Windows Security Event Log Parser

Parses Windows Security Event Logs in XML format into normalized AuthEvent objects.
Handles Event IDs: 4624 (logon success), 4625 (logon failure), 4634 (logoff), 4672 (special privileges).
"""

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict

from .base_parser import BaseParser, ParseError
from src.models.events import AuthEvent, EventType, SourceType, LogonType


class WindowsEventParser(BaseParser):
    """
    Parser for Windows Security Event Logs in XML format.

    Handles Event IDs:
    - 4624: Successful logon
    - 4625: Failed logon
    - 4634: Logoff
    - 4647: User-initiated logoff
    - 4672: Special privileges assigned to new logon
    """

    # Maps Windows logon type numbers to LogonType enum values
    LOGON_TYPE_MAP = {
        '2':  LogonType.INTERACTIVE,
        '3':  LogonType.NETWORK,
        '4':  LogonType.BATCH,
        '5':  LogonType.SERVICE,
        '7':  LogonType.UNLOCK,
        '8':  LogonType.NETWORK_CLEARTEXT,
        '9':  LogonType.NEW_CREDENTIALS,
        '10': LogonType.REMOTE_INTERACTIVE,
        '11': LogonType.CACHED_INTERACTIVE,
    }

    # Maps Windows SubStatus hex codes to human-readable reasons
    SUBSTATUS_REASONS = {
        '0xC000006A': 'Bad password',
        '0xC0000064': 'User does not exist',
        '0xC0000072': 'Account disabled',
        '0xC0000234': 'Account locked out',
        '0xC0000071': 'Password expired',
        '0xC0000070': 'Workstation restriction',
        '0xC000006D': 'Logon failure',
        '0xC000006F': 'Time restriction',
    }

    def __init__(self):
        # XML namespace used in standard Windows event logs
        # Note: the sample file uses <s> instead of <System> — we handle both
        self._namespace = {
            'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'
        }

    @property
    def parser_name(self) -> str:
        return "Windows Security Event Parser"

    def get_supported_extensions(self) -> List[str]:
        return ['.xml', '.evtx']

    def parse_file(self, filepath: Path) -> List[AuthEvent]:
        """
        Parse a Windows event log XML file and return a list of AuthEvents.
        The root element is <Events> containing multiple <Event> children.
        """
        events = []
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            for event_elem in root.findall('.//Event'):
                try:
                    event = self._parse_event(event_elem)
                    if event:
                        events.append(event)
                except Exception as e:
                    print(f"Warning: Could not parse event: {e}")

        except ET.ParseError as e:
            raise ParseError(f"Invalid XML: {e}")

        return events

    def parse_line(self, line: str) -> Optional[AuthEvent]:
        """
        Parse a single XML event string into an AuthEvent.
        Used for compatibility with the BaseParser interface.
        """
        try:
            event_elem = ET.fromstring(line)
            return self._parse_event(event_elem)
        except ET.ParseError:
            return None

    def _parse_event(self, event_elem: ET.Element) -> Optional[AuthEvent]:
        """
        Parse a single <Event> XML element into an AuthEvent.
        Returns None for event IDs we don't care about.
        """
        system_data = self._extract_system_data(event_elem)
        if not system_data:
            return None

        event_id = system_data.get('event_id')
        if event_id not in ('4624', '4625', '4634', '4647', '4672'):
            return None

        event_data = self._extract_event_data(event_elem)

        if event_id == '4624':
            return self._create_logon_success_event(system_data, event_data)
        elif event_id == '4625':
            return self._create_logon_failure_event(system_data, event_data)
        elif event_id in ('4634', '4647'):
            return self._create_logoff_event(system_data, event_data)
        elif event_id == '4672':
            return self._create_special_privileges_event(system_data, event_data)

        return None

    def _extract_system_data(self, event_elem: ET.Element) -> Optional[Dict[str, str]]:
        """
        Extract metadata from the <s> (System) section of an event.
        Returns a dict with event_id, timestamp, and computer name.

        Note: The sample file uses <s> as a shorthand for <System>.
        We check for both to be safe.
        """
        # Try <s> first (as used in the sample), then standard <System>
        system = event_elem.find('s')
        if system is None:
            system = event_elem.find('System')
        if system is None:
            system = event_elem.find('evt:System', self._namespace)
        if system is None:
            return None

        result = {}

        event_id_elem = system.find('EventID')
        if event_id_elem is not None:
            result['event_id'] = event_id_elem.text

        time_elem = system.find('TimeCreated')
        if time_elem is not None:
            result['timestamp'] = time_elem.get('SystemTime')

        computer_elem = system.find('Computer')
        if computer_elem is not None:
            result['computer'] = computer_elem.text

        provider_elem = system.find('Provider')
        if provider_elem is not None:
            result['provider'] = provider_elem.get('Name', '')

        return result if 'event_id' in result else None

    def _extract_event_data(self, event_elem: ET.Element) -> Dict[str, str]:
        """
        Extract fields from the <EventData> section.
        Converts <Data Name="FieldName">Value</Data> elements into a dict.
        Returns an empty dict if EventData is missing.
        """
        result = {}

        event_data = event_elem.find('EventData')
        if event_data is None:
            return result

        for data_elem in event_data.findall('Data'):
            name = data_elem.get('Name')
            value = data_elem.text
            if name and value and value != '-':
                result[name] = value

        return result

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        if not timestamp_str:
            return None
        try:
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1]  # Just remove the Z, don't add +00:00
            return datetime.fromisoformat(timestamp_str)
        except ValueError:
            return None

    def _get_logon_type(self, event_data: Dict) -> Optional[LogonType]:
        """Map the LogonType number string to a LogonType enum value."""
        logon_type_str = event_data.get('LogonType')
        if logon_type_str:
            return self.LOGON_TYPE_MAP.get(logon_type_str)
        return None

    def _get_failure_reason(self, status: str, substatus: str) -> str:
        """Convert Windows status/substatus hex codes to a readable failure reason."""
        # SubStatus is more specific than Status — check it first
        if substatus and substatus in self.SUBSTATUS_REASONS:
            return self.SUBSTATUS_REASONS[substatus]
        if status and status in self.SUBSTATUS_REASONS:
            return self.SUBSTATUS_REASONS[status]
        return 'Unknown failure'

    def _clean_value(self, value: Optional[str]) -> Optional[str]:
        """Return None for missing/placeholder values like '-' or empty strings."""
        if not value or value.strip() in ('-', ''):
            return None
        return value.strip()

    def _create_logon_success_event(self, system_data: Dict, event_data: Dict) -> AuthEvent:
        """
        Create an AuthEvent for a successful Windows logon (Event ID 4624).
        Uses TargetUserName/TargetDomainName as the authenticated user.
        """
        return AuthEvent(
            timestamp=self._parse_timestamp(system_data.get('timestamp')),
            event_type=EventType.LOGON_SUCCESS,
            source_type=SourceType.WINDOWS_SECURITY,
            username=event_data.get('TargetUserName', 'unknown'),
            domain=self._clean_value(event_data.get('TargetDomainName')),
            source_ip=self._clean_value(event_data.get('IpAddress')),
            source_hostname=self._clean_value(event_data.get('WorkstationName')),
            target_hostname=system_data.get('computer'),
            logon_type=self._get_logon_type(event_data),
            auth_method=self._clean_value(event_data.get('AuthenticationPackageName')),
            success=True,
            raw_event_id='4624',
        )

    def _create_logon_failure_event(self, system_data: Dict, event_data: Dict) -> AuthEvent:
        """
        Create an AuthEvent for a failed Windows logon (Event ID 4625).
        Includes failure reason derived from Status/SubStatus codes.
        """
        status = event_data.get('Status', '')
        substatus = event_data.get('SubStatus', '')
        failure_reason = self._get_failure_reason(status, substatus)

        # Flag non-existent users for enumeration detection
        tags = []
        if substatus == '0xC0000064':
            tags.append('invalid_user')

        return AuthEvent(
            timestamp=self._parse_timestamp(system_data.get('timestamp')),
            event_type=EventType.LOGON_FAILURE,
            source_type=SourceType.WINDOWS_SECURITY,
            username=event_data.get('TargetUserName', 'unknown'),
            domain=self._clean_value(event_data.get('TargetDomainName')),
            source_ip=self._clean_value(event_data.get('IpAddress')),
            source_hostname=self._clean_value(event_data.get('WorkstationName')),
            target_hostname=system_data.get('computer'),
            logon_type=self._get_logon_type(event_data),
            auth_method=self._clean_value(event_data.get('AuthenticationPackageName')),
            failure_reason=failure_reason,
            success=False,
            raw_event_id='4625',
            tags=tags,
        )

    def _create_logoff_event(self, system_data: Dict, event_data: Dict) -> AuthEvent:
        """
        Create an AuthEvent for a Windows logoff (Event ID 4634 or 4647).
        """
        return AuthEvent(
            timestamp=self._parse_timestamp(system_data.get('timestamp')),
            event_type=EventType.USER_LOGOFF,
            source_type=SourceType.WINDOWS_SECURITY,
            username=event_data.get('TargetUserName', 'unknown'),
            domain=self._clean_value(event_data.get('TargetDomainName')),
            target_hostname=system_data.get('computer'),
            logon_type=self._get_logon_type(event_data),
            success=True,
            raw_event_id=system_data.get('event_id'),
        )

    def _create_special_privileges_event(self, system_data: Dict, event_data: Dict) -> AuthEvent:
        """
        Create an AuthEvent for special privileges assigned (Event ID 4672).
        This indicates a highly privileged logon — Domain Admin, local admin, etc.
        The privileges list is stored in tags for downstream analysis.
        """
        privileges = self._clean_value(event_data.get('PrivilegeList'))
        tags = ['special_privileges']
        if privileges:
            tags.append(f'privileges:{privileges}')

        return AuthEvent(
            timestamp=self._parse_timestamp(system_data.get('timestamp')),
            event_type=EventType.SPECIAL_PRIV,
            source_type=SourceType.WINDOWS_SECURITY,
            username=event_data.get('SubjectUserName', 'unknown'),
            domain=self._clean_value(event_data.get('SubjectDomainName')),
            target_hostname=system_data.get('computer'),
            success=True,
            raw_event_id='4672',
            tags=tags,
        )
