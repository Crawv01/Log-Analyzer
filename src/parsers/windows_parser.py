"""
Windows Security Event Log Parser

This module parses Windows Security Event Logs in XML format.

YOUR TASK: Implement the WindowsEventParser class to parse Windows XML logs.

HINTS:
1. Study the sample windows_security_events.xml file
2. Use Python's xml.etree.ElementTree for XML parsing
3. Focus on Event IDs: 4624, 4625, 4634, 4672
4. Pay attention to the LogonType field - it's crucial for analysis
"""

import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict

from .base_parser import BaseParser, ParseError

# Uncomment once you implement events.py:
# from src.models.events import AuthEvent, EventType, SourceType, LogonType


class WindowsEventParser(BaseParser):
    """
    Parser for Windows Security Event Logs in XML format.
    
    Handles Event IDs:
    - 4624: Successful logon
    - 4625: Failed logon
    - 4634: Logoff
    - 4647: User-initiated logoff
    - 4672: Special privileges assigned
    """
    
    # Mapping of Windows logon type numbers to names
    # Reference: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
    LOGON_TYPE_MAP = {
        '2': 'interactive',
        '3': 'network',
        '4': 'batch',
        '5': 'service',
        '7': 'unlock',
        '8': 'network_cleartext',
        '9': 'new_credentials',
        '10': 'remote_interactive',
        '11': 'cached_interactive',
    }
    
    # Mapping of Event IDs to event types
    EVENT_ID_MAP = {
        '4624': 'logon_success',
        '4625': 'logon_failure',
        '4634': 'logoff',
        '4647': 'logoff',
        '4672': 'privilege_escalation',
    }
    
    def __init__(self):
        """
        Initialize the parser.
        
        TODO: Set up any instance variables you need.
        
        Consider:
        - XML namespace handling (Windows logs use namespaces)
        - Caching for repeated lookups
        """
        
        # XML namespace used in Windows event logs
        # You'll need this when querying with ElementTree
        self._namespace = {
            'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'
        }
        
        # TODO: Add any additional initialization
        
        pass  # You can keep or remove this
    
    @property
    def parser_name(self) -> str:
        return "Windows Security Event Parser"
    
    def get_supported_extensions(self) -> List[str]:
        return ['.xml', '.evtx']  # Note: .evtx needs special handling (binary format)
    
    def parse_file(self, filepath: Path) -> List['AuthEvent']:
        """
        Parse a Windows event log XML file.
        
        TODO: Implement this method
        
        Steps:
        1. Load and parse the XML file
        2. Find all <Event> elements
        3. For each event, call _parse_event()
        4. Collect and return results
        
        HINT: The sample file has <Events> as root with multiple <Event> children
        """
        
        # TODO: Implement
        #
        # events = []
        # try:
        #     tree = ET.parse(filepath)
        #     root = tree.getroot()
        #     
        #     # Find all Event elements
        #     for event_elem in root.findall('.//Event'):  # or 'evt:Event' with namespace
        #         event = self._parse_event(event_elem)
        #         if event:
        #             events.append(event)
        # except ET.ParseError as e:
        #     raise ParseError(f"Invalid XML: {e}")
        # 
        # return events
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def parse_line(self, line: str) -> Optional['AuthEvent']:
        """
        Parse a single XML event (as a string).
        
        This is less commonly used for Windows logs, but implement for
        compatibility with the base class interface.
        
        TODO: Implement this method
        """
        
        # TODO: Implement
        #
        # try:
        #     event_elem = ET.fromstring(line)
        #     return self._parse_event(event_elem)
        # except ET.ParseError:
        #     return None
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _parse_event(self, event_elem: ET.Element) -> Optional['AuthEvent']:
        """
        Parse a single XML Event element into an AuthEvent.
        
        TODO: Implement this method
        
        Steps:
        1. Extract the EventID from <s><EventID>
        2. Check if it's an Event ID we care about (4624, 4625, etc.)
        3. If not, return None
        4. Extract timestamp from <TimeCreated SystemTime="...">
        5. Extract computer name from <Computer>
        6. Extract event data from <EventData><Data Name="...">
        7. Create and return an AuthEvent
        
        HINT: Use helper methods for extracting system and event data
        """
        
        # TODO: Implement
        #
        # # Get System section data
        # system_data = self._extract_system_data(event_elem)
        # if not system_data:
        #     return None
        # 
        # event_id = system_data.get('event_id')
        # if event_id not in self.EVENT_ID_MAP:
        #     return None  # Not an event we care about
        # 
        # # Get EventData section
        # event_data = self._extract_event_data(event_elem)
        # 
        # # Create the appropriate event based on Event ID
        # if event_id == '4624':
        #     return self._create_logon_success_event(system_data, event_data)
        # elif event_id == '4625':
        #     return self._create_logon_failure_event(system_data, event_data)
        # # ... handle other event IDs
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _extract_system_data(self, event_elem: ET.Element) -> Optional[Dict[str, str]]:
        """
        Extract data from the <s> section of an event.
        
        TODO: Implement this method
        
        Should extract:
        - event_id: The Event ID (4624, 4625, etc.)
        - timestamp: The SystemTime attribute
        - computer: The Computer element text
        - provider: The Provider Name attribute
        
        Returns:
            Dictionary with extracted values, or None if required fields missing
        """
        
        # TODO: Implement
        #
        # try:
        #     system = event_elem.find('s') or event_elem.find('evt:System', self._namespace)
        #     if system is None:
        #         return None
        #     
        #     result = {}
        #     
        #     # Event ID
        #     event_id_elem = system.find('EventID') or system.find('evt:EventID', self._namespace)
        #     if event_id_elem is not None:
        #         result['event_id'] = event_id_elem.text
        #     
        #     # Timestamp
        #     time_elem = system.find('TimeCreated') or system.find('evt:TimeCreated', self._namespace)
        #     if time_elem is not None:
        #         result['timestamp'] = time_elem.get('SystemTime')
        #     
        #     # Computer
        #     computer_elem = system.find('Computer') or system.find('evt:Computer', self._namespace)
        #     if computer_elem is not None:
        #         result['computer'] = computer_elem.text
        #     
        #     return result
        # except Exception:
        #     return None
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _extract_event_data(self, event_elem: ET.Element) -> Dict[str, str]:
        """
        Extract data from the <EventData> section of an event.
        
        TODO: Implement this method
        
        The EventData section contains <Data Name="FieldName">Value</Data> elements.
        Convert these to a dictionary: {"FieldName": "Value", ...}
        
        Important fields to extract:
        - TargetUserName: The user being logged in
        - TargetDomainName: The domain
        - LogonType: Type of logon (2, 3, 10, etc.)
        - IpAddress: Source IP
        - WorkstationName: Source hostname
        - Status/SubStatus: Failure reason codes (for 4625)
        
        Returns:
            Dictionary mapping field names to values
        """
        
        # TODO: Implement
        #
        # result = {}
        # 
        # event_data = event_elem.find('EventData') or event_elem.find('evt:EventData', self._namespace)
        # if event_data is None:
        #     return result
        # 
        # for data_elem in event_data.findall('Data') or event_data.findall('evt:Data', self._namespace):
        #     name = data_elem.get('Name')
        #     value = data_elem.text
        #     if name and value:
        #         result[name] = value
        # 
        # return result
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """
        Parse a Windows timestamp string to datetime.
        
        TODO: Implement this method
        
        Windows uses ISO 8601 format: "2024-01-15T14:32:18.123456Z"
        
        HINT: datetime.fromisoformat() works, but you may need to handle
        the 'Z' suffix (replace with +00:00 or use a different approach)
        """
        
        # TODO: Implement
        #
        # try:
        #     # Handle 'Z' suffix
        #     if timestamp_str.endswith('Z'):
        #         timestamp_str = timestamp_str[:-1] + '+00:00'
        #     return datetime.fromisoformat(timestamp_str)
        # except ValueError:
        #     return None
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _create_logon_success_event(self, system_data: Dict, event_data: Dict) -> 'AuthEvent':
        """
        Create an AuthEvent for a successful logon (Event ID 4624).
        
        TODO: Implement this method
        
        Extract and map:
        - Username from TargetUserName
        - Domain from TargetDomainName
        - Logon type from LogonType (use LOGON_TYPE_MAP)
        - Source IP from IpAddress
        - Source hostname from WorkstationName
        
        HINT: Some fields may be '-' which means not applicable
        """
        
        # TODO: Implement
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _create_logon_failure_event(self, system_data: Dict, event_data: Dict) -> 'AuthEvent':
        """
        Create an AuthEvent for a failed logon (Event ID 4625).
        
        TODO: Implement this method
        
        Similar to success, but also include:
        - Failure reason from Status/SubStatus codes
        
        Common SubStatus codes:
        - 0xC000006A: Wrong password
        - 0xC0000064: User doesn't exist
        - 0xC0000072: Account disabled
        - 0xC0000234: Account locked out
        """
        
        # TODO: Implement
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _get_failure_reason(self, status: str, substatus: str) -> str:
        """
        Convert Windows status codes to human-readable failure reasons.
        
        TODO: Implement this method
        
        Map common status/substatus codes to descriptions.
        """
        
        # Status code to reason mapping
        substatus_reasons = {
            '0xC000006A': 'Bad password',
            '0xC0000064': 'User does not exist',
            '0xC0000072': 'Account disabled',
            '0xC0000234': 'Account locked out',
            '0xC0000071': 'Password expired',
            '0xC0000070': 'Workstation restriction',
            '0xC000006D': 'Logon failure',
            '0xC000006F': 'Time restriction',
        }
        
        # TODO: Implement lookup logic
        #
        # return substatus_reasons.get(substatus, 
        #        substatus_reasons.get(status, 'Unknown'))
        
        pass  # DELETE THIS AND IMPLEMENT


# =============================================================================
# TESTING YOUR IMPLEMENTATION
# =============================================================================
#
# Once implemented, test with:
#
# ```python
# from src.parsers.windows_parser import WindowsEventParser
# from pathlib import Path
#
# parser = WindowsEventParser()
# events = parser.parse_file(Path("sample-data/windows_security_events.xml"))
#
# for event in events:
#     print(f"{event.timestamp} - {event.event_type} - {event.username} ({event.logon_type})")
# ```
#
# You should see:
# - Successful logins with different logon types
# - Failed logins (the brute force attempts)
# - Privilege escalation events
#
# =============================================================================
