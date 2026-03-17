"""
Anomaly Detection Analyzer

This module detects anomalous authentication patterns.

YOUR TASK: Implement detection for:
1. Off-hours activity
2. New/unusual source IPs for users
3. Impossible travel
4. Unusual logon types
"""

from datetime import datetime, timedelta, time
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict

# Uncomment once you implement events.py:
# from src.models.events import AuthEvent, DetectionAlert, EventType


class AnomalyAnalyzer:
    """
    Detects anomalous authentication patterns.
    
    This analyzer looks for deviations from normal behavior:
    - Logins at unusual times
    - Logins from new/unknown locations
    - Impossible travel scenarios
    - Unusual authentication methods
    """
    
    # Default configuration
    DEFAULT_CONFIG = {
        # Business hours (24-hour format)
        'business_hours_start': 7,   # 7 AM
        'business_hours_end': 19,    # 7 PM
        'business_days': [0, 1, 2, 3, 4],  # Monday=0 through Friday=4
        
        # Impossible travel
        'impossible_travel_minutes': 60,  # Min time for "impossible" travel
    }
    
    def __init__(self, config: Dict = None, baseline_events: List['AuthEvent'] = None):
        """
        Initialize the analyzer.
        
        TODO: Set up configuration and optional baseline
        
        Args:
            config: Optional dict to override DEFAULT_CONFIG
            baseline_events: Optional list of events to establish "normal" behavior
        """
        
        self.config = {**self.DEFAULT_CONFIG}
        if config:
            self.config.update(config)
        
        # Baseline data structures
        # These track "normal" behavior patterns
        
        # TODO: Initialize baseline tracking
        #
        # self._user_source_ips: Dict[str, Set[str]] = defaultdict(set)  # user -> set of known IPs
        # self._user_login_hours: Dict[str, List[int]] = defaultdict(list)  # user -> list of hours
        # self._user_logon_types: Dict[str, Set[str]] = defaultdict(set)  # user -> set of logon types
        
        # Build baseline if provided
        if baseline_events:
            self._build_baseline(baseline_events)
    
    def _build_baseline(self, events: List['AuthEvent']) -> None:
        """
        Build a baseline of normal behavior from historical events.
        
        TODO: Implement this method
        
        This should populate:
        - Known IPs for each user
        - Normal login hours for each user
        - Normal logon types for each user
        
        HINT: Only use successful logins for baseline
        """
        
        # TODO: Implement
        #
        # for event in events:
        #     if event.event_type == EventType.LOGON_SUCCESS:
        #         # Track known IPs
        #         if event.source_ip:
        #             self._user_source_ips[event.username].add(event.source_ip)
        #         
        #         # Track login hours
        #         self._user_login_hours[event.username].append(event.timestamp.hour)
        #         
        #         # Track logon types
        #         if event.logon_type:
        #             self._user_logon_types[event.username].add(event.logon_type)
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def analyze(self, events: List['AuthEvent']) -> List['DetectionAlert']:
        """
        Analyze events for anomalies.
        
        TODO: Implement this method
        
        Run all anomaly detections and return combined alerts.
        """
        
        # TODO: Implement
        #
        # alerts = []
        # 
        # alerts.extend(self.detect_off_hours_activity(events))
        # alerts.extend(self.detect_new_source_ip(events))
        # alerts.extend(self.detect_impossible_travel(events))
        # alerts.extend(self.detect_unusual_logon_type(events))
        # 
        # return alerts
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def detect_off_hours_activity(self, events: List['AuthEvent']) -> List['DetectionAlert']:
        """
        Detect logins outside of business hours.
        
        TODO: Implement this method
        
        Off-hours defined as:
        - Before business_hours_start or after business_hours_end
        - On weekends (Saturday=5, Sunday=6)
        
        Algorithm:
        1. Filter to successful logins
        2. For each login, check if timestamp is outside business hours
        3. Create alert for off-hours logins
        
        CONSIDERATIONS:
        - Some users legitimately work off-hours (on-call, etc.)
        - Severity might depend on the user or logon type
        - 3 AM RDP login is more suspicious than 8 PM local login
        """
        
        # TODO: Implement
        #
        # alerts = []
        # 
        # start_hour = self.config['business_hours_start']
        # end_hour = self.config['business_hours_end']
        # business_days = self.config['business_days']
        # 
        # for event in events:
        #     if event.event_type != EventType.LOGON_SUCCESS:
        #         continue
        #     
        #     is_off_hours = self._is_off_hours(
        #         event.timestamp, 
        #         start_hour, 
        #         end_hour, 
        #         business_days
        #     )
        #     
        #     if is_off_hours:
        #         alert = self._create_off_hours_alert(event)
        #         alerts.append(alert)
        # 
        # return alerts
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _is_off_hours(
        self, 
        timestamp: datetime, 
        start_hour: int, 
        end_hour: int, 
        business_days: List[int]
    ) -> bool:
        """
        Check if a timestamp is outside business hours.
        
        TODO: Implement this method
        
        Args:
            timestamp: The datetime to check
            start_hour: Business hours start (e.g., 7 for 7 AM)
            end_hour: Business hours end (e.g., 19 for 7 PM)
            business_days: List of weekday numbers (0=Monday)
            
        Returns:
            True if outside business hours, False otherwise
        """
        
        # TODO: Implement
        #
        # # Check day of week
        # if timestamp.weekday() not in business_days:
        #     return True
        # 
        # # Check hour
        # if timestamp.hour < start_hour or timestamp.hour >= end_hour:
        #     return True
        # 
        # return False
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def detect_new_source_ip(self, events: List['AuthEvent']) -> List['DetectionAlert']:
        """
        Detect logins from IPs not previously seen for a user.
        
        TODO: Implement this method
        
        This requires baseline data. If no baseline, this detection won't work.
        
        Algorithm:
        1. For each successful login
        2. Check if source IP is in baseline for that user
        3. If not, create alert
        
        CONSIDERATIONS:
        - First time users will have no baseline (handle gracefully)
        - VPN/NAT might cause same user to appear from different IPs
        - Internal IPs (10.x, 192.168.x) might be less concerning than external
        """
        
        # TODO: Implement
        #
        # alerts = []
        # 
        # for event in events:
        #     if event.event_type != EventType.LOGON_SUCCESS:
        #         continue
        #     
        #     if not event.source_ip or not event.username:
        #         continue
        #     
        #     known_ips = self._user_source_ips.get(event.username, set())
        #     
        #     # Skip if no baseline for this user
        #     if not known_ips:
        #         continue
        #     
        #     if event.source_ip not in known_ips:
        #         alert = self._create_new_ip_alert(event, known_ips)
        #         alerts.append(alert)
        # 
        # return alerts
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def detect_impossible_travel(self, events: List['AuthEvent']) -> List['DetectionAlert']:
        """
        Detect logins from different locations that are too close in time.
        
        TODO: Implement this method (BONUS - more challenging)
        
        Algorithm:
        1. Group successful logins by user
        2. Sort by timestamp
        3. For consecutive logins, check if IPs are "far apart"
        4. If time difference is too small for travel, alert
        
        CHALLENGE: You'd need IP geolocation for real implementation.
        For this exercise, you can:
        - Treat different IPs as "different locations"
        - Or use IP ranges to guess location (192.168.x = internal, etc.)
        
        HINT: Start simple - just flag when same user logs in from
        different IPs within the impossible_travel_minutes window.
        """
        
        # TODO: Implement
        #
        # alerts = []
        # 
        # # Group events by user
        # user_events: Dict[str, List[AuthEvent]] = defaultdict(list)
        # 
        # for event in events:
        #     if event.event_type == EventType.LOGON_SUCCESS and event.username:
        #         user_events[event.username].append(event)
        # 
        # travel_minutes = self.config['impossible_travel_minutes']
        # travel_delta = timedelta(minutes=travel_minutes)
        # 
        # for username, user_login_events in user_events.items():
        #     # Sort by timestamp
        #     sorted_events = sorted(user_login_events, key=lambda e: e.timestamp)
        #     
        #     # Check consecutive logins
        #     for i in range(1, len(sorted_events)):
        #         prev = sorted_events[i-1]
        #         curr = sorted_events[i]
        #         
        #         # Different IPs?
        #         if prev.source_ip != curr.source_ip:
        #             # Within impossible travel window?
        #             if (curr.timestamp - prev.timestamp) < travel_delta:
        #                 alert = self._create_impossible_travel_alert(prev, curr)
        #                 alerts.append(alert)
        # 
        # return alerts
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def detect_unusual_logon_type(self, events: List['AuthEvent']) -> List['DetectionAlert']:
        """
        Detect unusual logon types for a user.
        
        TODO: Implement this method
        
        Examples of unusual:
        - User normally does interactive login, suddenly does RDP
        - Service account suddenly logs in interactively
        - Network logon (type 3) to workstation (lateral movement?)
        
        This requires baseline data.
        """
        
        # TODO: Implement
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _create_off_hours_alert(self, event: 'AuthEvent') -> 'DetectionAlert':
        """
        Create alert for off-hours activity.
        
        TODO: Implement this method
        """
        
        # TODO: Implement
        #
        # # Determine severity based on how far off-hours
        # hour = event.timestamp.hour
        # if 0 <= hour <= 5:  # Middle of night
        #     severity = "high"
        # elif event.timestamp.weekday() >= 5:  # Weekend
        #     severity = "medium"
        # else:  # Just outside business hours
        #     severity = "low"
        # 
        # return DetectionAlert(
        #     alert_id=f"OOH-{event.username}-{event.timestamp.isoformat()}",
        #     detection_name="Off-Hours Activity",
        #     severity=severity,
        #     related_events=[event],
        #     mitre_technique="T1078",  # Valid Accounts
        #     description=f"User '{event.username}' logged in at {event.timestamp.strftime('%H:%M')} "
        #                 f"on {event.timestamp.strftime('%A')} from {event.source_ip}",
        #     timestamp=event.timestamp,
        # )
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _create_new_ip_alert(self, event: 'AuthEvent', known_ips: Set[str]) -> 'DetectionAlert':
        """
        Create alert for login from new IP.
        
        TODO: Implement this method
        """
        
        # TODO: Implement
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _create_impossible_travel_alert(
        self, 
        event1: 'AuthEvent', 
        event2: 'AuthEvent'
    ) -> 'DetectionAlert':
        """
        Create alert for impossible travel.
        
        TODO: Implement this method
        """
        
        # TODO: Implement
        
        pass  # DELETE THIS AND IMPLEMENT


# =============================================================================
# TESTING YOUR IMPLEMENTATION
# =============================================================================
#
# The sample data includes off-hours activity (3 AM login).
# Test with:
#
# ```python
# from src.parsers.linux_parser import LinuxAuthParser
# from src.analyzers.anomaly import AnomalyAnalyzer
# from pathlib import Path
#
# parser = LinuxAuthParser()
# events = parser.parse_file(Path("sample-data/auth.log"))
#
# # First batch as baseline, analyze later events
# baseline = [e for e in events if e.timestamp.day == 15 and e.timestamp.hour < 14]
# to_analyze = [e for e in events if e not in baseline]
#
# analyzer = AnomalyAnalyzer(baseline_events=baseline)
# alerts = analyzer.analyze(to_analyze)
#
# for alert in alerts:
#     print(f"[{alert.severity}] {alert.detection_name}: {alert.description}")
# ```
#
# Expected: Should detect the 3 AM activity
#
# =============================================================================
