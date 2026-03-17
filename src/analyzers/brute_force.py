"""
Brute Force Detection Analyzer

This module detects brute force and password spray attacks.

YOUR TASK: Implement detection algorithms for:
1. Brute force attacks (many failures to same account)
2. Password spray attacks (failures across many accounts)
3. Credential stuffing (mixed success/failure patterns)
"""

from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

# Uncomment once you implement events.py:
# from src.models.events import AuthEvent, DetectionAlert, EventType


class BruteForceAnalyzer:
    """
    Detects brute force and related credential attacks.
    
    Detection Types:
    1. Brute Force: Many failed attempts to ONE account from ONE source
    2. Distributed Brute Force: Many failed attempts to ONE account from MANY sources
    3. Password Spray: ONE failed attempt to MANY accounts from ONE source
    4. Credential Stuffing: Mix of success/failure across many accounts
    """
    
    # Default detection thresholds
    DEFAULT_THRESHOLDS = {
        'brute_force_failures': 5,      # Failures before alerting
        'brute_force_window_minutes': 5, # Time window for brute force
        'password_spray_accounts': 5,    # Unique accounts for spray detection
        'password_spray_window_minutes': 10,
    }
    
    def __init__(self, thresholds: Dict[str, int] = None):
        """
        Initialize the analyzer with detection thresholds.
        
        TODO: Store thresholds and set up any tracking structures
        
        Args:
            thresholds: Optional dict to override DEFAULT_THRESHOLDS
        """
        
        # Merge provided thresholds with defaults
        self.thresholds = {**self.DEFAULT_THRESHOLDS}
        if thresholds:
            self.thresholds.update(thresholds)
        
        # TODO: Initialize any data structures for tracking
        # 
        # Consider:
        # - Dict to track failures by (source_ip, target_user) tuple
        # - Dict to track failures by source_ip (for spray detection)
        # - List to store generated alerts
        
        pass  # You can keep or remove this
    
    def analyze(self, events: List['AuthEvent']) -> List['DetectionAlert']:
        """
        Analyze a list of events for brute force patterns.
        
        TODO: Implement this method
        
        This is the main entry point. It should:
        1. Sort events by timestamp
        2. Filter to only failed authentication events
        3. Run each detection algorithm
        4. Return combined list of alerts
        
        Args:
            events: List of AuthEvent objects (mix of success/failure)
            
        Returns:
            List of DetectionAlert objects for detected attacks
        """
        
        # TODO: Implement
        #
        # alerts = []
        # 
        # # Sort events by time
        # sorted_events = sorted(events, key=lambda e: e.timestamp)
        # 
        # # Run detections
        # alerts.extend(self.detect_brute_force(sorted_events))
        # alerts.extend(self.detect_password_spray(sorted_events))
        # alerts.extend(self.detect_credential_stuffing(sorted_events))
        # 
        # return alerts
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def detect_brute_force(self, events: List['AuthEvent']) -> List['DetectionAlert']:
        """
        Detect classic brute force attacks.
        
        Pattern: Many failed logins to SAME account from SAME source in short time
        
        TODO: Implement this method
        
        Algorithm:
        1. Group failed events by (source_ip, target_username)
        2. For each group, use sliding window to find clusters
        3. If cluster exceeds threshold, create alert
        
        HINT: Use a sliding window approach
        
        ```
        For each (ip, user) pair:
            failures_in_window = []
            for event in sorted_events:
                # Remove events outside the window
                while failures_in_window and (event.time - failures_in_window[0].time > window):
                    failures_in_window.pop(0)
                
                # Add current event
                failures_in_window.append(event)
                
                # Check threshold
                if len(failures_in_window) >= threshold:
                    create_alert()
        ```
        """
        
        # TODO: Implement
        #
        # alerts = []
        # 
        # # Group failures by (source_ip, username)
        # failures_by_target: Dict[Tuple[str, str], List[AuthEvent]] = defaultdict(list)
        # 
        # for event in events:
        #     if event.event_type == EventType.LOGON_FAILURE:
        #         key = (event.source_ip, event.username)
        #         failures_by_target[key].append(event)
        # 
        # # Analyze each group
        # for (source_ip, username), failure_events in failures_by_target.items():
        #     alert = self._check_brute_force_window(source_ip, username, failure_events)
        #     if alert:
        #         alerts.append(alert)
        # 
        # return alerts
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _check_brute_force_window(
        self, 
        source_ip: str, 
        username: str, 
        failures: List['AuthEvent']
    ) -> Optional['DetectionAlert']:
        """
        Check if failures exceed threshold within time window.
        
        TODO: Implement this method
        
        Use sliding window to find the maximum number of failures
        within the configured time window.
        """
        
        # TODO: Implement
        #
        # window_minutes = self.thresholds['brute_force_window_minutes']
        # threshold = self.thresholds['brute_force_failures']
        # 
        # # Sort by timestamp
        # sorted_failures = sorted(failures, key=lambda e: e.timestamp)
        # 
        # # Sliding window
        # window_start = 0
        # max_in_window = 0
        # events_at_max = []
        # 
        # for i, event in enumerate(sorted_failures):
        #     # Move window start forward
        #     window_delta = timedelta(minutes=window_minutes)
        #     while window_start < i and (event.timestamp - sorted_failures[window_start].timestamp) > window_delta:
        #         window_start += 1
        #     
        #     # Count events in window
        #     in_window = i - window_start + 1
        #     if in_window > max_in_window:
        #         max_in_window = in_window
        #         events_at_max = sorted_failures[window_start:i+1]
        # 
        # if max_in_window >= threshold:
        #     return self._create_brute_force_alert(source_ip, username, events_at_max)
        # 
        # return None
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def detect_password_spray(self, events: List['AuthEvent']) -> List['DetectionAlert']:
        """
        Detect password spray attacks.
        
        Pattern: Failed logins to MANY accounts from SAME source (trying same password)
        
        TODO: Implement this method
        
        Algorithm:
        1. Group failed events by source_ip
        2. For each source, count unique target usernames in time window
        3. If unique targets exceed threshold, create alert
        
        Key difference from brute force:
        - Brute force: many attempts to ONE account
        - Password spray: few attempts to MANY accounts
        """
        
        # TODO: Implement
        #
        # alerts = []
        # 
        # # Group failures by source IP
        # failures_by_source: Dict[str, List[AuthEvent]] = defaultdict(list)
        # 
        # for event in events:
        #     if event.event_type == EventType.LOGON_FAILURE and event.source_ip:
        #         failures_by_source[event.source_ip].append(event)
        # 
        # # Analyze each source
        # for source_ip, failure_events in failures_by_source.items():
        #     alert = self._check_password_spray_window(source_ip, failure_events)
        #     if alert:
        #         alerts.append(alert)
        # 
        # return alerts
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _check_password_spray_window(
        self,
        source_ip: str,
        failures: List['AuthEvent']
    ) -> Optional['DetectionAlert']:
        """
        Check if a source IP is targeting many unique accounts.
        
        TODO: Implement this method
        """
        
        # TODO: Implement
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def detect_credential_stuffing(self, events: List['AuthEvent']) -> List['DetectionAlert']:
        """
        Detect credential stuffing attacks.
        
        Pattern: Mix of successes and failures from same source, hitting many accounts
        This suggests attacker is using leaked credential lists
        
        TODO: Implement this method (BONUS - more challenging)
        
        Indicators:
        - Many unique accounts accessed from one source
        - Mix of success and failure (some leaked creds work)
        - Rapid succession of attempts
        - Unusual source IP
        """
        
        # TODO: Implement (this one is harder - save for later if needed)
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _create_brute_force_alert(
        self,
        source_ip: str,
        username: str,
        events: List['AuthEvent']
    ) -> 'DetectionAlert':
        """
        Create a DetectionAlert for a brute force attack.
        
        TODO: Implement this method
        
        Should include:
        - Alert ID (generate a unique ID)
        - Detection name: "Brute Force Attack"
        - Severity: Based on number of attempts
        - Related events: The events that triggered the alert
        - MITRE technique: T1110.001
        - Description: Human-readable summary
        """
        
        # TODO: Implement
        #
        # severity = self._calculate_severity(len(events))
        # 
        # return DetectionAlert(
        #     alert_id=f"BF-{source_ip}-{username}-{events[0].timestamp.isoformat()}",
        #     detection_name="Brute Force Attack",
        #     severity=severity,
        #     related_events=events,
        #     mitre_technique="T1110.001",
        #     description=f"Detected {len(events)} failed login attempts to account '{username}' from {source_ip}",
        #     timestamp=events[-1].timestamp,  # Time of last event
        # )
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _create_password_spray_alert(
        self,
        source_ip: str,
        usernames: List[str],
        events: List['AuthEvent']
    ) -> 'DetectionAlert':
        """
        Create a DetectionAlert for a password spray attack.
        
        TODO: Implement this method
        
        MITRE technique: T1110.003
        """
        
        # TODO: Implement
        
        pass  # DELETE THIS AND IMPLEMENT
    
    def _calculate_severity(self, event_count: int) -> str:
        """
        Calculate alert severity based on event count.
        
        TODO: Implement this method
        
        Suggested mapping:
        - 5-10 events: "low"
        - 11-25 events: "medium"
        - 26-50 events: "high"
        - 50+ events: "critical"
        """
        
        # TODO: Implement
        #
        # if event_count >= 50:
        #     return "critical"
        # elif event_count >= 26:
        #     return "high"
        # elif event_count >= 11:
        #     return "medium"
        # else:
        #     return "low"
        
        pass  # DELETE THIS AND IMPLEMENT


# =============================================================================
# TESTING YOUR IMPLEMENTATION
# =============================================================================
#
# Test with the sample data which includes brute force and spray patterns:
#
# ```python
# from src.parsers.linux_parser import LinuxAuthParser
# from src.analyzers.brute_force import BruteForceAnalyzer
# from pathlib import Path
#
# # Parse events
# parser = LinuxAuthParser()
# events = parser.parse_file(Path("sample-data/auth.log"))
#
# # Analyze for attacks
# analyzer = BruteForceAnalyzer()
# alerts = analyzer.analyze(events)
#
# for alert in alerts:
#     print(f"[{alert.severity}] {alert.detection_name}: {alert.description}")
# ```
#
# Expected: Should detect the brute force attack from 203.0.113.50
#
# =============================================================================
