"""
Anomaly Detection Analyzer

Detects anomalous authentication patterns including off-hours activity,
logins from new source IPs, and impossible travel scenarios.
Maps primarily to MITRE ATT&CK T1078 (Valid Accounts).
"""

from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional
from collections import defaultdict

from src.models.events import AuthEvent, DetectionAlert, EventType


class AnomalyAnalyzer:
    """
    Detects anomalous authentication patterns by comparing events
    against configured business hours and optional baseline behavior.

    Detection Types:
    1. Off-hours activity — logins outside business hours or on weekends
    2. New source IP — login from an IP not seen in baseline
    3. Impossible travel — same user logs in from different IPs too quickly
    """

    DEFAULT_CONFIG = {
        'business_hours_start': 7,          # 7 AM
        'business_hours_end': 19,           # 7 PM
        'business_days': [0, 1, 2, 3, 4],  # Monday=0 through Friday=4
        'impossible_travel_minutes': 60,    # Window for impossible travel detection
    }

    def __init__(self, config: Dict = None, baseline_events: List[AuthEvent] = None):
        """
        Initialize with optional config overrides and baseline events.
        Baseline events are used to establish what's "normal" for each user.
        """
        self.config = {**self.DEFAULT_CONFIG}
        if config:
            self.config.update(config)

        # Baseline tracking — populated from historical successful logins
        self._user_source_ips: Dict[str, Set[str]] = defaultdict(set)
        self._user_login_hours: Dict[str, List[int]] = defaultdict(list)
        self._user_logon_types: Dict[str, Set] = defaultdict(set)

        if baseline_events:
            self._build_baseline(baseline_events)

    def _build_baseline(self, events: List[AuthEvent]) -> None:
        """
        Build a baseline of normal behavior from historical successful logins.
        Only uses successful logins — failures don't represent normal behavior.
        """
        for event in events:
            if event.event_type == EventType.LOGON_SUCCESS:
                if event.source_ip:
                    self._user_source_ips[event.username].add(event.source_ip)
                if event.timestamp:
                    self._user_login_hours[event.username].append(event.timestamp.hour)
                if event.logon_type:
                    self._user_logon_types[event.username].add(event.logon_type)

    def analyze(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        """
        Run all anomaly detections and return combined alerts.
        """
        alerts = []
        alerts.extend(self.detect_off_hours_activity(events))
        alerts.extend(self.detect_new_source_ip(events))
        alerts.extend(self.detect_impossible_travel(events))
        return alerts

    def detect_off_hours_activity(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        """
        Detect successful logins outside configured business hours or on weekends.
        Severity scales with how far outside normal hours the login occurred:
        - Middle of night (midnight-5AM): high
        - Weekend: medium
        - Just outside business hours: low
        """
        alerts = []
        start_hour = self.config['business_hours_start']
        end_hour = self.config['business_hours_end']
        business_days = self.config['business_days']

        for event in events:
            if event.event_type != EventType.LOGON_SUCCESS:
                continue
            if not event.timestamp:
                continue
            if self._is_off_hours(event.timestamp, start_hour, end_hour, business_days):
                alerts.append(self._create_off_hours_alert(event))

        return alerts

    def _is_off_hours(
        self,
        timestamp: datetime,
        start_hour: int,
        end_hour: int,
        business_days: List[int]
    ) -> bool:
        """
        Return True if the timestamp falls outside business hours or on a weekend.
        weekday() returns 0 for Monday through 6 for Sunday.
        """
        if timestamp.weekday() not in business_days:
            return True
        if timestamp.hour < start_hour or timestamp.hour >= end_hour:
            return True
        return False

    def detect_new_source_ip(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        """
        Detect successful logins from IPs not seen in the baseline for that user.
        Skips users with no baseline — we can't know what's new without history.
        External IPs (not RFC1918) are flagged as higher severity.
        """
        alerts = []

        for event in events:
            if event.event_type != EventType.LOGON_SUCCESS:
                continue
            if not event.source_ip or not event.username:
                continue

            known_ips = self._user_source_ips.get(event.username, set())
            if not known_ips:
                continue  # No baseline for this user, skip

            if event.source_ip not in known_ips:
                alerts.append(self._create_new_ip_alert(event, known_ips))

        return alerts

    def detect_impossible_travel(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        """
        Detect when the same user logs in from different IPs within a short window.
        Without geolocation, we treat different IPs as potentially different locations.
        Consecutive logins from different IPs within impossible_travel_minutes trigger an alert.
        """
        alerts = []
        travel_delta = timedelta(minutes=self.config['impossible_travel_minutes'])

        # Group successful logins by user
        user_events: Dict[str, List[AuthEvent]] = defaultdict(list)
        for event in events:
            if event.event_type == EventType.LOGON_SUCCESS and event.username and event.source_ip:
                user_events[event.username].append(event)

        for username, login_events in user_events.items():
            sorted_logins = sorted(login_events, key=lambda e: e.timestamp)

            for i in range(1, len(sorted_logins)):
                prev = sorted_logins[i - 1]
                curr = sorted_logins[i]

                if prev.source_ip != curr.source_ip:
                    time_diff = curr.timestamp - prev.timestamp
                    if time_diff < travel_delta:
                        alerts.append(self._create_impossible_travel_alert(prev, curr))

        return alerts

    def _create_off_hours_alert(self, event: AuthEvent) -> DetectionAlert:
        """
        Create a DetectionAlert for off-hours login activity.
        Severity is based on how suspicious the timing is.
        """
        hour = event.timestamp.hour
        if 0 <= hour <= 5:
            severity = "high"
        elif event.timestamp.weekday() >= 5:
            severity = "medium"
        else:
            severity = "low"

        return DetectionAlert(
            alert_id=f"OOH-{event.username}-{event.timestamp.isoformat()}",
            detection_name="Off-Hours Activity",
            severity=severity,
            related_events=[event],
            mitre_technique="T1078",
            description=(
                f"User '{event.username}' logged in at "
                f"{event.timestamp.strftime('%H:%M')} on "
                f"{event.timestamp.strftime('%A')} from {event.source_ip or 'unknown'}."
            ),
            timestamp=event.timestamp,
        )

    def _create_new_ip_alert(self, event: AuthEvent, known_ips: Set[str]) -> DetectionAlert:
        """
        Create a DetectionAlert for a login from a previously unseen IP.
        External IPs are higher severity than internal RFC1918 addresses.
        """
        is_external = not any(
            event.source_ip.startswith(prefix)
            for prefix in ('10.', '192.168.', '172.')
        )
        severity = "medium" if is_external else "low"

        return DetectionAlert(
            alert_id=f"NIP-{event.username}-{event.source_ip}-{event.timestamp.isoformat()}",
            detection_name="Login from New Source IP",
            severity=severity,
            related_events=[event],
            mitre_technique="T1078",
            description=(
                f"User '{event.username}' logged in from new IP {event.source_ip}. "
                f"Previously seen from: {', '.join(list(known_ips)[:3])}"
                f"{'...' if len(known_ips) > 3 else ''}."
            ),
            timestamp=event.timestamp,
        )

    def _create_impossible_travel_alert(
        self,
        event1: AuthEvent,
        event2: AuthEvent
    ) -> DetectionAlert:
        """
        Create a DetectionAlert for impossible travel between two logins.
        """
        time_diff = event2.timestamp - event1.timestamp
        minutes = int(time_diff.total_seconds() / 60)

        return DetectionAlert(
            alert_id=f"IT-{event1.username}-{event2.timestamp.isoformat()}",
            detection_name="Impossible Travel",
            severity="high",
            related_events=[event1, event2],
            mitre_technique="T1078",
            description=(
                f"User '{event1.username}' logged in from {event1.source_ip} at "
                f"{event1.timestamp.strftime('%H:%M')} then from {event2.source_ip} "
                f"just {minutes} minute(s) later."
            ),
            timestamp=event2.timestamp,
        )
