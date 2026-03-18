"""
Brute Force Detection Analyzer

Detects brute force and password spray attacks from normalized AuthEvent lists.
Maps to MITRE ATT&CK T1110.001 (Brute Force) and T1110.003 (Password Spray).
"""

from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

from src.models.events import AuthEvent, DetectionAlert, EventType


class BruteForceAnalyzer:
    """
    Detects brute force and related credential attacks.

    Detection Types:
    1. Brute Force: Many failed attempts to ONE account from ONE source (T1110.001)
    2. Password Spray: Failed attempts to MANY accounts from ONE source (T1110.003)
    3. Credential Stuffing: Mix of success/failure across many accounts (T1110.004)
    """

    DEFAULT_THRESHOLDS = {
        'brute_force_failures': 5,           # Failures to same account before alerting
        'brute_force_window_minutes': 5,      # Time window for brute force detection
        'password_spray_accounts': 5,         # Unique accounts targeted before alerting
        'password_spray_window_minutes': 10,  # Time window for spray detection
        'credential_stuffing_accounts': 3,    # Unique accounts with mix of success/failure
    }

    def __init__(self, thresholds: Dict[str, int] = None):
        """
        Initialize with optional threshold overrides.
        Merges provided thresholds with defaults so you only need to specify
        what you want to change.
        """
        self.thresholds = {**self.DEFAULT_THRESHOLDS}
        if thresholds:
            self.thresholds.update(thresholds)

    def analyze(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        """
        Main entry point. Runs all detection algorithms and returns combined alerts.
        Sorts events by timestamp first so all sliding window logic works correctly.
        """
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        alerts = []
        alerts.extend(self.detect_brute_force(sorted_events))
        alerts.extend(self.detect_password_spray(sorted_events))
        alerts.extend(self.detect_credential_stuffing(sorted_events))

        return alerts

    def detect_brute_force(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        """
        Detect classic brute force: many failures to SAME account from SAME IP.
        Groups failures by (source_ip, username) then checks each group with
        a sliding window.
        """
        alerts = []

        # Group all failures by (source_ip, username) tuple
        failures_by_target: Dict[Tuple[str, str], List[AuthEvent]] = defaultdict(list)

        for event in events:
            if event.event_type == EventType.LOGON_FAILURE and event.source_ip:
                key = (event.source_ip, event.username)
                failures_by_target[key].append(event)

        # Check each (ip, user) pair for threshold breach
        for (source_ip, username), failure_events in failures_by_target.items():
            alert = self._check_brute_force_window(source_ip, username, failure_events)
            if alert:
                alerts.append(alert)

        return alerts

    def _check_brute_force_window(
        self,
        source_ip: str,
        username: str,
        failures: List[AuthEvent]
    ) -> Optional[DetectionAlert]:
        """
        Sliding window check: find the maximum number of failures within the
        configured time window. If it exceeds the threshold, create an alert.

        Uses two-pointer sliding window (O(n)) rather than nested loops (O(n²)).
        window_start moves forward whenever the oldest event falls outside the window.
        """
        window = timedelta(minutes=self.thresholds['brute_force_window_minutes'])
        threshold = self.thresholds['brute_force_failures']

        sorted_failures = sorted(failures, key=lambda e: e.timestamp)

        window_start = 0
        max_in_window = 0
        events_at_max = []

        for i, event in enumerate(sorted_failures):
            # Shrink window from the left if oldest event is outside the window
            while (event.timestamp - sorted_failures[window_start].timestamp) > window:
                window_start += 1

            in_window = i - window_start + 1
            if in_window > max_in_window:
                max_in_window = in_window
                events_at_max = sorted_failures[window_start:i + 1]

        if max_in_window >= threshold:
            return self._create_brute_force_alert(source_ip, username, events_at_max)

        return None

    def detect_password_spray(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        """
        Detect password spray: failures to MANY unique accounts from ONE source.
        Key difference from brute force — attacker tries one password per account
        to avoid lockouts.
        """
        alerts = []

        # Group failures by source IP
        failures_by_source: Dict[str, List[AuthEvent]] = defaultdict(list)

        for event in events:
            if event.event_type == EventType.LOGON_FAILURE and event.source_ip:
                failures_by_source[event.source_ip].append(event)

        for source_ip, failure_events in failures_by_source.items():
            alert = self._check_password_spray_window(source_ip, failure_events)
            if alert:
                alerts.append(alert)

        return alerts

    def _check_password_spray_window(
        self,
        source_ip: str,
        failures: List[AuthEvent]
    ) -> Optional[DetectionAlert]:
        """
        Sliding window check for password spray.
        Counts unique usernames targeted within the time window.
        If unique targets exceed threshold, create alert.
        """
        window = timedelta(minutes=self.thresholds['password_spray_window_minutes'])
        threshold = self.thresholds['password_spray_accounts']

        sorted_failures = sorted(failures, key=lambda e: e.timestamp)

        window_start = 0
        best_events = []
        best_unique = 0

        for i, event in enumerate(sorted_failures):
            while (event.timestamp - sorted_failures[window_start].timestamp) > window:
                window_start += 1

            window_events = sorted_failures[window_start:i + 1]
            unique_users = len(set(e.username for e in window_events))

            if unique_users > best_unique:
                best_unique = unique_users
                best_events = window_events

        if best_unique >= threshold:
            unique_usernames = list(set(e.username for e in best_events))
            return self._create_password_spray_alert(source_ip, unique_usernames, best_events)

        return None

    def detect_credential_stuffing(self, events: List[AuthEvent]) -> List[DetectionAlert]:
        """
        Detect credential stuffing: mix of successes AND failures from one source
        across many accounts. Indicates attacker is using a leaked credential list
        where some passwords are valid.

        Indicators:
        - Same source IP has both successes and failures
        - Multiple unique accounts involved
        - Attempts happen in rapid succession
        """
        alerts = []
        threshold = self.thresholds['credential_stuffing_accounts']

        # Group all events (success + failure) by source IP
        events_by_source: Dict[str, List[AuthEvent]] = defaultdict(list)

        for event in events:
            if event.source_ip and event.event_type in (
                EventType.LOGON_SUCCESS, EventType.LOGON_FAILURE
            ):
                events_by_source[event.source_ip].append(event)

        for source_ip, source_events in events_by_source.items():
            successes = [e for e in source_events if e.event_type == EventType.LOGON_SUCCESS]
            failures = [e for e in source_events if e.event_type == EventType.LOGON_FAILURE]

            # Must have both successes and failures, with enough unique accounts
            unique_accounts = set(e.username for e in source_events)
            if successes and failures and len(unique_accounts) >= threshold:
                alert = DetectionAlert(
                    alert_id=f"CS-{source_ip}-{source_events[0].timestamp.isoformat()}",
                    detection_name="Credential Stuffing",
                    severity=self._calculate_severity(len(source_events)),
                    related_events=source_events,
                    mitre_technique="T1110.004",
                    description=(
                        f"Possible credential stuffing from {source_ip}: "
                        f"{len(failures)} failures and {len(successes)} successes "
                        f"across {len(unique_accounts)} unique accounts."
                    ),
                    timestamp=source_events[-1].timestamp,
                )
                alerts.append(alert)

        return alerts

    def _create_brute_force_alert(
        self,
        source_ip: str,
        username: str,
        events: List[AuthEvent]
    ) -> DetectionAlert:
        """
        Create a DetectionAlert for a brute force attack (T1110.001).
        Severity scales with number of attempts.
        """
        return DetectionAlert(
            alert_id=f"BF-{source_ip}-{username}-{events[0].timestamp.isoformat()}",
            detection_name="Brute Force Attack",
            severity=self._calculate_severity(len(events)),
            related_events=events,
            mitre_technique="T1110.001",
            description=(
                f"Detected {len(events)} failed login attempts to account "
                f"'{username}' from {source_ip} within "
                f"{self.thresholds['brute_force_window_minutes']} minutes."
            ),
            timestamp=events[-1].timestamp,
        )

    def _create_password_spray_alert(
        self,
        source_ip: str,
        usernames: List[str],
        events: List[AuthEvent]
    ) -> DetectionAlert:
        """
        Create a DetectionAlert for a password spray attack (T1110.003).
        """
        return DetectionAlert(
            alert_id=f"PS-{source_ip}-{events[0].timestamp.isoformat()}",
            detection_name="Password Spray Attack",
            severity=self._calculate_severity(len(usernames)),
            related_events=events,
            mitre_technique="T1110.003",
            description=(
                f"Detected password spray from {source_ip}: "
                f"{len(events)} failures across {len(usernames)} unique accounts "
                f"({', '.join(usernames[:5])}{'...' if len(usernames) > 5 else ''})."
            ),
            timestamp=events[-1].timestamp,
        )

    def _calculate_severity(self, count: int) -> str:
        """
        Map event/account count to a severity level.
        Used for both brute force (failure count) and spray (account count).
        """
        if count >= 50:
            return "critical"
        elif count >= 26:
            return "high"
        elif count >= 11:
            return "medium"
        else:
            return "low"
