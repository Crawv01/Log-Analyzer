"""
Statistics Analyzer

Calculates summary statistics for authentication events.
Provides counts, distributions, top-N rankings, and per-user/per-IP summaries.
"""

from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict, Counter

from src.models.events import AuthEvent, AnalysisSummary, EventType


class StatisticsAnalyzer:
    """
    Calculates summary statistics for a set of AuthEvents.

    Provides:
    - Event counts and success/failure rates
    - Unique user, IP, and host counts
    - Hourly, daily, and weekday distributions
    - Top-N user and IP rankings
    - Per-user and per-IP activity summaries
    """

    def __init__(self):
        pass

    def analyze(self, events: List[AuthEvent]) -> AnalysisSummary:
        """
        Calculate summary statistics and return an AnalysisSummary object.
        This is the main entry point for the analyzer.
        """
        time_range = self.get_time_range(events)
        return AnalysisSummary(
            total_events=len(events),
            success_count=self.count_successes(events),
            failure_count=self.count_failures(events),
            unique_users=self.get_unique_users(events),
            unique_ips=self.get_unique_ips(events),
            unique_hosts=self.get_unique_hosts(events),
            time_range_start=time_range[0],
            time_range_end=time_range[1],
        )

    def count_successes(self, events: List[AuthEvent]) -> int:
        """Count successful authentication events."""
        return sum(1 for e in events if e.event_type == EventType.LOGON_SUCCESS)

    def count_failures(self, events: List[AuthEvent]) -> int:
        """Count failed authentication events."""
        return sum(1 for e in events if e.event_type == EventType.LOGON_FAILURE)

    def get_success_rate(self, events: List[AuthEvent]) -> float:
        """
        Calculate the authentication success rate as a float between 0.0 and 1.0.
        Returns 0.0 if there are no events to avoid division by zero.
        """
        total = len(events)
        if total == 0:
            return 0.0
        return self.count_successes(events) / total

    def get_unique_users(self, events: List[AuthEvent]) -> int:
        """Count unique usernames across all events."""
        return len(set(e.username for e in events if e.username))

    def get_unique_ips(self, events: List[AuthEvent]) -> int:
        """Count unique source IP addresses across all events."""
        return len(set(e.source_ip for e in events if e.source_ip))

    def get_unique_hosts(self, events: List[AuthEvent]) -> int:
        """Count unique target hostnames across all events."""
        return len(set(e.target_hostname for e in events if e.target_hostname))

    def get_time_range(self, events: List[AuthEvent]) -> Tuple[Optional[datetime], Optional[datetime]]:
        """
        Get the earliest and latest timestamps in the event set.
        Returns (None, None) if there are no events with timestamps.
        """
        if not events:
            return (None, None)
        timestamps = [e.timestamp for e in events if e.timestamp]
        if not timestamps:
            return (None, None)
        return (min(timestamps), max(timestamps))

    def get_hourly_distribution(self, events: List[AuthEvent]) -> Dict[int, int]:
        """
        Count events by hour of day (0-23).
        Useful for visualizing login activity patterns across a 24-hour period.
        """
        distribution: Dict[int, int] = defaultdict(int)
        for event in events:
            if event.timestamp:
                distribution[event.timestamp.hour] += 1
        return dict(distribution)

    def get_daily_distribution(self, events: List[AuthEvent]) -> Dict[str, int]:
        """Count events by date (YYYY-MM-DD format)."""
        distribution: Dict[str, int] = defaultdict(int)
        for event in events:
            if event.timestamp:
                distribution[event.timestamp.strftime('%Y-%m-%d')] += 1
        return dict(distribution)

    def get_weekday_distribution(self, events: List[AuthEvent]) -> Dict[str, int]:
        """Count events by day of week (Monday through Sunday)."""
        days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        distribution: Dict[str, int] = defaultdict(int)
        for event in events:
            if event.timestamp:
                distribution[days[event.timestamp.weekday()]] += 1
        return dict(distribution)

    def get_top_users(self, events: List[AuthEvent], n: int = 10) -> List[Tuple[str, int]]:
        """Get the n most active users by total event count."""
        counter = Counter(e.username for e in events if e.username)
        return counter.most_common(n)

    def get_top_source_ips(self, events: List[AuthEvent], n: int = 10) -> List[Tuple[str, int]]:
        """Get the n most common source IP addresses by total event count."""
        counter = Counter(e.source_ip for e in events if e.source_ip)
        return counter.most_common(n)

    def get_top_failed_users(self, events: List[AuthEvent], n: int = 10) -> List[Tuple[str, int]]:
        """
        Get users with the most failed login attempts.
        Useful for identifying brute force targets or users with account issues.
        """
        failures = [e for e in events if e.event_type == EventType.LOGON_FAILURE]
        counter = Counter(e.username for e in failures if e.username)
        return counter.most_common(n)

    def get_top_failed_ips(self, events: List[AuthEvent], n: int = 10) -> List[Tuple[str, int]]:
        """
        Get source IPs with the most failed login attempts.
        Useful for identifying brute force sources or misconfigured systems.
        """
        failures = [e for e in events if e.event_type == EventType.LOGON_FAILURE]
        counter = Counter(e.source_ip for e in failures if e.source_ip)
        return counter.most_common(n)

    def get_logon_type_distribution(self, events: List[AuthEvent]) -> Dict[str, int]:
        """Count events by logon type (interactive, network, remote_interactive, etc.)."""
        distribution: Dict[str, int] = defaultdict(int)
        for event in events:
            if event.logon_type:
                distribution[event.logon_type.value] += 1
        return dict(distribution)

    def get_auth_method_distribution(self, events: List[AuthEvent]) -> Dict[str, int]:
        """Count events by authentication method (password, publickey, Negotiate, etc.)."""
        distribution: Dict[str, int] = defaultdict(int)
        for event in events:
            if event.auth_method:
                distribution[event.auth_method] += 1
        return dict(distribution)

    def get_user_activity_summary(self, events: List[AuthEvent], username: str) -> Dict[str, Any]:
        """
        Get a detailed activity summary for a specific user.
        Includes success/failure counts, source IPs, and time range.
        Returns an empty dict if the user has no events.
        """
        user_events = [e for e in events if e.username == username]
        if not user_events:
            return {}

        timestamps = [e.timestamp for e in user_events if e.timestamp]
        return {
            'username': username,
            'total_events': len(user_events),
            'success_count': sum(1 for e in user_events if e.event_type == EventType.LOGON_SUCCESS),
            'failure_count': sum(1 for e in user_events if e.event_type == EventType.LOGON_FAILURE),
            'unique_source_ips': len(set(e.source_ip for e in user_events if e.source_ip)),
            'source_ip_list': list(set(e.source_ip for e in user_events if e.source_ip)),
            'first_seen': min(timestamps) if timestamps else None,
            'last_seen': max(timestamps) if timestamps else None,
            'logon_types_used': list(set(
                e.logon_type.value for e in user_events if e.logon_type
            )),
        }

    def get_ip_activity_summary(self, events: List[AuthEvent], ip_address: str) -> Dict[str, Any]:
        """
        Get a detailed activity summary for a specific source IP.
        Includes success/failure counts, targeted users, and time range.
        Returns an empty dict if the IP has no events.
        """
        ip_events = [e for e in events if e.source_ip == ip_address]
        if not ip_events:
            return {}

        timestamps = [e.timestamp for e in ip_events if e.timestamp]
        return {
            'ip_address': ip_address,
            'total_events': len(ip_events),
            'success_count': sum(1 for e in ip_events if e.event_type == EventType.LOGON_SUCCESS),
            'failure_count': sum(1 for e in ip_events if e.event_type == EventType.LOGON_FAILURE),
            'unique_users_targeted': len(set(e.username for e in ip_events if e.username)),
            'users_targeted_list': list(set(e.username for e in ip_events if e.username)),
            'first_seen': min(timestamps) if timestamps else None,
            'last_seen': max(timestamps) if timestamps else None,
        }

    def to_dict(self, events: List[AuthEvent]) -> Dict[str, Any]:
        """
        Generate a complete statistics dictionary combining all metrics.
        Suitable for JSON export and frontend consumption.
        """
        time_range = self.get_time_range(events)

        return {
            'summary': {
                'total_events': len(events),
                'success_count': self.count_successes(events),
                'failure_count': self.count_failures(events),
                'success_rate': round(self.get_success_rate(events), 4),
                'unique_users': self.get_unique_users(events),
                'unique_ips': self.get_unique_ips(events),
                'unique_hosts': self.get_unique_hosts(events),
                'time_range_start': time_range[0].isoformat() if time_range[0] else None,
                'time_range_end': time_range[1].isoformat() if time_range[1] else None,
            },
            'distributions': {
                'by_hour': self.get_hourly_distribution(events),
                'by_weekday': self.get_weekday_distribution(events),
                'by_logon_type': self.get_logon_type_distribution(events),
                'by_auth_method': self.get_auth_method_distribution(events),
            },
            'top_lists': {
                'top_users': self.get_top_users(events),
                'top_source_ips': self.get_top_source_ips(events),
                'top_failed_users': self.get_top_failed_users(events),
                'top_failed_ips': self.get_top_failed_ips(events),
            },
        }
