"""
Unit Tests for Log Analyzer

Run with: python -m pytest tests/ -v
"""

import pytest
from datetime import datetime
from pathlib import Path

from src.models.events import AuthEvent, EventType, LogonType, SourceType
from src.parsers.linux_parser import LinuxAuthParser
from src.parsers.windows_parser import WindowsEventParser
from src.analyzers.brute_force import BruteForceAnalyzer
from src.analyzers.anomaly import AnomalyAnalyzer
from src.analyzers.statistics import StatisticsAnalyzer


# =============================================================================
# HELPERS
# =============================================================================

def make_event(
    event_type=EventType.LOGON_FAILURE,
    username="testuser",
    source_ip="1.2.3.4",
    hour=14,
    minute=0,
    second=0,
    day=15,
    source_type=SourceType.LINUX_AUTH,
    success=False,
    logon_type=None,
):
    """Helper to create AuthEvents for tests without repeating boilerplate."""
    return AuthEvent(
        timestamp=datetime(2024, 1, day, hour, minute, second),
        event_type=event_type,
        source_type=source_type,
        username=username,
        source_ip=source_ip,
        success=success,
        logon_type=logon_type,
    )


# =============================================================================
# EVENT MODEL TESTS
# =============================================================================

class TestAuthEvent:
    """Tests for the AuthEvent data model."""

    def test_create_event(self):
        event = AuthEvent(
            timestamp=datetime(2024, 1, 15, 14, 30, 0),
            event_type=EventType.LOGON_SUCCESS,
            source_type=SourceType.LINUX_AUTH,
            username="testuser",
            source_ip="192.168.1.100",
            target_hostname="webserver",
            success=True,
        )
        assert event.username == "testuser"
        assert event.event_type == EventType.LOGON_SUCCESS
        assert event.source_ip == "192.168.1.100"
        assert event.success is True

    def test_event_defaults(self):
        """Optional fields should default to None or empty list."""
        event = AuthEvent(
            timestamp=datetime(2024, 1, 15, 8, 0, 0),
            event_type=EventType.LOGON_FAILURE,
            source_type=SourceType.SSH,
            username="user",
        )
        assert event.source_ip is None
        assert event.domain is None
        assert event.risk_score == 0
        assert event.risk_factors == []
        assert event.tags == []

    def test_event_to_dict(self):
        event = AuthEvent(
            timestamp=datetime(2024, 1, 15, 14, 30, 0),
            event_type=EventType.LOGON_SUCCESS,
            source_type=SourceType.LINUX_AUTH,
            username="testuser",
            success=True,
        )
        d = event.to_dict()
        assert isinstance(d, dict)
        assert d['username'] == "testuser"
        assert d['event_type'] == "logon_success"
        assert d['source_type'] == "linux_auth"
        # Timestamp should be ISO string, not datetime object
        assert isinstance(d['timestamp'], str)
        assert "2024-01-15" in d['timestamp']

    def test_event_from_dict_roundtrip(self):
        """to_dict() then from_dict() should produce equivalent event."""
        original = AuthEvent(
            timestamp=datetime(2024, 1, 15, 14, 30, 0),
            event_type=EventType.LOGON_FAILURE,
            source_type=SourceType.SSH,
            username="admin",
            source_ip="10.0.0.1",
            success=False,
        )
        d = original.to_dict()
        restored = AuthEvent.from_dict(d)
        assert restored.username == original.username
        assert restored.event_type == original.event_type
        assert restored.source_ip == original.source_ip
        assert restored.success == original.success


# =============================================================================
# LINUX PARSER TESTS
# =============================================================================

class TestLinuxParser:
    """Tests for the Linux auth.log parser."""

    @pytest.fixture
    def parser(self):
        return LinuxAuthParser()

    def test_parse_ssh_success(self, parser):
        line = "Jan 15 08:15:32 webserver sshd[1234]: Accepted publickey for admin from 192.168.1.10 port 52413 ssh2"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.LOGON_SUCCESS
        assert event.username == "admin"
        assert event.source_ip == "192.168.1.10"
        assert event.auth_method == "publickey"
        assert event.success is True

    def test_parse_ssh_failure_valid_user(self, parser):
        line = "Jan 15 14:22:01 webserver sshd[2001]: Failed password for root from 203.0.113.50 port 55001 ssh2"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.LOGON_FAILURE
        assert event.username == "root"
        assert event.source_ip == "203.0.113.50"
        assert event.success is False

    def test_parse_ssh_failure_invalid_user(self, parser):
        line = "Jan 15 15:00:01 webserver sshd[2100]: Failed password for invalid user admin123 from 198.51.100.25 port 60001 ssh2"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.LOGON_FAILURE
        assert event.username == "admin123"
        assert event.source_ip == "198.51.100.25"
        assert "invalid_user" in event.tags

    def test_parse_sudo_success(self, parser):
        line = "Jan 15 08:20:45 webserver sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/systemctl status nginx"
        event = parser.parse_line(line)
        assert event is not None
        assert event.username == "admin"
        assert event.event_type == EventType.PRIVILEGE_ESCALATION
        assert event.success is True

    def test_parse_sudo_failure(self, parser):
        line = "Jan 15 17:00:00 webserver sudo: developer : command not allowed ; TTY=pts/1 ; PWD=/home/developer ; USER=root ; COMMAND=/bin/rm -rf /var/log"
        event = parser.parse_line(line)
        assert event is not None
        assert event.username == "developer"
        assert event.success is False

    def test_parse_session_open(self, parser):
        line = "Jan 15 08:15:32 webserver sshd[1234]: pam_unix(sshd:session): session opened for user admin by (uid=0)"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.SESSION_OPEN
        assert event.username == "admin"

    def test_parse_session_closed(self, parser):
        line = "Jan 15 08:25:00 webserver sshd[1234]: pam_unix(sshd:session): session closed for user admin"
        event = parser.parse_line(line)
        assert event is not None
        assert event.event_type == EventType.SESSION_CLOSED
        assert event.username == "admin"

    def test_parse_comment_line_returns_none(self, parser):
        line = "# This is a comment"
        assert parser.parse_line(line) is None

    def test_parse_empty_line_returns_none(self, parser):
        assert parser.parse_line("") is None

    def test_parse_non_auth_line_returns_none(self, parser):
        line = "Jan 15 12:00:00 webserver kernel: Some kernel message here"
        assert parser.parse_line(line) is None

    def test_parse_timestamp(self, parser):
        line = "Jan 15 14:30:45 webserver sshd[123]: Accepted password for user from 1.2.3.4 port 22 ssh2"
        event = parser.parse_line(line)
        assert event.timestamp.month == 1
        assert event.timestamp.day == 15
        assert event.timestamp.hour == 14
        assert event.timestamp.minute == 30
        assert event.timestamp.second == 45

    def test_parse_file_returns_events(self, parser):
        events = parser.parse_file(Path("sample-data/auth.log"))
        assert len(events) > 0

    def test_parse_file_event_types(self, parser):
        events = parser.parse_file(Path("sample-data/auth.log"))
        event_types = {e.event_type for e in events}
        assert EventType.LOGON_SUCCESS in event_types
        assert EventType.LOGON_FAILURE in event_types
        assert EventType.PRIVILEGE_ESCALATION in event_types

    def test_parse_file_count(self, parser):
        """Sample file should produce exactly 60 events."""
        events = parser.parse_file(Path("sample-data/auth.log"))
        assert len(events) == 60


# =============================================================================
# WINDOWS PARSER TESTS
# =============================================================================

class TestWindowsParser:
    """Tests for the Windows Security Event parser."""

    @pytest.fixture
    def parser(self):
        return WindowsEventParser()

    def test_parse_file_returns_events(self, parser):
        events = parser.parse_file(Path("sample-data/windows_security_events.xml"))
        assert len(events) > 0

    def test_parse_file_count(self, parser):
        """Sample file should produce exactly 17 events."""
        events = parser.parse_file(Path("sample-data/windows_security_events.xml"))
        assert len(events) == 17

    def test_parse_logon_success(self, parser):
        events = parser.parse_file(Path("sample-data/windows_security_events.xml"))
        successes = [e for e in events if e.event_type == EventType.LOGON_SUCCESS]
        assert len(successes) > 0
        # Check first success has expected fields
        first = successes[0]
        assert first.username is not None
        assert first.source_type == SourceType.WINDOWS_SECURITY

    def test_parse_logon_failure_has_reason(self, parser):
        events = parser.parse_file(Path("sample-data/windows_security_events.xml"))
        failures = [e for e in events if e.event_type == EventType.LOGON_FAILURE]
        assert len(failures) > 0
        # All failures should have a failure reason
        for f in failures:
            assert f.failure_reason is not None

    def test_parse_rdp_logon_type(self, parser):
        """Event with LogonType=10 should map to remote_interactive."""
        events = parser.parse_file(Path("sample-data/windows_security_events.xml"))
        rdp_events = [e for e in events if e.logon_type == LogonType.REMOTE_INTERACTIVE]
        assert len(rdp_events) > 0

    def test_parse_special_privileges(self, parser):
        events = parser.parse_file(Path("sample-data/windows_security_events.xml"))
        priv_events = [e for e in events if e.event_type == EventType.SPECIAL_PRIV]
        assert len(priv_events) == 1
        assert priv_events[0].username == "Administrator"

    def test_parse_logoff(self, parser):
        events = parser.parse_file(Path("sample-data/windows_security_events.xml"))
        logoff_events = [e for e in events if e.event_type == EventType.USER_LOGOFF]
        assert len(logoff_events) == 1
        assert logoff_events[0].username == "jsmith"


# =============================================================================
# BRUTE FORCE ANALYZER TESTS
# =============================================================================

class TestBruteForceAnalyzer:
    """Tests for brute force and password spray detection."""

    @pytest.fixture
    def analyzer(self):
        return BruteForceAnalyzer(thresholds={
            'brute_force_failures': 3,
            'brute_force_window_minutes': 5,
            'password_spray_accounts': 3,
            'password_spray_window_minutes': 10,
        })

    def test_detect_brute_force(self, analyzer):
        """5 failures to same account from same IP within window should alert."""
        events = [
            make_event(username="admin", source_ip="1.2.3.4", second=i)
            for i in range(5)
        ]
        alerts = analyzer.detect_brute_force(events)
        assert len(alerts) == 1
        assert "Brute Force" in alerts[0].detection_name
        assert alerts[0].mitre_technique == "T1110.001"

    def test_no_alert_below_threshold(self, analyzer):
        """2 failures should not trigger alert (threshold is 3)."""
        events = [
            make_event(username="admin", source_ip="1.2.3.4", second=i)
            for i in range(2)
        ]
        alerts = analyzer.detect_brute_force(events)
        assert len(alerts) == 0

    def test_no_alert_spread_failures(self, analyzer):
        """Failures spread over hours should not trigger brute force."""
        events = [
            make_event(username="admin", source_ip="1.2.3.4", hour=h)
            for h in range(5)
        ]
        alerts = analyzer.detect_brute_force(events)
        assert len(alerts) == 0

    def test_detect_password_spray(self, analyzer):
        """One IP hitting many accounts should trigger spray alert."""
        events = [
            make_event(username=f"user{i}", source_ip="5.5.5.5", second=i)
            for i in range(5)
        ]
        alerts = analyzer.detect_password_spray(events)
        assert len(alerts) == 1
        assert "Spray" in alerts[0].detection_name
        assert alerts[0].mitre_technique == "T1110.003"

    def test_brute_force_different_ips_no_alert(self, analyzer):
        """Failures from different IPs to same user should not trigger single BF alert."""
        events = [
            make_event(username="admin", source_ip=f"1.2.3.{i}", second=i)
            for i in range(5)
        ]
        alerts = analyzer.detect_brute_force(events)
        # Each IP only has 1 failure — no brute force
        assert len(alerts) == 0

    def test_sample_data_detects_brute_force(self, analyzer):
        """Integration: should detect brute force in sample auth.log."""
        parser = LinuxAuthParser()
        events = parser.parse_file(Path("sample-data/auth.log"))
        alerts = analyzer.analyze(events)
        bf_alerts = [a for a in alerts if "Brute Force" in a.detection_name]
        assert len(bf_alerts) > 0

    def test_sample_data_detects_spray(self, analyzer):
        """Integration: should detect password spray in sample data."""
        parser = LinuxAuthParser()
        events = parser.parse_file(Path("sample-data/auth.log"))
        alerts = analyzer.analyze(events)
        spray_alerts = [a for a in alerts if "Spray" in a.detection_name]
        assert len(spray_alerts) > 0

    def test_severity_low(self, analyzer):
        events = [make_event(second=i) for i in range(4)]
        alerts = analyzer.detect_brute_force(events)
        assert alerts[0].severity == "low"

    def test_alert_contains_related_events(self, analyzer):
        events = [make_event(second=i) for i in range(5)]
        alerts = analyzer.detect_brute_force(events)
        assert len(alerts[0].related_events) >= 3


# =============================================================================
# ANOMALY ANALYZER TESTS
# =============================================================================

class TestAnomalyAnalyzer:
    """Tests for anomaly detection."""

    @pytest.fixture
    def analyzer(self):
        return AnomalyAnalyzer()

    def test_detect_off_hours_3am(self, analyzer):
        """Login at 3AM should trigger high severity alert."""
        event = make_event(
            event_type=EventType.LOGON_SUCCESS,
            hour=3, success=True
        )
        alerts = analyzer.detect_off_hours_activity([event])
        assert len(alerts) == 1
        assert alerts[0].severity == "high"

    def test_detect_off_hours_late_evening(self, analyzer):
        """Login at 11PM should trigger low severity alert."""
        event = make_event(
            event_type=EventType.LOGON_SUCCESS,
            hour=23, success=True
        )
        alerts = analyzer.detect_off_hours_activity([event])
        assert len(alerts) == 1
        assert alerts[0].severity == "low"

    def test_no_alert_business_hours(self, analyzer):
        """Login at 10AM on a weekday should not alert."""
        event = make_event(
            event_type=EventType.LOGON_SUCCESS,
            hour=10, success=True
        )
        alerts = analyzer.detect_off_hours_activity([event])
        assert len(alerts) == 0

    def test_no_alert_for_failures(self, analyzer):
        """Off-hours failures should not trigger off-hours alert (only successes)."""
        event = make_event(
            event_type=EventType.LOGON_FAILURE,
            hour=3, success=False
        )
        alerts = analyzer.detect_off_hours_activity([event])
        assert len(alerts) == 0

    def test_detect_new_source_ip(self, analyzer):
        """Login from unknown IP should alert when baseline exists."""
        baseline = [
            make_event(event_type=EventType.LOGON_SUCCESS,
                      username="alice", source_ip="10.0.0.1", success=True)
        ]
        analyzer._build_baseline(baseline)

        new_event = make_event(
            event_type=EventType.LOGON_SUCCESS,
            username="alice", source_ip="99.99.99.99", success=True
        )
        alerts = analyzer.detect_new_source_ip([new_event])
        assert len(alerts) == 1
        assert "New Source IP" in alerts[0].detection_name

    def test_no_alert_known_ip(self, analyzer):
        """Login from known IP should not alert."""
        baseline = [
            make_event(event_type=EventType.LOGON_SUCCESS,
                      username="alice", source_ip="10.0.0.1", success=True)
        ]
        analyzer._build_baseline(baseline)

        same_ip_event = make_event(
            event_type=EventType.LOGON_SUCCESS,
            username="alice", source_ip="10.0.0.1", success=True
        )
        alerts = analyzer.detect_new_source_ip([same_ip_event])
        assert len(alerts) == 0

    def test_no_alert_no_baseline(self, analyzer):
        """New IP without any baseline should not alert."""
        event = make_event(
            event_type=EventType.LOGON_SUCCESS,
            username="newuser", source_ip="1.2.3.4", success=True
        )
        alerts = analyzer.detect_new_source_ip([event])
        assert len(alerts) == 0

    def test_detect_impossible_travel(self, analyzer):
        """Same user from different IPs within 60 min should alert."""
        event1 = make_event(
            event_type=EventType.LOGON_SUCCESS,
            username="bob", source_ip="10.0.0.1",
            hour=3, minute=0, success=True
        )
        event2 = make_event(
            event_type=EventType.LOGON_SUCCESS,
            username="bob", source_ip="203.0.113.50",
            hour=3, minute=5, success=True
        )
        alerts = analyzer.detect_impossible_travel([event1, event2])
        assert len(alerts) == 1
        assert "Impossible Travel" in alerts[0].detection_name
        assert alerts[0].severity == "high"

    def test_sample_data_off_hours(self, analyzer):
        """Integration: 3AM activity in sample data should be detected."""
        parser = LinuxAuthParser()
        events = parser.parse_file(Path("sample-data/auth.log"))
        alerts = analyzer.detect_off_hours_activity(events)
        assert len(alerts) > 0


# =============================================================================
# STATISTICS ANALYZER TESTS
# =============================================================================

class TestStatisticsAnalyzer:
    """Tests for statistics calculations."""

    @pytest.fixture
    def analyzer(self):
        return StatisticsAnalyzer()

    @pytest.fixture
    def sample_events(self):
        return [
            make_event(event_type=EventType.LOGON_SUCCESS, username="alice", success=True),
            make_event(event_type=EventType.LOGON_SUCCESS, username="bob", success=True),
            make_event(event_type=EventType.LOGON_FAILURE, username="alice", source_ip="2.2.2.2"),
            make_event(event_type=EventType.LOGON_FAILURE, username="charlie", source_ip="3.3.3.3"),
            make_event(event_type=EventType.LOGON_FAILURE, username="charlie", source_ip="3.3.3.3"),
        ]

    def test_count_successes(self, analyzer, sample_events):
        assert analyzer.count_successes(sample_events) == 2

    def test_count_failures(self, analyzer, sample_events):
        assert analyzer.count_failures(sample_events) == 3

    def test_success_rate(self, analyzer, sample_events):
        rate = analyzer.get_success_rate(sample_events)
        assert abs(rate - 0.4) < 0.001

    def test_success_rate_empty(self, analyzer):
        assert analyzer.get_success_rate([]) == 0.0

    def test_unique_users(self, analyzer, sample_events):
        assert analyzer.get_unique_users(sample_events) == 3

    def test_unique_ips(self, analyzer, sample_events):
        # alice success has "1.2.3.4", bob success has "1.2.3.4", failure has "2.2.2.2", "3.3.3.3"
        count = analyzer.get_unique_ips(sample_events)
        assert count >= 2

    def test_get_time_range(self, analyzer, sample_events):
        start, end = analyzer.get_time_range(sample_events)
        assert start is not None
        assert end is not None
        assert start <= end

    def test_get_time_range_empty(self, analyzer):
        start, end = analyzer.get_time_range([])
        assert start is None
        assert end is None

    def test_top_failed_users(self, analyzer, sample_events):
        top = analyzer.get_top_failed_users(sample_events, n=1)
        assert top[0][0] == "charlie"  # charlie has 2 failures
        assert top[0][1] == 2

    def test_hourly_distribution(self, analyzer, sample_events):
        dist = analyzer.get_hourly_distribution(sample_events)
        assert isinstance(dist, dict)
        assert 14 in dist  # All sample events are at hour 14

    def test_to_dict_structure(self, analyzer, sample_events):
        result = analyzer.to_dict(sample_events)
        assert 'summary' in result
        assert 'distributions' in result
        assert 'top_lists' in result
        assert result['summary']['total_events'] == 5

    def test_user_activity_summary(self, analyzer, sample_events):
        summary = analyzer.get_user_activity_summary(sample_events, "charlie")
        assert summary['username'] == "charlie"
        assert summary['failure_count'] == 2
        assert summary['success_count'] == 0

    def test_user_activity_summary_missing_user(self, analyzer, sample_events):
        summary = analyzer.get_user_activity_summary(sample_events, "nobody")
        assert summary == {}


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """End-to-end integration tests using real sample data."""

    def test_full_linux_pipeline(self):
        parser = LinuxAuthParser()
        events = parser.parse_file(Path("sample-data/auth.log"))

        bf_analyzer = BruteForceAnalyzer()
        anomaly_analyzer = AnomalyAnalyzer()
        stats_analyzer = StatisticsAnalyzer()

        bf_alerts = bf_analyzer.analyze(events)
        anomaly_alerts = anomaly_analyzer.analyze(events)
        stats = stats_analyzer.to_dict(events)

        assert len(events) == 60
        assert len(bf_alerts) > 0
        assert len(anomaly_alerts) > 0
        assert stats['summary']['total_events'] == 60
        assert stats['summary']['failure_count'] > stats['summary']['success_count']

    def test_full_windows_pipeline(self):
        parser = WindowsEventParser()
        events = parser.parse_file(Path("sample-data/windows_security_events.xml"))

        bf_analyzer = BruteForceAnalyzer()
        stats_analyzer = StatisticsAnalyzer()

        bf_alerts = bf_analyzer.analyze(events)
        stats = stats_analyzer.to_dict(events)

        assert len(events) == 17
        assert len(bf_alerts) > 0
        assert stats['summary']['total_events'] == 17

    def test_combined_linux_windows_pipeline(self):
        linux_parser = LinuxAuthParser()
        windows_parser = WindowsEventParser()

        events = linux_parser.parse_file(Path("sample-data/auth.log"))
        events += windows_parser.parse_file(Path("sample-data/windows_security_events.xml"))

        bf_analyzer = BruteForceAnalyzer()
        alerts = bf_analyzer.analyze(events)

        # Should detect brute force from both sources
        assert len(alerts) > 0
        assert len(events) == 77


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
