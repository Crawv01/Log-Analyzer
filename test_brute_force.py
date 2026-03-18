from src.parsers.linux_parser import LinuxAuthParser
from src.parsers.windows_parser import WindowsEventParser
from src.analyzers.brute_force import BruteForceAnalyzer
from pathlib import Path

linux_parser = LinuxAuthParser()
windows_parser = WindowsEventParser()

events = linux_parser.parse_file(Path('sample-data/auth.log'))
events += windows_parser.parse_file(Path('sample-data/windows_security_events.xml'))

analyzer = BruteForceAnalyzer()
alerts = analyzer.analyze(events)

for alert in alerts:
    print(f"[{alert.severity.upper()}] {alert.detection_name}")
    print(f"  {alert.description}")
    print(f"  MITRE: {alert.mitre_technique}")
    print(f"  Events: {len(alert.related_events)}")
    print()

print(f"Total alerts: {len(alerts)}")