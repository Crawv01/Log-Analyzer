from src.parsers.linux_parser import LinuxAuthParser
from src.parsers.windows_parser import WindowsEventParser
from src.analyzers.anomaly import AnomalyAnalyzer
from src.analyzers.statistics import StatisticsAnalyzer
from pathlib import Path
import json

linux_parser = LinuxAuthParser()
windows_parser = WindowsEventParser()

events = linux_parser.parse_file(Path('sample-data/auth.log'))
events += windows_parser.parse_file(Path('sample-data/windows_security_events.xml'))

# Use Jan 15 morning as baseline, analyze the rest
baseline = [e for e in events if e.timestamp.hour < 14 and e.timestamp.day == 15]
to_analyze = [e for e in events if e not in baseline]

# Anomaly detection
print("=== ANOMALY ALERTS ===")
anomaly = AnomalyAnalyzer(baseline_events=baseline)
alerts = anomaly.analyze(to_analyze)
for alert in alerts:
    print(f"[{alert.severity.upper()}] {alert.detection_name}: {alert.description}")

# Statistics
print("\n=== STATISTICS ===")
stats = StatisticsAnalyzer()
print(json.dumps(stats.to_dict(events), indent=2, default=str))