from src.parsers.windows_parser import WindowsEventParser
from pathlib import Path

parser = WindowsEventParser()
events = parser.parse_file(Path('sample-data/windows_security_events.xml'))

for e in events:
    print(f'{e.timestamp} | {e.event_type.value:25} | {e.username:15} | {e.source_ip or "":15} | {e.failure_reason or ""}')

print(f'\nTotal events parsed: {len(events)}')