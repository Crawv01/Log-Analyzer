from src.parsers.linux_parser import LinuxAuthParser
from pathlib import Path

parser = LinuxAuthParser()
events = parser.parse_file(Path('sample-data/auth.log'))

for e in events:
    print(f'{e.timestamp} | {e.event_type.value:25} | {e.username:12} | {e.source_ip or ""}')

print(f'\nTotal events parsed: {len(events)}')