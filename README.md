# Log Analyzer

A security log analysis tool for detecting authentication anomalies and potential threats.

## Project Structure

```
log-analyzer/
├── docs/
│   └── DOMAIN_KNOWLEDGE.md    # READ THIS FIRST!
├── sample-data/
│   ├── auth.log               # Sample Linux auth logs
│   └── windows_security_events.xml  # Sample Windows events
├── src/
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── base_parser.py     # Abstract base class
│   │   ├── linux_parser.py    # Linux auth.log parser (IMPLEMENT THIS)
│   │   └── windows_parser.py  # Windows XML parser (IMPLEMENT THIS)
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── brute_force.py     # Brute force detection (IMPLEMENT THIS)
│   │   ├── anomaly.py         # Anomaly detection (IMPLEMENT THIS)
│   │   └── statistics.py      # Statistics calculator (IMPLEMENT THIS)
│   ├── models/
│   │   ├── __init__.py
│   │   └── events.py          # Data models (IMPLEMENT THIS)
│   └── main.py                # CLI entry point
├── tests/
│   └── test_parsers.py        # Unit tests (IMPLEMENT THIS)
├── frontend/                  # React dashboard (Phase 3)
├── requirements.txt
└── README.md
```

## Getting Started

### Phase 1: Learn the Domain
1. Read `docs/DOMAIN_KNOWLEDGE.md` thoroughly
2. Answer all the research questions
3. Examine the sample data files

### Phase 2: Implement the Core
Work through the skeleton files in this order:
1. `src/models/events.py` - Define your data structures
2. `src/parsers/linux_parser.py` - Parse auth.log files
3. `src/parsers/windows_parser.py` - Parse Windows XML logs
4. `src/analyzers/statistics.py` - Basic statistics
5. `src/analyzers/brute_force.py` - Detect brute force attacks
6. `src/analyzers/anomaly.py` - Detect anomalies
7. `tests/test_parsers.py` - Test your implementations

### Phase 3: Build the Frontend
- Create React dashboard
- Visualize events and detections
- Add filtering and search

## Running the Project

```bash
# Install dependencies
pip install -r requirements.txt

# Run the analyzer
python -m src.main --input sample-data/auth.log --format linux

# Run tests
python -m pytest tests/
```

## Skills Demonstrated

- Log parsing and normalization
- Security event analysis
- Attack pattern detection (brute force, password spray)
- Anomaly detection
- Data visualization
- Python/JavaScript development
- Understanding of authentication protocols

## MITRE ATT&CK Coverage

| Detection | Technique |
|-----------|-----------|
| Brute Force | T1110.001 |
| Password Spray | T1110.003 |
| Valid Accounts | T1078 |
| Remote Services | T1021 |
