# 🔍 Python Security Log Analyzer

A Python-based security log analysis tool that parses Linux and Windows system logs to detect brute force attacks, password spraying, and anomalous authentication behavior — with automated threat reporting.

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-CompTIA-red?style=flat)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-covered-orange?style=flat)

---

## ✨ Features

- **Linux Log Parsing** — Parses `/var/log/auth.log` format for SSH and authentication events
- **Windows Event Log Parsing** — Parses Windows Security Event XML logs (Event IDs 4624, 4625, etc.)
- **Brute Force Detection** — Identifies repeated failed login attempts against MITRE ATT&CK T1110.001
- **Password Spray Detection** — Detects low-and-slow attacks across multiple accounts (T1110.003)
- **Anomaly Detection** — Flags unusual login times, new source IPs, and statistical outliers
- **Statistics Engine** — Summarizes event counts, top offenders, and authentication patterns
- **Automated Reporting** — Generates threat summaries from analyzed log data
- **CLI Interface** — Run analysis directly from the command line with format flags

---

## 🛡 MITRE ATT&CK Coverage

| Detection | Technique ID |
|---|---|
| Brute Force | T1110.001 |
| Password Spray | T1110.003 |
| Valid Accounts | T1078 |
| Remote Services | T1021 |

---

## 🛠 Tech Stack

- **Python 3** — Core analysis engine
- **XML parsing** — Windows Security Event log ingestion
- **Regex** — Linux auth.log pattern matching
- **pytest** — Unit testing
- **React** *(planned)* — Dashboard frontend for event visualization

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+

### Installation

```bash
git clone https://github.com/Crawv01/Log-Analyzer.git
cd Log-Analyzer
pip install -r requirements.txt
```

### Run

```bash
# Analyze a Linux auth log
python -m src.main --input sample-data/auth.log --format linux

# Analyze Windows Security Event logs
python -m src.main --input sample-data/windows_security_events.xml --format windows

# Run tests
python -m pytest tests/
```

---

## 📁 Project Structure

```
log-analyzer/
├── docs/
│   └── DOMAIN_KNOWLEDGE.md    # Security domain research and notes
├── sample-data/
│   ├── auth.log               # Sample Linux auth logs
│   └── windows_security_events.xml  # Sample Windows Security Events
├── src/
│   ├── main.py                # CLI entry point
│   ├── models/
│   │   └── events.py          # Data models for log events
│   ├── parsers/
│   │   ├── base_parser.py     # Abstract base parser class
│   │   ├── linux_parser.py    # Linux auth.log parser
│   │   └── windows_parser.py  # Windows XML event parser
│   └── analyzers/
│       ├── brute_force.py     # Brute force attack detection
│       ├── anomaly.py         # Anomaly detection
│       └── statistics.py      # Authentication statistics
├── tests/
│   └── test_parsers.py        # Unit tests
├── requirements.txt
└── README.md
```

---

## 🗺 Roadmap

- [ ] React dashboard for event visualization
- [ ] Filtering and search across log events
- [ ] Export reports to PDF/CSV
- [ ] Real-time log monitoring mode
- [ ] Additional log format support (Apache, nginx, syslog)

---

## 📄 License

MIT
