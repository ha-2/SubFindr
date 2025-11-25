# SubFindr – Open Source Subdomain Enumeration Tool

SubFindr is an open-source subdomain enumeration tool that helps discover subdomains of any given domain using multiple enumeration techniques.

## Features

- Multi-source subdomain discovery
- Basic and Aggressive scan modes
- Certificate Transparency (CT) logs scanning
- DNS brute-force enumeration
- DNS record extraction (MX, NS, TXT, SOA)
- JavaScript file parsing
- Wayback Machine passive DNS
- Search engine scraping
- Alive subdomain checking
- PDF report generation
- Clean web interface

## Scan Modes

### Basic Mode
Fast scanning using essential OSINT sources:
- DNS bruteforce
- crt.sh CT logs
- DNS records
- JS file analysis
- DuckDuckGo search
- Wayback Machine

### Aggressive Mode
Comprehensive scanning using additional public OSINT services:
- All basic mode sources
- Anubis (jldc.me)
- Sonar Omnisint
- HackerTarget hostsearch
- RapidDNS HTML parsing
- CertAPI (if configured)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ha-2/SubFindr.git
   cd SubFindr
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

Start the server:
```bash
uvicorn app.main:app --reload
```

The application will be available at `http://localhost:8000`

## Screenshots

![SubFindr Interface](screenshots/interface.png)
*Main scanning interface*

![SubFindr Results](screenshots/results.png)
*Scan results with alive status*

![SubFindr PDF Report](screenshots/report.png)
*Generated PDF report sample*

## License

SubFindr is open-source under the Creative Commons Attribution-NonCommercial 4.0 License (CC BY-NC 4.0).  
Commercial use, resale, or monetization of this software is strictly prohibited.

## Creator

[https://github.com/ha-2](https://github.com/ha-2)

> This tool is intended for security research and education.  
> Only scan domains you own or are authorized to test.