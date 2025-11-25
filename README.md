# SubFindr – Open Source Subdomain Enumeration Tool

SubFindr is an open-source web tool for discovering subdomains of any target domain using multiple OSINT, DNS, and CT-based enumeration techniques.  
It is designed for learning, research, and defensive security testing — **strictly not for commercial resale or malicious use**.

> 🔒 **Note:** Only scan domains you own or are authorized to test.

---

# 🌟 Features

- 🔍 Multi-source subdomain discovery  
- ⚡ **Basic & Aggressive scan modes**  
- 📜 Certificate Transparency (CT) log scanning  
- 🧩 DNS brute-force using a wordlist  
- 🧬 DNS record enumeration (MX, NS, TXT, SOA)  
- 📄 JavaScript file parsing for hidden domains  
- 🕰 Wayback Machine historical URL extraction  
- 🛰 Search engine scraping (DuckDuckGo)  
- 🛰 Passive DNS via public OSINT sites (Aggressive mode)  
- ❤️ Alive check (HTTP/HTTPS) with status codes  
- 📑 Professional **PDF report generation** with watermark & creator link  
- 🖥 Clean TailwindCSS UI  
- 🔰 Simple FastAPI backend  

---

# 🧭 Scan Modes

## 🔹 Basic Mode (recommended for quick scans)

Uses fast essential OSINT sources:

- DNS bruteforce (resolved subdomains only)
- CRT.sh (Certificate Transparency)
- DNS records
- JavaScript file parsing
- DuckDuckGo search
- Wayback Machine
- AlienVault OTX (if available)
- CertAPI (optional external CT source)

---

## 🔸 Aggressive Mode (deeper enumeration)

Includes all Basic mode sources **plus**:

- Anubis (jldc.me)
- Sonar Omnisint
- RapidDNS
- HackerTarget hostsearch
- Additional passive DNS APIs

Aggressive mode is slower and may hit rate limits, but finds more subdomains.

---

# 🛠 Tech Stack

- **Backend:** FastAPI (Python)
- **Async:** aiohttp, asyncio
- **DNS:** aiodns, pycares
- **Frontend:** HTML, TailwindCSS, Vanilla JS
- **Reports:** jsPDF + jsPDF-AutoTable
- **Server:** Uvicorn

---

# 📁 Project Structure

```bash
SubFindr/
├── app/
│   ├── main.py                 # FastAPI application
│   ├── schemas.py              # Pydantic models
│   └── services/
│       └── subdomain_enum.py   # Core enumeration logic
├── static/
│   ├── index.html              # UI
│   └── app.js                  # Frontend logic (scan + PDF)
├── wordlists/
│   └── subdomains.txt          # Wordlist for bruteforce
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
