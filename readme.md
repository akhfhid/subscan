

# Bug-Bounty Recon (BBR)  
Lightweight reconnaissance & vulnerability scanner for bug-bounty hunters.

![Python](https://img.shields.io/badge/python-3.7+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

##  What it does
- Enumerate sub-domains (crt.sh + built-in wordlist fallback)
- Probe live hosts (A/AAAA record)
- Quick vulnerability checks:
  - CORS mis-configuration
  - Open redirect
  - Reflected XSS (simple)
  - Missing security headers (CSP, HSTS, X-Content-Type-Options, Clickjacking)
- Export results:
  - `subdomains.txt`
  - `vulns.json`
  - `report.html` (human-friendly)

---

## 🚀 One-liner install & run
```bash
git clone https://github.com/akhfhid/subscan.git
cd subscan
pip install -r requirements.txt
python bbr.py -t example.com
```

---

## How To Use
| Flag | Description | Example |
|------|-------------|---------|
| `-t TARGET` | Scan single domain | `python bbr.py -t hackerone.com` |
| `-f FILE` | Multi-target (scope file) | `python bbr.py -f scope.txt` |
| `--fast` | Reduce requests (faster) | `python bbr.py -t example.com --fast` |
| `--threads N` | Concurrent workers (default 30) | `python bbr.py -t example.com --threads 50` |

---

##  Output tree
```
out/example.com/
├── subdomains.txt   # live hosts
├── vulns.json       # raw findings
└── report.html      # pretty report
```

---

## 🔍 Sample finding
```json
{
  "type": "CORS",
  "url": "https://api.example.com",
  "detail": "ACAO: *"
}
```

---

## ⚠️ Ethics & rules
1. Only scan domains you own or have explicit permission to test.  
2. Respect program scope & rate-limits – use `--fast` / lower `--threads` if needed.  
3. Always validate manually before submitting bugs.

---

## 🛠️ Extending
- Drop your own wordlist in `check_open_redirect` / `check_xss_reflection` functions.  
- Add new sources in `subfinder()` (SecurityTrails, Amass, sublist3r, etc.).  
- Integrate with your Burp / Zap exports by parsing extra URLs into `out/TARGET/vulns.json`.

---

## 🤝 Contribute
PRs & issues are welcome!  
Please run ` bbr.py` before submitting code.

---

## 📜 License
MIT – feel free to use, modify, and share.

---

##  Author
```
[Affan Khulafa Hidayah](https://github.com/akhfhid) 
```