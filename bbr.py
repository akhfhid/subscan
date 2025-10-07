import argparse, asyncio, json, os, re, sys, time, urllib.parse
from pathlib import Path
from typing import List, Dict, Set, Sequence

import aiohttp, aiodns, tldextract, socket
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init

colorama_color = lambda c, s: f"{c}{s}{Style.RESET_ALL}"
R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
B = Fore.BLUE
C = Fore.CYAN

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BugBountyRecon/1.0; +https://yourblog)",
    "X-BugBounty": "Recon-Scanner",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}
TIMEOUT = aiohttp.ClientTimeout(total=10)

# ---------- UTILS ----------
def load_config(path="config.json"):
    if Path(path).exists():
        return json.loads(Path(path).read_text())
    return {}

def save_json(obj, path):
    Path(path).write_text(json.dumps(obj, indent=2))

def extract_params(url: str) -> List[str]:
    parsed = urllib.parse.urlparse(url)
    return [k for k, _ in urllib.parse.parse_qsl(parsed.query)]

async def dns_resolve(domain: str, resolver: aiodns.DNSResolver) -> bool:
    try:
        await resolver.gethostbyname(domain, socket.AF_INET)
        return True
    except Exception:
        return False

async def fetch_crtsh(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains: Set[str] = set()
    try:
        async with session.get(url, headers=HEADERS, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                subdomains = {entry["name_value"].lower().strip() for entry in data if "name_value" in entry}
    except Exception as e:
        print(colorama_color(Y, f"[warn] crt.sh error: {e}"))
    return subdomains

# async def subfinder(domain: str, session: aiohttp.ClientSession) -> Set[str]:
#     return await fetch_crtsh(domain, session)

async def check_cors_misconfiguration(url: str, session: aiohttp.ClientSession) -> Dict:
    headers = {**HEADERS, "Origin": "https://evil.com"}
    try:
        async with session.get(url, headers=headers, timeout=TIMEOUT) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "https://evil.com" or acao == "*":
                return {"type": "CORS", "url": url, "detail": f"ACAO: {acao}"}
    except Exception:
        pass
    return {}


async def check_open_redirect(url: str, session: aiohttp.ClientSession) -> Dict:
    payloads = ["https://evil.com", "//evil.com", "/\\evil.com"]
    for p in payloads:
        test_url = f"{url.rstrip('/')}/?next={p}&url={p}&redirect={p}&return={p}"
        try:
            async with session.get(test_url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False) as resp:
                loc = resp.headers.get("Location", "")
                if "evil.com" in loc:
                    return {"type": "OpenRedirect", "url": test_url, "detail": f"redirects to {loc}"}
        except Exception:
            pass
    return {}


async def check_xss_reflection(url: str, session: aiohttp.ClientSession) -> Dict:
    payload = "bbr<xss>"
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_qs = [(k, payload) for k, _ in qs]
    if not new_qs:
        return {}
    test_url = parsed._replace(query=urllib.parse.urlencode(new_qs)).geturl()
    try:
        async with session.get(test_url, headers=HEADERS, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                text = await resp.text()
                if payload in text:
                    return {"type": "XSS (reflected)", "url": test_url, "detail": f"param reflected: {payload}"}
    except Exception:
        pass
    return {}


async def check_security_headers(url: str, session: aiohttp.ClientSession) -> List[Dict]:
    try:
        async with session.get(url, headers=HEADERS, timeout=TIMEOUT) as resp:
            miss = []
            headers = {k.lower(): v for k, v in resp.headers.items()}
            if "content-security-policy" not in headers:
                miss.append({"type": "Missing CSP", "url": url})
            if "strict-transport-security" not in headers:
                miss.append({"type": "Missing HSTS", "url": url})
            if "x-content-type-options" not in headers:
                miss.append({"type": "Missing X-Content-Type-Options", "url": url})
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                miss.append({"type": "Missing Clickjacking Protection", "url": url})
            return miss
    except Exception:
        return []
COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]
COMMON_PATHS = [
    "admin",
    "backup",
    "config",
    "api",
    "v1",
    "v2",
    "test",
    "dev",
    "staging",
    "phpmyadmin",
    ".git",
    ".env",
    "robots.txt",
    "sitemap.xml",
    "uploads",
]


def extract_ip(domain: str) -> Sequence[str]:  
    try:
        ans = socket.getaddrinfo(domain, None)
        return list({r[4][0] for r in ans})
    except Exception:
        return []


async def tcp_scan(host: str, port: int, timeout: float = 1.0) -> bool:
    
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def fetch_text(url: str, session: aiohttp.ClientSession) -> str:
    try:
        async with session.get(url, headers=HEADERS, timeout=TIMEOUT) as r:
            return await r.text() if r.status == 200 else ""
    except Exception:
        return ""

async def fetch_crtsh_wildcard(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs: Set[str] = set()
    try:
        async with session.get(url, headers=HEADERS, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                subs = {
                    entry["name_value"].lower().strip()
                    for entry in data
                    if "name_value" in entry
                }
    except Exception:
        pass
    return subs


async def fetch_sublist3r(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    """Scrape sublist3r (tidak memerlukan API key)."""
    url = f"https://api.sublist3r.com/search.php?domain={domain}"
    subs: Set[str] = set()
    try:
        async with session.get(url, headers=HEADERS, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                subs = {sub.lower().strip() for sub in data}
    except Exception:
        # fallback: scrape dari halaman web sublist3r
        url2 = f"https://tool.sublist3r.com/search.php?domain={domain}"
        txt = await fetch_text(url2, session)
        subs = set(re.findall(rf"([a-z0-9]+\.{re.escape(domain)})", txt, re.I))
    return subs


# ---------- PERLUAS SUBFINDER ----------
async def subfinder(
    domain: str, session: aiohttp.ClientSession, deep: bool = False
) -> Set[str]:
    subs: Set[str] = set()
    # 1. crt.sh
    subs.update(await fetch_crtsh(domain, session))
    if deep:
        # 2. crt.sh wildcard
        subs.update(await fetch_crtsh_wildcard(domain, session))
        # 3. sublist3r scrape
        subs.update(await fetch_sublist3r(domain, session))
    # 4. tambah wordlist otomatis (selalu)
    wordlist = [
        "www",
        "mail",
        "ftp",
        "admin",
        "blog",
        "shop",
        "api",
        "app",
        "portal",
        "webmail",
        "dev",
        "test",
        "staging",
        "beta",
        "demo",
        "vpn",
        "git",
        "gitlab",
        "jenkins",
    ]
    subs.update(f"{w}.{domain}" for w in wordlist)
    return subs

async def scan_ip_ports(ip: str, ports: List[int]) -> List[int]:
    tasks = [tcp_scan(ip, p) for p in ports]
    results = await asyncio.gather(*tasks)
    return [p for p, ok in zip(ports, results) if ok]
async def fuzz_common_paths(
    base_url: str, session: aiohttp.ClientSession
) -> List[Dict]:
    found = []
    for path in COMMON_PATHS:
        url = f"{base_url.rstrip('/')}/{path}"
        try:
            async with session.head(url, headers=HEADERS, timeout=TIMEOUT) as r:
                if r.status in (200, 401, 403):
                    found.append(
                        {
                            "type": f"Interesting path ({r.status})",
                            "url": url,
                            "detail": f"{path} -> {r.status}",
                        }
                    )
        except Exception:
            pass
    return found

async def detect_tech(url: str, session: aiohttp.ClientSession) -> Dict:
    tech = {}
    try:
        async with session.get(url, headers=HEADERS, timeout=TIMEOUT) as r:
            txt = await r.text()
            headers = {k.lower(): v for k, v in r.headers.items()}
            # server
            if "server" in headers:
                tech["server"] = headers["server"]
            # x-powered-by
            if "x-powered-by" in headers:
                tech["x-powered-by"] = headers["x-powered-by"]
            # teks
            if "wordpress" in txt.lower():
                tech["cms"] = "WordPress"
            elif "drupal" in txt.lower():
                tech["cms"] = "Drupal"
            elif "joomla" in txt.lower():
                tech["cms"] = "Joomla"
            elif "django" in txt.lower():
                tech["framework"] = "Django"
            elif "laravel" in txt.lower():
                tech["framework"] = "Laravel"
            elif "express" in txt.lower():
                tech["framework"] = "Express"
            # via header
            if "via" in headers:
                tech["proxy"] = headers["via"]
    except Exception:
        pass
    return tech
async def worker_subdomain(
    domain: str,
    sub: str,
    resolver: aiodns.DNSResolver,
    session: aiohttp.ClientSession,
    out: Dict,
    deep: bool,
):
    if not await dns_resolve(sub, resolver):
        return
    print(colorama_color(C, f"[sub] {sub}"))
    out["subdomains"].append(sub)

    base_url = f"https://{sub}"
    tasks = [
        check_cors_misconfiguration(base_url, session),
        check_open_redirect(base_url, session),
        check_security_headers(base_url, session),
    ]
    if deep:
        tasks.append(fuzz_common_paths(base_url, session))
    results = await asyncio.gather(*tasks)
    for r in results:
        if isinstance(r, list):
            for item in r:
                if item:
                    out["vulns"].append(item)
        elif r:
            out["vulns"].append(r)
    if deep:
        ips = extract_ip(sub)
        if ips:
            out.setdefault("ips", {}).setdefault(sub, [])
            out.setdefault("open_ports", {}).setdefault(sub, [])
            for ip in ips:
                out["ips"][sub].append(ip)
                open_ports = await scan_ip_ports(ip, COMMON_PORTS)
                if open_ports:
                    out["open_ports"][sub].extend(open_ports)
                    print(colorama_color(Y, f"[ports] {sub} ({ip}) -> {open_ports}"))
    tech = await detect_tech(base_url, session)
    if tech:
        out.setdefault("tech", {}).setdefault(sub, tech)


async def main(target: str, fast: bool, threads: int, deep: bool):
    resolver = aiodns.DNSResolver()
    out_dir = Path("out") / target
    out_dir.mkdir(parents=True, exist_ok=True)
    out = {"subdomains": [], "vulns": [], "ips": {}, "open_ports": {}, "tech": {}}

    connector = aiohttp.TCPConnector(ssl=False, limit=threads)
    session = aiohttp.ClientSession(connector=connector, timeout=TIMEOUT)

    try:
        print(colorama_color(B, "[*] Collecting subdomains..."))
        subs = await subfinder(target, session, deep=deep)
        if fast and len(subs) > 100:
            subs = list(subs)[:100]
        print(colorama_color(G, f"[+] Got {len(subs)} subdomains"))

        if not subs:
            wordlist = [
                "www",
                "mail",
                "ftp",
                "admin",
                "blog",
                "shop",
                "api",
                "app",
                "portal",
                "webmail",
            ]
            subs = {f"{w}.{target}" for w in wordlist}
            print(colorama_color(Y, "[!] semua sumber kosong – fallback wordlist"))

        print(colorama_color(B, "[*] Probing live hosts + vuln scan..."))
        sem = asyncio.Semaphore(threads)

        async def sem_worker(sub):
            async with sem:
                await worker_subdomain(target, sub, resolver, session, out, deep)

        await asyncio.gather(*(sem_worker(s) for s in subs))

    finally:
        await session.close()
        connector.close()
    save_json(out, out_dir / "vulns.json")
    Path(out_dir / "subdomains.txt").write_text("\n".join(out["subdomains"]))
    if out["ips"]:
        with open(out_dir / "ips.txt", "w") as f:
            for sub, ips in out["ips"].items():
                f.write(f"{sub} -> {', '.join(ips)}\n")
    if out["open_ports"]:
        with open(out_dir / "open_ports.txt", "w") as f:
            for sub, ports in out["open_ports"].items():
                f.write(f"{sub} -> {', '.join(map(str, ports))}\n")
    if out["tech"]:
        save_json(out["tech"], out_dir / "tech.json")
    generate_html(out, out_dir / "report.html")
    print(colorama_color(G, f"[+] Selesai! Output di {out_dir}"))


def generate_html(data: Dict, path: Path):
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>BBR Report</title>
    <style>body{{font-family:Arial;margin:40px}}.vuln{{background:#ffecec;border-left:5px solid #c20000;padding:10px;margin:10px 0}}
    .sub{{background:#ecffec;border-left:5px solid #008000;padding:5px;margin:3px 0}}</style></head><body>
    <h1>Bug-Bounty Recon Report</h1>
    <h2>Subdomains ({len(data["subdomains"])})</h2>"""
    for s in data["subdomains"]:
        html += f'<div class="sub">{s}</div>'
    html += f'<h2>Vulns ({len(data["vulns"])})</h2>'
    for v in data["vulns"]:
        html += f'<div class="vuln"><strong>{v["type"]}</strong> on <a href="{v["url"]}" target="_blank">{v["url"]}</a><br>{v.get("detail","")}</div>'
    html += "</body></html>"
    Path(path).write_text(html)

if __name__ == "__main__":
    # import sys, asyncio
    # if __name__ == "__main__":
        # asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    parser = argparse.ArgumentParser(description="Bug-Bounty Recon + Light Scanner")
    parser.add_argument("-t", "--target", help="single target domain")
    parser.add_argument("-f", "--file", help="file berisi daftar domain (scope)")
    parser.add_argument("--fast", action="store_true", help="mode cepat, lebih sedikit request")
    parser.add_argument("--threads", type=int, default=30)
    parser.add_argument(
        "--deep",
        action="store_true",
        help="recon mendalam (port scan, path fuzz, tech detect)",
    )
    args = parser.parse_args()

    if not args.target and not args.file:
        parser.print_help()
        sys.exit(1)

    targets = [args.target] if args.target else Path(args.file).read_text().splitlines()
    for tgt in targets:
        tgt = tgt.strip()
        if not tgt:
            continue
        print(colorama_color(B, f"\n>>> Starting recon for {tgt}"))
        asyncio.run(main(tgt, args.fast, args.threads, args.deep))
