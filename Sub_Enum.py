#!/usr/bin/env python3
"""
subenum.py — subdomain enumeration utility
Author: ChatGPT (security expert role)
License: Use on domains you own or have permission to test ONLY.
"""

import concurrent.futures
import json
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Set, Dict, Optional

import requests
import tldextract
from bs4 import BeautifulSoup

try:
    import dns.resolver
    DNSPY_AVAILABLE = True
except Exception:
    DNSPY_AVAILABLE = False

USER_AGENT = "Mozilla/5.0 (compatible; subenum/1.0; +https://example.local/)"
REQUESTS_TIMEOUT = 15
RATE_LIMIT_SLEEP = 1.0

# ---------- Helpers ----------
def now_ts():
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def domain_match(host: str, target_domain: str) -> bool:
    host = host.lower().rstrip('.')
    target = target_domain.lower().rstrip('.')
    if host == target:
        return True
    return host.endswith("." + target)


import re
HOST_RE = re.compile(r"(?i)([a-z0-9\-_]+(?:\.[a-z0-9\-_]+)+)")

def extract_hostnames_from_text(text: str) -> Set[str]:
    found = set()
    for m in HOST_RE.findall(text):
        h = m.rstrip('.,:;\"\'()[]{}<>')
        if any(c.isalpha() for c in h):
            found.add(h.lower())
    return found

# ---------- Engines ----------
def fetch_crtsh(domain: str) -> Set[str]:
    print("[*] crt.sh lookup...")
    out = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=REQUESTS_TIMEOUT)
        time.sleep(RATE_LIMIT_SLEEP)
        if r.status_code == 200:
            for item in r.json():
                name = item.get("name_value") or item.get("common_name")
                if name:
                    for n in str(name).splitlines():
                        out.add(n.strip().lower())
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
    return out


def fetch_wayback(domain: str) -> Set[str]:
    print("[*] Wayback lookup...")
    out = set()
    url = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "filter": "statuscode:200",
        "limit": "10000"
    }
    try:
        r = requests.get(url, params=params, headers={"User-Agent": USER_AGENT}, timeout=REQUESTS_TIMEOUT)
        time.sleep(RATE_LIMIT_SLEEP)
        if r.status_code == 200:
            try:
                payload = r.json()
                if isinstance(payload, list):
                    for entry in payload:
                        if isinstance(entry, list) and entry:
                            for h in extract_hostnames_from_text(entry[0]):
                                out.add(h)
            except Exception:
                for line in r.text.splitlines():
                    for h in extract_hostnames_from_text(line):
                        out.add(h)
    except Exception as e:
        print(f"[!] Wayback error: {e}")
    return out


def fetch_duckduckgo(domain: str, pages: int = 3) -> Set[str]:
    print("[*] DuckDuckGo scraping...")
    out = set()
    base = "https://html.duckduckgo.com/html/"
    session = requests.Session()
    for p in range(0, pages):
        params = {"q": f"site:*.{domain} -www.{domain}", "s": str(p*50)}
        try:
            r = session.post(base, data=params, headers={"User-Agent": USER_AGENT}, timeout=REQUESTS_TIMEOUT)
            time.sleep(RATE_LIMIT_SLEEP)
            if r.status_code != 200:
                break
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                for h in extract_hostnames_from_text(a["href"]):
                    out.add(h)
        except Exception as e:
            print(f"[!] DuckDuckGo error: {e}")
            break
    return out

# ---------- DNS ----------
def resolve_host(host: str, timeout: float = 5.0) -> Dict[str, Optional[list]]:
    result = {"A": None, "CNAME": None}
    try:
        if DNSPY_AVAILABLE:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            try:
                answers = resolver.resolve(host, "A")
                result["A"] = [a.address for a in answers]
            except Exception:
                pass
            try:
                answers = resolver.resolve(host, "CNAME")
                result["CNAME"] = [str(r.target).rstrip('.') for r in answers]
            except Exception:
                pass
        else:
            try:
                _, _, addrs = socket.gethostbyname_ex(host)
                result["A"] = addrs
            except Exception:
                pass
    except Exception:
        pass
    return result

# ---------- Main ----------
def enumerate_subdomains(domain: str) -> Dict[str, Dict]:
    found = set()

    use_crt = input("Use crt.sh? (y/n): ").strip().lower() == "y"
    use_way = input("Use Wayback? (y/n): ").strip().lower() == "y"
    use_duck = input("Use DuckDuckGo? (y/n): ").strip().lower() == "y"

    if use_crt:
        found |= fetch_crtsh(domain)
    if use_way:
        found |= fetch_wayback(domain)
    if use_duck:
        found |= fetch_duckduckgo(domain)

    filtered = {h.rstrip('.') for h in found if domain_match(h, domain)}
    normalized = {h[2:] if h.startswith("*.") else h for h in filtered}

    results = {}
    print(f"[*] Resolving {len(normalized)} candidates...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as exe:
        future_map = {exe.submit(resolve_host, h): h for h in normalized}
        for fut in concurrent.futures.as_completed(future_map):
            host = future_map[fut]
            try:
                results[host] = fut.result()
            except Exception:
                results[host] = {"A": None, "CNAME": None}

    return results


def save_results(domain: str, results: Dict[str, Dict]):
    ts = now_ts()
    outdir = Path(f"subenum_results_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)
    txtpath = outdir / f"{domain}_subdomains.txt"
    with open(txtpath, "w") as f:
        for host, info in sorted(results.items()):
            f.write(f"{host}\tA={info.get('A')}\tCNAME={info.get('CNAME')}\n")
    print(f"[*] Results saved to {txtpath}")


def main():
    print("=== Subdomain Enumeration Tool ===")
    domain = input("Enter target domain (e.g. example.com): ").strip()
    if not domain:
        sys.exit("No domain given.")

    results = enumerate_subdomains(domain)
    alive = {h: info for h, info in results.items() if info.get("A")}

    print(f"\n[*] Found {len(results)} total subdomains, {len(alive)} with A records.\n")
    for h, info in sorted(alive.items()):
        print(f"{h}\tA={info.get('A')}\tCNAME={info.get('CNAME')}")

    if input("\nSave results to file? (y/n): ").strip().lower() == "y":
        save_results(domain, results)


if __name__ == "__main__":
    main()
      
