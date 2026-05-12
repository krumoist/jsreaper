from __future__ import annotations
import re
import json
import threading
from urllib.parse import urlparse, quote

try:
    import requests
except ImportError:
    raise ImportError("pip install requests")

URLSCAN_API      = "https://urlscan.io/api/v1/search/"
COMMONCRAWL_CDX  = "https://index.commoncrawl.org/CC-MAIN-2024-10-index"
CERTSH_API       = "https://crt.sh/?q=%25.{}&output=json"
OTX_API          = "https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list?limit=100"
OTX_PASSIVE_DNS  = "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns"
WAYBACK_CDX      = "https://web.archive.org/cdx/search/cdx?url={}&output=json&matchType=domain&limit=500&fl=original&filter=statuscode:200"
GITHUB_SEARCH    = "https://api.github.com/search/code?q={}&per_page=50"
RAPIDDNS         = "https://rapiddns.io/subdomain/{}?full=1"
HACKERTARGET     = "https://api.hackertarget.com/hostsearch/?q={}"
THREATFOX        = "https://threatfox-api.abuse.ch/api/v1/"

TIMEOUT = 12

JS_RE = re.compile(r"""(?:src|url)\s*['"]?\s*:\s*['"]?(https?://[^\s'"`,]+\.(?:js|mjs|cjs))""", re.I)
URL_RE = re.compile(r"""https?://[^\s'"`,\]>]+""")


def _safe_get(session, url: str, **kwargs) -> requests.Response | None:
    try:
        r = session.get(url, timeout=TIMEOUT, **kwargs)
        if r and r.status_code == 200:
            return r
    except Exception:
        pass
    return None


def _urlscan(domain: str, session) -> list[str]:
    found: set[str] = set()
    r = _safe_get(session, URLSCAN_API, params={"q": f"domain:{domain}", "size": 200})
    if not r:
        return []
    try:
        data = r.json()
        for hit in data.get("results", []):
            page_url = hit.get("page", {}).get("url", "")
            if page_url:
                found.add(page_url)
            for link in hit.get("links", []):
                href = link.get("href", "")
                if href.endswith((".js", ".mjs")):
                    found.add(href)
            for script in hit.get("lists", {}).get("scripts", []):
                found.add(script)
    except Exception:
        pass
    return [u for u in found if domain in u]


def _commoncrawl(domain: str, session) -> list[str]:
    found: set[str] = set()
    for suffix in ["", ".js", ".mjs"]:
        r = _safe_get(session, COMMONCRAWL_CDX, params={
            "url": f"*.{domain}{suffix}/*",
            "output": "json", "limit": 500, "fl": "url",
            "filter": "statuscode:200",
            "matchType": "domain",
        })
        if not r:
            continue
        lines = r.text.strip().splitlines()
        for line in lines[1:]:
            try:
                rec = json.loads(line)
                url = rec.get("url") or (rec[0] if isinstance(rec, list) else "")
                if url:
                    found.add(url)
            except Exception:
                if "http" in line:
                    for m in URL_RE.finditer(line):
                        found.add(m.group(0))
    return sorted(found)


def _wayback(domain: str, session) -> list[str]:
    found: set[str] = set()
    url = WAYBACK_CDX.format(f"*.{domain}/*.js")
    r = _safe_get(session, url)
    if not r:
        return []
    try:
        data = r.json()
        for row in data[1:]:
            if row:
                found.add(row[0])
    except Exception:
        pass
    return sorted(found)


def _certsh(domain: str, session) -> list[str]:
    subdomains: set[str] = set()
    r = _safe_get(session, CERTSH_API.format(domain))
    if not r:
        return []
    try:
        for entry in r.json():
            for name in re.split(r"[\n,]", entry.get("name_value", "")):
                name = name.strip().lstrip("*.")
                if name and domain in name and " " not in name and len(name) < 200:
                    subdomains.add(name.lower())
    except Exception:
        pass
    return sorted(subdomains)


def _hackertarget(domain: str, session) -> list[str]:
    subdomains: set[str] = set()
    r = _safe_get(session, HACKERTARGET.format(domain))
    if not r:
        return []
    for line in r.text.splitlines():
        parts = line.split(",")
        if parts:
            host = parts[0].strip()
            if host and domain in host and len(host) < 100:
                subdomains.add(host.lower())
    return sorted(subdomains)


def _otx(domain: str, session) -> tuple[list[str], list[str]]:
    urls: set[str]  = set()
    subs: set[str]  = set()
    r = _safe_get(session, OTX_API.format(domain))
    if r:
        try:
            for entry in r.json().get("url_list", []):
                u = entry.get("url", "")
                if u and domain in u:
                    urls.add(u)
        except Exception:
            pass
    r2 = _safe_get(session, OTX_PASSIVE_DNS.format(domain))
    if r2:
        try:
            for entry in r2.json().get("passive_dns", []):
                h = entry.get("hostname", "")
                if h and domain in h and len(h) < 100:
                    subs.add(h.lower())
        except Exception:
            pass
    return sorted(urls), sorted(subs)


def _github_search(domain: str, session) -> list[str]:
    found: set[str] = set()
    queries = [f'"{domain}"', f'site:{domain}', f'"{domain}" extension:js',
               f'"{domain}" extension:env', f'"{domain}" api_key']
    for q in queries[:2]:
        r = _safe_get(session, GITHUB_SEARCH.format(quote(q)))
        if not r:
            continue
        try:
            for item in r.json().get("items", []):
                url = item.get("html_url", "")
                if url:
                    found.add(url)
        except Exception:
            pass
    return sorted(found)


def _probe_subdomains(subdomains: list[str], session) -> list[str]:
    live: list[str]  = []
    lock = threading.Lock()

    def probe(host: str):
        for scheme in ["https", "http"]:
            try:
                r = session.head(f"{scheme}://{host}", timeout=5, allow_redirects=True)
                if r and r.status_code < 500:
                    with lock:
                        live.append(f"{scheme}://{host}")
                    return
            except Exception:
                pass

    threads = [threading.Thread(target=probe, args=(h,), daemon=True) for h in subdomains[:80]]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=8)
    return live


def _discover_js_from_pages(live_origins: list[str], session) -> list[str]:
    found: set[str] = set()
    for origin in live_origins[:20]:
        try:
            r = _safe_get(session, origin)
            if not r:
                continue
            for m in re.finditer(r"""<script[^>]+src\s*=\s*["']([^"']+\.(?:js|mjs))["']""", r.text, re.I):
                from urllib.parse import urljoin
                found.add(urljoin(origin, m.group(1)))
        except Exception:
            pass
    return sorted(found)


def gather_intelligence(domain: str, session, threads: int = 6) -> dict:
    results: dict = {
        "js_urls":     [],
        "subdomains":  [],
        "raw_urls":    [],
        "github_hits": [],
    }
    lock  = threading.Lock()

    def run(fn, key, *args):
        try:
            val = fn(*args)
            with lock:
                if isinstance(val, tuple):
                    results.setdefault("js_urls", [])
                    results["js_urls"].extend(v for v in val[0] if v not in results["js_urls"])
                    results["subdomains"].extend(v for v in val[1] if v not in results["subdomains"])
                else:
                    existing = results.get(key, [])
                    for v in val:
                        if v not in existing:
                            existing.append(v)
                    results[key] = existing
        except Exception:
            pass

    tasks = [
        (threading.Thread(target=run, args=(_urlscan,     "js_urls",    domain, session), daemon=True)),
        (threading.Thread(target=run, args=(_commoncrawl, "js_urls",    domain, session), daemon=True)),
        (threading.Thread(target=run, args=(_wayback,     "js_urls",    domain, session), daemon=True)),
        (threading.Thread(target=run, args=(_certsh,      "subdomains", domain, session), daemon=True)),
        (threading.Thread(target=run, args=(_hackertarget,"subdomains", domain, session), daemon=True)),
        (threading.Thread(target=run, args=(_otx,         "js_urls",    domain, session), daemon=True)),
        (threading.Thread(target=run, args=(_github_search,"github_hits",domain, session), daemon=True)),
    ]
    for t in tasks: t.start()
    for t in tasks: t.join(timeout=25)

    if results["subdomains"]:
        live = _probe_subdomains(results["subdomains"], session)
        extra_js = _discover_js_from_pages(live, session)
        results["js_urls"].extend(u for u in extra_js if u not in results["js_urls"])

    results["js_urls"]    = sorted(set(results["js_urls"]))
    results["subdomains"] = sorted(set(results["subdomains"]))

    return results
