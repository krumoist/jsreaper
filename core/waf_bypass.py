from __future__ import annotations
import re
import time
import random
import threading
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    raise ImportError("pip install requests")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.40 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
    "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
    "Apache-HttpClient/4.5.14 (Java/17.0.8)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "en,en-US;q=0.9",
    "en-AU,en;q=0.9",
    "en-CA,en;q=0.9,fr-CA;q=0.8",
    "en-US,en;q=0.5",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en;q=0.8",
]

SEC_CH_UA_STRINGS = [
    '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    '"Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="8"',
    '"Chromium";v="122", "Google Chrome";v="122", "Not-A.Brand";v="24"',
    '"Chromium";v="121", "Google Chrome";v="121", "Not-A.Brand";v="9"',
    '"Microsoft Edge";v="124", "Chromium";v="124", "Not-A.Brand";v="99"',
]

IP_SPOOF_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP",
    "True-Client-IP", "X-Originating-IP", "X-Remote-IP",
    "X-Client-IP", "Forwarded", "X-Cluster-Client-IP",
    "X-ProxyUser-Ip", "Via",
]

SPOOF_IPS = [
    "8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1",
    "198.51.100.1", "203.0.113.5", "192.0.2.100",
    "37.19.220.129", "45.152.64.33", "185.220.101.45",
    "104.28.20.55", "104.26.10.33", "172.67.68.228",
]

CLOUDFLARE_BYPASS_HEADERS = {
    "CF-IPCountry": random.choice(["US", "GB", "DE", "CA", "AU", "FR", "NL"]),
    "CDN-Loop": "cloudflare",
}

REFERERS = [
    "https://www.google.com/",
    "https://google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.reddit.com/",
    "https://t.co/",
    "https://twitter.com/",
    "https://www.linkedin.com/",
]


def get_random_ua() -> str:
    return random.choice(USER_AGENTS)


def _is_chrome(ua: str) -> bool:
    return "Chrome" in ua and "Edg" not in ua and "OPR" not in ua and "bot" not in ua.lower()


def _is_firefox(ua: str) -> bool:
    return "Firefox" in ua

def _is_mobile(ua: str) -> bool:
    return any(s in ua for s in ["Mobile", "Android", "iPhone", "iPad"])


def _platform_hint(ua: str) -> str:
    if "Android" in ua:    return '"Android"'
    if "iPhone" in ua:     return '"iOS"'
    if "iPad" in ua:       return '"iOS"'
    if "Mac" in ua:        return '"macOS"'
    if "Linux" in ua:      return '"Linux"'
    return '"Windows"'


def build_browser_headers(ua: str, referer: str = "", spoof_ip: bool = False,
                          include_cf_bypass: bool = False) -> dict:
    headers: dict[str, str] = {
        "User-Agent": ua,
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }

    if _is_chrome(ua):
        is_js_req = random.random() < 0.35
        if is_js_req:
            headers["Accept"] = "*/*"
            headers["Sec-Fetch-Site"] = "same-origin"
            headers["Sec-Fetch-Mode"] = "cors"
            headers["Sec-Fetch-Dest"] = "script"
        else:
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-User"] = "?1"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Upgrade-Insecure-Requests"] = "1"
        headers["Sec-Ch-Ua"] = random.choice(SEC_CH_UA_STRINGS)
        headers["Sec-Ch-Ua-Mobile"] = "?1" if _is_mobile(ua) else "?0"
        headers["Sec-Ch-Ua-Platform"] = _platform_hint(ua)
        if random.random() < 0.4:
            headers["Sec-Ch-Ua-Full-Version-List"] = headers["Sec-Ch-Ua"]
        if random.random() < 0.3:
            headers["Sec-Ch-Prefers-Color-Scheme"] = random.choice(["dark", "light"])
        if random.random() < 0.2:
            headers["Sec-Ch-Ua-Arch"] = '"x86"'
            headers["Sec-Ch-Ua-Bitness"] = '"64"'
    elif _is_firefox(ua):
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        headers["Sec-Fetch-Site"] = "none"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-User"] = "?1"
        headers["Sec-Fetch-Dest"] = "document"
        headers["Upgrade-Insecure-Requests"] = "1"
        headers["TE"] = "trailers"
    else:
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

    if referer:
        headers["Referer"] = referer
    elif random.random() < 0.25:
        headers["Referer"] = random.choice(REFERERS)

    if random.random() < 0.15:
        headers["DNT"] = "1"

    if random.random() < 0.1:
        headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])

    if spoof_ip:
        fake_ip = random.choice(SPOOF_IPS)
        chosen_hdrs = random.sample(IP_SPOOF_HEADERS, k=random.randint(1, 3))
        for h in chosen_hdrs:
            if h == "Forwarded":
                headers[h] = f"for={fake_ip};proto=https;host=target.com"
            elif h == "Via":
                headers[h] = f"1.1 {fake_ip}"
            else:
                if random.random() < 0.3:
                    chain = f"{random.choice(SPOOF_IPS)}, {fake_ip}"
                    headers[h] = chain
                else:
                    headers[h] = fake_ip

    if include_cf_bypass:
        headers["CF-IPCountry"] = random.choice(["US", "GB", "DE", "CA", "AU", "NL"])

    return headers


class RateLimitBackoff:
    def __init__(self, max_retries: int = 6, base_delay: float = 2.0):
        self.max_retries = max_retries
        self.base_delay  = base_delay
        self._hits       = 0
        self._lock       = threading.Lock()
        self._total_429  = 0
        self._total_403  = 0

    def hit(self, status: int = 429):
        with self._lock:
            self._hits += 1
            if status == 429: self._total_429 += 1
            if status == 403: self._total_403 += 1

    def is_blocked(self) -> bool:
        with self._lock:
            return self._hits >= self.max_retries

    def wait(self, attempt: int = 0):
        with self._lock:
            base = self.base_delay * (2 ** min(attempt, 7))
        jitter = random.uniform(0, base * 0.5)
        time.sleep(base + jitter)

    def reset(self):
        with self._lock:
            self._hits = max(0, self._hits - 1)

    @property
    def stats(self) -> dict:
        with self._lock:
            return {"429": self._total_429, "403": self._total_403, "hits": self._hits}


class WAFSession(requests.Session):
    def __init__(self, args, base_url: str = ""):
        super().__init__()
        self.args         = args
        self.base_url     = base_url
        self._ua          = get_random_ua()
        self._rotate      = getattr(args, "rotate_ua", False)
        self._spoof_ip    = getattr(args, "spoof_ip", False)
        self._cf_bypass   = getattr(args, "cf_bypass", False)
        self._min_delay   = getattr(args, "delay", 0.0)
        self._jitter      = getattr(args, "jitter", 0.3)
        self._last_url    = base_url
        self._req_count   = 0
        self._req_lock    = threading.Lock()
        self._backoff     = RateLimitBackoff(
            max_retries=getattr(args, "max_retries", 6),
            base_delay=getattr(args, "backoff_delay", 2.0),
        )

        retry = Retry(
            total=2, backoff_factor=0.4,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
        self.mount("http://", adapter)
        self.mount("https://", adapter)
        self.verify = not getattr(args, "no_ssl_verify", False)

        if getattr(args, "headers", None):
            for h in args.headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    self.headers[k.strip()] = v.strip()

        if getattr(args, "cookies", None):
            for pair in args.cookies.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    self.cookies.set(k.strip(), v.strip())

        if getattr(args, "proxy", None):
            self.proxies = {"http": args.proxy, "https": args.proxy}

    def _pick_ua(self) -> str:
        if self._rotate:
            return get_random_ua()
        with self._req_lock:
            self._req_count += 1
            if self._req_count % 40 == 0:
                self._ua = get_random_ua()
        return self._ua

    def _inject_headers(self, kwargs: dict, url: str):
        ua = self._pick_ua()
        browser_hdrs = build_browser_headers(
            ua, referer=self._last_url,
            spoof_ip=self._spoof_ip,
            include_cf_bypass=self._cf_bypass,
        )
        existing = kwargs.get("headers") or {}
        kwargs["headers"] = {**browser_hdrs, **existing}
        self._last_url = url

    def request(self, method, url, **kwargs):
        self._inject_headers(kwargs, url)

        total_delay = self._min_delay + random.uniform(0, self._jitter)
        if total_delay > 0:
            time.sleep(total_delay)

        if self._backoff.is_blocked():
            return None

        for attempt in range(5):
            try:
                resp = super().request(method, url, **kwargs)

                if resp.status_code == 429:
                    self._backoff.hit(429)
                    retry_after = int(resp.headers.get("Retry-After", 0))
                    self._backoff.wait(max(attempt, retry_after // 2))
                    kwargs["headers"]["User-Agent"] = get_random_ua()
                    continue

                if resp.status_code == 403:
                    self._backoff.hit(403)
                    if attempt < 3:
                        self._backoff.wait(attempt)
                        new_ua = get_random_ua()
                        kwargs["headers"] = build_browser_headers(
                            new_ua, spoof_ip=self._spoof_ip,
                            include_cf_bypass=True,
                        )
                        continue

                if resp.status_code in (200, 201, 204, 206, 301, 302, 304):
                    self._backoff.reset()

                return resp

            except requests.exceptions.SSLError:
                kwargs["verify"] = False
                continue
            except requests.exceptions.ConnectionError:
                if attempt < 3:
                    time.sleep(1.5 * (attempt + 1))
                continue
            except Exception:
                break

        return None


def build_waf_session(args, base_url: str = "") -> requests.Session:
    if getattr(args, "waf_bypass", False):
        return WAFSession(args, base_url=base_url)

    session = requests.Session()
    retry = Retry(
        total=3, backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=30, pool_maxsize=30)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    ua = getattr(args, "user_agent", None) or get_random_ua()
    session.headers.update({
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate, br",
    })

    if getattr(args, "headers", None):
        for h in args.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                session.headers[k.strip()] = v.strip()

    if getattr(args, "cookies", None):
        for pair in args.cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                session.cookies.set(k.strip(), v.strip())

    if getattr(args, "proxy", None):
        session.proxies = {"http": args.proxy, "https": args.proxy}

    session.verify = not getattr(args, "no_ssl_verify", False)
    return session
