from __future__ import annotations
import re
import json
import time
import random
import threading
from urllib.parse import urljoin, urlparse
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    raise ImportError("pip install requests")

SCRIPT_SRC_RE      = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>""", re.I)
MODULEPRELOAD_RE   = re.compile(r"""<link[^>]+rel\s*=\s*["'](?:modulepreload|preload)["'][^>]+href\s*=\s*["']([^"']+\.(?:js|mjs))["']""", re.I)
IMPORTMAP_RE       = re.compile(r"""<script[^>]+type\s*=\s*["']importmap["'][^>]*>(.*?)</script>""", re.I | re.DOTALL)
INLINE_SCRIPT_RE   = re.compile(r"""<script(?![^>]+src\s*=)[^>]*>(.*?)</script>""", re.I | re.DOTALL)
LINK_RE            = re.compile(r"""<a[^>]+href\s*=\s*["']([^"'#?]+)["']""", re.I)
NEXT_DATA_RE       = re.compile(r"""<script[^>]+id\s*=\s*["']__NEXT_DATA__["'][^>]*>\s*(\{.*?\})\s*</script>""", re.DOTALL)
NEXT_BUILD_MF_RE   = re.compile(r"""/_next/static/[A-Za-z0-9_\-]+/_buildManifest\.js""")
NEXT_CHUNK_RE      = re.compile(r"""/_next/static/(?:chunks|css|media)/[^\s"'`,\)]+""")
JS_IN_JS_RE        = re.compile(r"""(?:import|require|fetch|src|from)\s*\(?\s*["'`]([^"'`\s]+\.(?:js|mjs|cjs)(?:\?[^"'`\s]*)?)["'`]""", re.I)
WEBPACK_CHUNK_MAP  = re.compile(r"""["']([a-f0-9]{8,20})["']\s*:\s*["']([a-zA-Z0-9.\-_]+)["']""")
TURBOPACK_CHUNK_RE = re.compile(r"""__turbopack_load__\s*\(\s*["']([^"']+\.js)["']""")
RSC_PUSH_RE        = re.compile(r"""self\.__next_f\.push\(\s*\[.*?,(["'])(.*?)\1\s*\]\s*\)""", re.DOTALL)
DATA_LAYER_RE      = re.compile(r"""(?:dataLayer|__REDUX_STATE__|__APP_STATE__|__INITIAL_STATE__|__PRELOADED_STATE__)\s*=\s*(\{.*?\});""", re.DOTALL)
VITE_MANIFEST_RE   = re.compile(r"""/(?:[^"'\s]*/)?manifest\.json""", re.I)


def _is_js(url: str) -> bool:
    path = urlparse(url).path.split("?")[0]
    return path.endswith((".js", ".mjs", ".cjs"))


def _is_same_scope(url: str, scope: list, base: str) -> bool:
    p = urlparse(url)
    if scope:
        return any(p.netloc == d or p.netloc.endswith("." + d) for d in scope)
    return p.netloc == urlparse(base).netloc


class HTMLAnalysis:
    __slots__ = ["js_urls", "inline_scripts", "next_data", "build_id", "data_layers", "rsc_frags"]
    def __init__(self):
        self.js_urls: list[str]       = []
        self.inline_scripts: list[str] = []
        self.next_data: dict | None    = None
        self.build_id: str | None      = None
        self.data_layers: list[str]    = []
        self.rsc_frags: list[str]      = []


class Crawler:
    def __init__(self, args, session, logger):
        self.args    = args
        self.session = session
        self.logger  = logger
        self.timeout = getattr(args, "timeout", 15)
        self.delay   = getattr(args, "delay", 0)
        self.max_js  = getattr(args, "max_js", 500)
        self.threads = getattr(args, "threads", 10)
        self.depth   = getattr(args, "depth", 2)
        self.scope   = getattr(args, "scope", None) or []

    def fetch(self, url: str) -> str | None:
        try:
            if self.delay:
                time.sleep(self.delay + random.uniform(0, self.delay * 0.2))
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if resp is None:
                return None
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            self.logger.debug(f"fetch {url}: {e}")
            return None

    def fetch_json(self, url: str) -> dict | list | None:
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp is None:
                return None
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return None

    def analyze_html(self, html: str, base_url: str) -> HTMLAnalysis:
        result = HTMLAnalysis()
        js_set: set[str] = set()

        for m in SCRIPT_SRC_RE.finditer(html):
            src = m.group(1).strip()
            if src and not src.startswith("data:"):
                full = urljoin(base_url, src)
                if urlparse(full).scheme in ("http", "https"):
                    js_set.add(full)

        for m in MODULEPRELOAD_RE.finditer(html):
            js_set.add(urljoin(base_url, m.group(1).strip()))

        for m in IMPORTMAP_RE.finditer(html):
            try:
                imap = json.loads(m.group(1))
                for v in (imap.get("imports") or {}).values():
                    full = urljoin(base_url, v)
                    if _is_js(full):
                        js_set.add(full)
            except Exception:
                pass

        for m in INLINE_SCRIPT_RE.finditer(html):
            block = m.group(1).strip()
            if len(block) > 20:
                result.inline_scripts.append(block)
                for jm in NEXT_CHUNK_RE.finditer(block):
                    js_set.add(urljoin(base_url, jm.group(0)))
                for jm in TURBOPACK_CHUNK_RE.finditer(block):
                    js_set.add(urljoin(base_url, jm.group(1)))
                for rm in RSC_PUSH_RE.finditer(block):
                    result.rsc_frags.append(rm.group(2))

        nd = NEXT_DATA_RE.search(html)
        if nd:
            try:
                data = json.loads(nd.group(1))
                result.next_data = data
                result.build_id  = data.get("buildId")
            except Exception:
                pass

        bm = NEXT_BUILD_MF_RE.search(html)
        if bm:
            js_set.add(urljoin(base_url, bm.group(0)))

        if result.build_id:
            for path in [
                f"/_next/static/{result.build_id}/_buildManifest.js",
                f"/_next/static/{result.build_id}/_ssgManifest.js",
            ]:
                js_set.add(urljoin(base_url, path))

        for m in DATA_LAYER_RE.finditer(html):
            result.data_layers.append(m.group(1))

        result.js_urls = list(js_set)
        return result

    def _discover_nextjs(self, base_url: str, build_id: str | None) -> list[str]:
        found = []
        p = urlparse(base_url)
        origin = f"{p.scheme}://{p.netloc}"
        if build_id:
            for manifest_path in [
                f"/_next/static/{build_id}/_buildManifest.js",
                f"/_next/static/{build_id}/_ssgManifest.js",
            ]:
                content = self.fetch(f"{origin}{manifest_path}")
                if content:
                    for m in re.finditer(r"""["'`](/_next/static/[^\s"'`]+\.js)["'`]""", content):
                        found.append(urljoin(base_url, m.group(1)))
        for path in ["/_next/app-build-manifest.json", "/_next/static/app-build-manifest.json"]:
            data = self.fetch_json(f"{origin}{path}")
            if data and isinstance(data, dict):
                for chunks in data.get("pages", {}).values():
                    for chunk in (chunks if isinstance(chunks, list) else []):
                        found.append(urljoin(base_url, chunk))
        return found

    def _discover_vite(self, base_url: str) -> list[str]:
        found = []
        p = urlparse(base_url)
        origin = f"{p.scheme}://{p.netloc}"
        for path in ["/manifest.json", "/.vite/manifest.json", "/assets/manifest.json",
                     "/build/manifest.json", "/static/manifest.json"]:
            data = self.fetch_json(f"{origin}{path}")
            if data and isinstance(data, dict):
                for entry in data.values():
                    if isinstance(entry, dict) and "file" in entry:
                        full = urljoin(base_url, "/" + entry["file"].lstrip("/"))
                        if _is_js(full):
                            found.append(full)
                break
        return found

    def _discover_common_files(self, base_url: str) -> list[str]:
        found = []
        p = urlparse(base_url)
        origin = f"{p.scheme}://{p.netloc}"
        paths = [
            "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/package.json", "/package-lock.json",
        ]
        for path in paths:
            try:
                resp = self.session.head(f"{origin}{path}", timeout=5)
                if resp and resp.status_code == 200:
                    ct = resp.headers.get("Content-Type", "")
                    if "json" in ct or "text" in ct:
                        self.logger.debug(f"Interesting file: {origin}{path}")
            except Exception:
                pass
        return found

    def extract_js_from_js(self, content: str, base_url: str) -> list[str]:
        found = set()
        for m in JS_IN_JS_RE.finditer(content):
            full = urljoin(base_url, m.group(1))
            if urlparse(full).scheme in ("http", "https"):
                found.add(full)
        for m in NEXT_CHUNK_RE.finditer(content):
            found.add(urljoin(base_url, m.group(0)))
        for m in TURBOPACK_CHUNK_RE.finditer(content):
            found.add(urljoin(base_url, m.group(1)))
        return list(found)

    def crawl(self, start_url: str) -> dict:
        visited: set[str]                      = set()
        found_js: set[str]                     = set()
        inline_map: dict[str, list[str]]       = {}
        next_data_map: dict[str, dict]         = {}
        data_layer_map: dict[str, list[str]]   = {}
        rsc_frag_map: dict[str, list[str]]     = {}
        page_q: Queue                          = Queue()
        page_q.put((start_url, 0))
        lock = threading.Lock()

        def process(url: str, depth: int):
            if url in visited:
                return
            visited.add(url)
            html = self.fetch(url)
            if not html:
                return
            analysis = self.analyze_html(html, url)
            with lock:
                for j in analysis.js_urls:
                    found_js.add(j)
                if analysis.inline_scripts:
                    inline_map[url] = analysis.inline_scripts
                if analysis.next_data:
                    next_data_map[url] = analysis.next_data
                if analysis.data_layers:
                    data_layer_map[url] = analysis.data_layers
                if analysis.rsc_frags:
                    rsc_frag_map[url] = analysis.rsc_frags
            if depth == 0:
                extra = self._discover_nextjs(url, analysis.build_id)
                extra += self._discover_vite(url)
                self._discover_common_files(url)
                with lock:
                    for u in extra:
                        found_js.add(u)
            if depth < self.depth:
                for m in LINK_RE.finditer(html):
                    href = m.group(1).strip()
                    if href and not href.startswith(("mailto:", "tel:", "javascript:")):
                        full = urljoin(url, href)
                        if _is_same_scope(full, self.scope, start_url) and full not in visited:
                            page_q.put((full, depth + 1))

        with ThreadPoolExecutor(max_workers=min(self.threads, 8)) as pool:
            futures: dict = {}
            while not page_q.empty() or futures:
                while not page_q.empty() and len(found_js) < self.max_js:
                    try:
                        url, d = page_q.get_nowait()
                        if url not in visited:
                            f = pool.submit(process, url, d)
                            futures[f] = url
                    except Empty:
                        break
                done = [f for f in list(futures) if f.done()]
                for f in done:
                    try:
                        f.result()
                    except Exception:
                        pass
                    del futures[f]
                if not done and futures:
                    try:
                        next(as_completed(list(futures), timeout=2), None)
                    except Exception:
                        pass

        return {
            "js_urls":       sorted(found_js),
            "pages_visited": sorted(visited),
            "inline_scripts": inline_map,
            "next_data":     next_data_map,
            "data_layers":   data_layer_map,
            "rsc_frags":     rsc_frag_map,
        }

    def fetch_js_batch(self, js_urls: list, on_result=None) -> dict:
        results = {}
        lock = threading.Lock()
        def fetch_one(url):
            content = self.fetch(url)
            if content:
                with lock:
                    results[url] = content
                if on_result:
                    on_result(url, content)
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            list(pool.map(fetch_one, js_urls))
        return results
