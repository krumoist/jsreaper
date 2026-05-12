from __future__ import annotations
import sys
import time
import json
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from .crawler import Crawler
from .scanner import Scanner
from .confidence import score_finding, confidence_label
from .security_checks import run_security_checks
from .extractor import extract_all
from .intel import gather_intelligence
from .vuln_libs import scan_for_vulnerable_libs
from .waf_bypass import build_waf_session


def _domain(url: str) -> str:
    return urlparse(url).netloc.replace("www.", "")


def _strip(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _severity_order(s: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0)


def _conf_order(c: str) -> int:
    return {"confirmed": 4, "likely": 3, "possible": 2, "unlikely": 1}.get(c, 0)


class Engine:
    def __init__(self, args, logger):
        self.args       = args
        self.logger     = logger
        self.target     = args.url
        self.domain     = _domain(self.target)
        self.session    = build_waf_session(args, base_url=self.target)
        self.crawler    = Crawler(args, self.session, logger)
        self.scanner    = Scanner(args)
        self.results: dict = {
            "target":            self.target,
            "scan_start":        None,
            "scan_end":          None,
            "js_files_scanned":  0,
            "pages_visited":     0,
            "secrets":           [],
            "security_issues":   [],
            "vuln_libs":         [],
            "endpoints":         {},
            "intel":             {},
            "extraction":        {},
            "errors":            [],
        }
        self._lock        = threading.Lock()
        self._seen_fps    = set()

    def _dedup_secrets(self, new: list[dict]) -> list[dict]:
        out = []
        for f in new:
            fp = f"{f['pattern']}:{f['value']}"
            if fp not in self._seen_fps:
                self._seen_fps.add(fp)
                out.append(f)
        return out

    def _score_batch(self, findings: list[dict]) -> list[dict]:
        for f in findings:
            s = score_finding(f)
            f["confidence_score"] = s
            f["confidence_label"] = confidence_label(s)
        min_conf = getattr(self.args, "min_confidence", 0)
        return [f for f in findings if f["confidence_score"] >= min_conf]

    def _merge_endpoints(self, endpoints: dict):
        with self._lock:
            for cat, items in endpoints.items():
                existing = self.results["endpoints"].get(cat, [])
                merged   = sorted(set(existing) | set(items))
                self.results["endpoints"][cat] = merged

    def _add_secrets(self, secrets: list[dict]):
        deduped = self._dedup_secrets(secrets)
        scored  = self._score_batch(deduped)
        min_sev = getattr(self.args, "severity", None)
        if min_sev:
            scored = [s for s in scored if _severity_order(s["severity"]) >= _severity_order(min_sev)]
        with self._lock:
            self.results["secrets"].extend(scored)

    def _add_security_issues(self, issues: list[dict]):
        min_sev = getattr(self.args, "severity", None)
        if min_sev:
            issues = [i for i in issues if _severity_order(i["severity"]) >= _severity_order(min_sev)]
        with self._lock:
            self.results["security_issues"].extend(issues)

    def _add_vuln_libs(self, libs: list[dict]):
        with self._lock:
            for vl in libs:
                fp = f"vullib:{vl['value']}:{vl.get('cves', [''])[0]}"
                if fp not in self._seen_fps:
                    self._seen_fps.add(fp)
                    self.results["vuln_libs"].append(vl)

    def _process_js(self, url: str, content: str):
        self.logger.info(f"Scanning {url} ({len(content):,} chars)")
        result  = self.scanner.scan_content(content, url)
        self._add_secrets(result["secrets"] + result.get("entropy_findings", []))
        self._add_security_issues(run_security_checks(content, url))
        self._add_vuln_libs(scan_for_vulnerable_libs(content, url))
        self._merge_endpoints(result.get("endpoints", {}))
        extra = self.crawler.extract_js_from_js(content, url)
        with self._lock:
            self.results["extraction"] = _merge_extraction(
                self.results["extraction"],
                extract_all(content, url, self.domain),
            )
        return extra

    def _process_inline(self, page_url: str, inline_scripts: list[str]):
        res = self.scanner.scan_inline_scripts(inline_scripts, page_url)
        self._add_secrets(res["secrets"] + res.get("entropy_findings", []))
        self._add_security_issues(run_security_checks("\n".join(inline_scripts), page_url + " [inline]"))
        self._merge_endpoints(res.get("endpoints", {}))
        with self._lock:
            self.results["extraction"] = _merge_extraction(
                self.results["extraction"],
                extract_all("\n".join(inline_scripts), page_url + " [inline]", self.domain),
            )

    def _process_next_data(self, page_url: str, nd: dict):
        secrets = self.scanner.scan_nextdata(nd, page_url)
        self._add_secrets(secrets)
        flat = json.dumps(nd)
        self._add_security_issues(run_security_checks(flat, page_url + " [__NEXT_DATA__]"))

    def _process_data_layers(self, page_url: str, layers: list[str]):
        for layer in layers:
            res = self.scanner.scan_content(layer, f"{page_url} [dataLayer]")
            self._add_secrets(res["secrets"])

    def _process_rsc_frags(self, page_url: str, frags: list[str]):
        for frag in frags:
            res = self.scanner.scan_rsc_payload(frag, page_url)
            self._add_secrets(res["secrets"])

    def _probe_endpoints(self):
        all_eps = []
        for cat, items in self.results["endpoints"].items():
            for ep in items:
                if isinstance(ep, str) and ep.startswith("http"):
                    all_eps.append(ep)
        if not all_eps or not getattr(self.args, "probe", False):
            return

        self.logger.info(f"Probing {len(all_eps)} discovered endpoints...")
        probe_results = []
        lock = threading.Lock()

        def probe(url: str):
            try:
                r = self.session.head(url, timeout=6, allow_redirects=True)
                if r is None:
                    return
                info = {
                    "url":             url,
                    "status":          r.status_code,
                    "content_type":    r.headers.get("Content-Type", ""),
                    "server":          r.headers.get("Server", ""),
                    "x_powered_by":    r.headers.get("X-Powered-By", ""),
                    "access_control":  r.headers.get("Access-Control-Allow-Origin", ""),
                    "cors_exposed":    r.headers.get("Access-Control-Expose-Headers", ""),
                }
                if r.status_code < 400:
                    with lock:
                        probe_results.append(info)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=getattr(self.args, "threads", 10)) as pool:
            list(pool.map(probe, all_eps[:200]))

        with self._lock:
            self.results.setdefault("endpoint_probes", [])
            self.results["endpoint_probes"].extend(probe_results)

    def run(self) -> dict:
        self.results["scan_start"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.logger.info(f"Target: {self.target}")

        if getattr(self.args, "intel", False):
            self.logger.info(f"Gathering intelligence for {self.domain}...")
            intel = gather_intelligence(self.domain, self.session, self.args.threads)
            self.results["intel"] = intel
            self.logger.info(f"Intel: {len(intel['js_urls'])} JS URLs, {len(intel['subdomains'])} subdomains")

        self.logger.info("Crawling...")
        crawl = self.crawler.crawl(self.target)
        with self._lock:
            self.results["pages_visited"] = len(crawl["pages_visited"])

        for page_url, inline_scripts in crawl["inline_scripts"].items():
            self._process_inline(page_url, inline_scripts)

        for page_url, nd in crawl["next_data"].items():
            self._process_next_data(page_url, nd)

        for page_url, layers in crawl.get("data_layers", {}).items():
            self._process_data_layers(page_url, layers)

        for page_url, frags in crawl.get("rsc_frags", {}).items():
            self._process_rsc_frags(page_url, frags)

        all_js = list(set(crawl["js_urls"]))
        if getattr(self.args, "intel", False):
            intel_js = self.results["intel"].get("js_urls", [])
            all_js   = sorted(set(all_js) | set(intel_js))

        if getattr(self.args, "extra_urls", None):
            all_js.extend(self.args.extra_urls)

        max_js = getattr(self.args, "max_js", 500)
        all_js = all_js[:max_js]
        self.logger.info(f"JS files to scan: {len(all_js)}")

        discovered_extra: set[str] = set()
        def process_js_worker(url: str):
            content = self.crawler.fetch(url)
            if not content:
                return
            with self._lock:
                self.results["js_files_scanned"] += 1
            extras = self._process_js(url, content)
            for u in extras:
                if u not in set(all_js) and u not in discovered_extra:
                    discovered_extra.add(u)

        with ThreadPoolExecutor(max_workers=getattr(self.args, "threads", 10)) as pool:
            futs = {pool.submit(process_js_worker, u): u for u in all_js}
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception as e:
                    self.logger.debug(f"Worker error: {e}")

        if discovered_extra:
            extra_list = sorted(discovered_extra)[:100]
            self.logger.info(f"Scanning {len(extra_list)} lazily-discovered JS chunks...")
            extra_futs = {pool_submit := {}}
            with ThreadPoolExecutor(max_workers=getattr(self.args, "threads", 10)) as pool2:
                f2 = {pool2.submit(process_js_worker, u): u for u in extra_list}
                for fut in as_completed(f2):
                    try:
                        fut.result()
                    except Exception:
                        pass

        self._probe_endpoints()

        self.results["secrets"]         = _sort_findings(self.results["secrets"])
        self.results["security_issues"] = _sort_findings(self.results["security_issues"])
        self.results["vuln_libs"]       = _sort_findings(self.results["vuln_libs"])
        self.results["scan_end"]        = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        return self.results


def _sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (
        -_severity_order(f.get("severity", "")),
        -f.get("confidence_score", 0),
        f.get("source_url", ""),
    ))


def _merge_extraction(base: dict, new: dict) -> dict:
    for key, items in new.items():
        existing = base.get(key, [])
        merged   = sorted(set(existing) | set(items))
        base[key] = merged
    return base
